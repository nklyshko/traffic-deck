"""End-to-end TLS-interception tests for SocksUpstreamLayer.

The other test module (``test_socks_upstream.py``) drives the SOCKS5 state machine
directly and asserts the layer *stack* is built, but stops short of the TLS handshake.
This module closes that gap with two self-contained, in-process integration tests (no
sockets, no live proxy, no network — real sockets are also blocked in CI sandboxes):

* ``test_both_sides_tls_through_socks_layer`` — after the SOCKS5 tunnel is granted, a real
  ``ssl`` client and a real (self-signed) upstream ``ssl`` server complete their handshakes
  *through* the layer.  This proves ``ClientTLSLayer`` decrypts the client side and
  ``ServerTLSLayer`` re-encrypts toward the upstream over the already-open tunnel — i.e.
  mitmproxy no longer forwards the decrypted request to the HTTPS upstream in cleartext.

* ``test_websocket_upgrade_through_socks_tls_stack`` — drives the *whole* stack
  (SOCKS → ServerTLS → ClientTLS → HttpLayer → WebSocketLayer): both TLS handshakes, a real
  HTTP ``Upgrade: websocket`` handshake, then masked WebSocket frames in both directions.
  It asserts the capture hook (``websocket_message``) fires with the correct, *decrypted*
  frame content — the whole point of intercepting the SOCKS-tunnelled TLS.

Both run the real ``tlsconfig`` and ``next_layer`` addons plus the capture addon's
``tls_clienthello`` hook (which forces server-TLS-first), driven by a tiny in-process event
loop that dispatches the layers' blocking hooks — the same contract mitmproxy's server
implements.
"""

from __future__ import annotations

import datetime
import secrets
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mitmproxy import connection
from mitmproxy.addons import next_layer as next_layer_addon
from mitmproxy.addons import tlsconfig
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.proxy import commands, context, events
from mitmproxy.proxy.layers import tls as tls_layer
from mitmproxy.test import taddons

from capture_mitmproxy.addon import GatewayPusher
from capture_mitmproxy.socks_upstream import SocksUpstreamLayer

TARGET_HOST = "ws-api.oneme.ru"
TARGET_PORT = 443


class _Driver:
    """A minimal stand-in for mitmproxy's proxy server event loop.

    Feeds events into the top layer, collects the commands it emits, and auto-replies to
    the blocking ones — dispatching hooks to the registered addons and completing
    OpenConnection — like ``mitmproxy.proxy.server`` does, but synchronously and without
    I/O.  ``sent[conn]`` accumulates the bytes the layer wanted to write to each
    connection, so the test can shuttle them into the peer's TLS engine.
    """

    def __init__(self, layer, addons, client, server):
        self._layer = layer
        self._addons = addons
        self.sent: dict[connection.Connection, bytearray] = {
            client: bytearray(),
            server: bytearray(),
        }

    def feed(self, event: events.Event) -> None:
        for cmd in list(self._layer.handle_event(event)):
            for reply in self._dispatch(cmd):
                self.feed(reply)

    def _dispatch(self, cmd: commands.Command) -> list[events.Event]:
        if isinstance(cmd, commands.SendData):
            self.sent[cmd.connection].extend(cmd.data)
            return []
        if isinstance(cmd, commands.OpenConnection):
            # Should not happen for the already-open tunnel (ServerTLSLayer's server-first
            # path swallows it), but satisfy it defensively if it ever surfaces.
            cmd.connection.state = connection.ConnectionState.OPEN
            return [events.OpenConnectionCompleted(cmd, None)]
        if isinstance(cmd, commands.StartHook):
            for addon in self._addons:
                handler = getattr(addon, cmd.name, None)
                if handler is not None:
                    result = handler(*cmd.args())
                    # The capture addon's flow hooks are async coroutines; we only need
                    # them dispatched, not awaited (a sync spy verifies capture instead).
                    if hasattr(result, "close"):
                        result.close()
            return [events.HookCompleted(cmd)]
        return []  # CloseConnection, Log, RequestWakeup, …


class _MemTls:
    """A TLS peer (client or server) driven over memory BIOs."""

    def __init__(self, ctx: ssl.SSLContext, server_side: bool, server_hostname=None):
        self._inc = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(
            self._inc, self._out, server_side=server_side, server_hostname=server_hostname
        )
        self.done = False

    def read_outgoing(self) -> bytes:
        return self._out.read()

    def write_incoming(self, data: bytes) -> None:
        if data:
            self._inc.write(data)

    def step(self) -> None:
        if self.done:
            return
        try:
            self.obj.do_handshake()
            self.done = True
        except ssl.SSLWantReadError:
            pass

    def app_write(self, data: bytes) -> None:
        self.obj.write(data)

    def app_read(self) -> bytes:
        out = bytearray()
        while True:
            try:
                chunk = self.obj.read(65536)
            except ssl.SSLWantReadError:
                break
            if not chunk:
                break
            out.extend(chunk)
        return bytes(out)


def _self_signed(host: str, tmp: Path) -> tuple[Path, Path]:
    """Mint a self-signed leaf cert+key for `host` — the fake upstream's identity."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp / "upstream.crt"
    key_file = tmp / "upstream.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


def _masked_frame(unmasked: bytes) -> bytes:
    """A client→server WebSocket frame: sets the mask bit and XOR-masks the payload
    (clients MUST mask, per RFC 6455). `unmasked` is header(2 bytes)+payload."""
    header = bytearray(unmasked[:2])
    assert header[1] < 126  # short payload only
    header[1] |= 0b1000_0000
    mask = secrets.token_bytes(4)
    body = bytes(x ^ mask[i % 4] for i, x in enumerate(unmasked[2:]))
    return bytes(header) + mask + body


def _socks5_connect_req(host: bytes, port: int) -> bytes:
    return bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host + bytes([port >> 8, port & 0xFF])


def _socks5_reply(rep: int = 0) -> bytes:
    return bytes([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])


def _make_ctx(tmp_path, tls_addon, extra_options=None):
    """A Context whose server connection is an already-open SOCKS tunnel, wired to a
    tlsconfig addon with a fresh throwaway CA in `tmp_path`."""
    with taddons.context(tls_addon, Proxyserver()) as tctx:
        tctx.options.confdir = str(tmp_path)
        if extra_options:
            for k, v in extra_options.items():
                setattr(tctx.options, k, v)
        tls_addon.configure({"confdir"})
        client = connection.Client(
            peername=("127.0.0.1", 54321), sockname=("127.0.0.1", 8888),
            state=connection.ConnectionState.OPEN,
        )
        server = connection.Server(address=("socks-proxy.example", 1080))
        server.state = connection.ConnectionState.OPEN  # the SOCKS tunnel is already open
        ctx = context.Context(client, tctx.options)
        ctx.server = server
        return tctx, ctx, client, server


def _do_socks_handshake(driver, client, server):
    driver.feed(events.Start())
    driver.feed(events.DataReceived(client, bytes([0x05, 0x01, 0x00])))
    driver.feed(events.DataReceived(server, bytes([0x05, 0x00])))
    driver.feed(events.DataReceived(client, _socks5_connect_req(TARGET_HOST.encode(), TARGET_PORT)))
    driver.feed(events.DataReceived(server, _socks5_reply()))


def _pump(driver, peers, *, handshake=False, rounds=60):
    """Shuttle TLS records between the memory-BIO peers and the intercepting layer until
    quiescent.  With handshake=True it also advances each peer's handshake each round and
    stops once both are done; otherwise it stops when no bytes move."""
    for _ in range(rounds):
        progressed = False
        for peer, conn in peers:
            out = peer.read_outgoing()
            if out:
                driver.feed(events.DataReceived(conn, out))
                progressed = True
        for peer, conn in peers:
            buf = bytes(driver.sent[conn])
            driver.sent[conn].clear()
            if buf:
                peer.write_incoming(buf)
                progressed = True
        if handshake:
            for peer, _ in peers:
                peer.step()
        if not progressed and (not handshake or all(p.done for p, _ in peers)):
            break


def _tls_client(ca_file: Path) -> _MemTls:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_file))
    return _MemTls(ctx, server_side=False, server_hostname=TARGET_HOST)


def _tls_upstream(cert: Path, key: Path) -> _MemTls:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return _MemTls(ctx, server_side=True)


def test_both_sides_tls_through_socks_layer(tmp_path):
    """Server TLS is established over the already-open SOCKS tunnel (no cleartext to the
    HTTPS upstream) and client TLS is established with the client — both must complete."""
    upstream_cert, upstream_key = _self_signed(TARGET_HOST, tmp_path)
    tls_addon = tlsconfig.TlsConfig()
    pusher = GatewayPusher()
    tctx, ctx, client, server = _make_ctx(tmp_path, tls_addon, {"ssl_insecure": True})
    ca_file = tmp_path / "mitmproxy-ca-cert.pem"

    layer = SocksUpstreamLayer(ctx)
    driver = _Driver(layer, [tls_addon, pusher], client, server)
    _do_socks_handshake(driver, client, server)

    assert isinstance(layer._child, tls_layer.ServerTLSLayer)
    assert isinstance(layer._child.child_layer, tls_layer.ClientTLSLayer)
    assert ctx.server.address == (TARGET_HOST, TARGET_PORT)
    driver.sent[client].clear()
    driver.sent[server].clear()

    tls_client = _tls_client(ca_file)
    tls_upstream = _tls_upstream(upstream_cert, upstream_key)
    tls_client.step()  # emit the client ClientHello
    _pump(driver, [(tls_client, client), (tls_upstream, server)], handshake=True)

    assert tls_upstream.done, "server-side TLS did not complete over the SOCKS tunnel"
    assert ctx.server.tls_established
    assert tls_client.done, "client-side TLS did not complete"
    assert ctx.client.tls_established
    assert ctx.client.sni == TARGET_HOST
    assert tls_client.obj.getpeercert(True), "client received no server certificate"


class _WsSpy:
    """A stand-in for the capture addon's websocket_message hook: records exactly what
    GatewayPusher.websocket_message reads — the newest frame's direction and content."""

    def __init__(self):
        self.messages: list[tuple[bool, bytes]] = []

    def websocket_message(self, flow):
        m = flow.websocket.messages[-1]
        self.messages.append((bool(m.from_client), bytes(m.content)))


def test_websocket_upgrade_through_socks_tls_stack(tmp_path):
    """Drive the whole stack: SOCKS → dual TLS → HTTP Upgrade → WebSocket frames. The
    capture hook must observe the decrypted frames in both directions."""
    upstream_cert, upstream_key = _self_signed(TARGET_HOST, tmp_path)
    tls_addon = tlsconfig.TlsConfig()
    pusher = GatewayPusher()
    ws_spy = _WsSpy()
    tctx, ctx, client, server = _make_ctx(tmp_path, tls_addon, {"ssl_insecure": True})
    ca_file = tmp_path / "mitmproxy-ca-cert.pem"

    layer = SocksUpstreamLayer(ctx)
    # The built-in next_layer addon picks HttpLayer for the decrypted HTTP; tls_addon does
    # TLS; pusher forces server-TLS-first; ws_spy records captured frames.
    driver = _Driver(
        layer, [next_layer_addon.NextLayer(), tls_addon, pusher, ws_spy], client, server
    )
    _do_socks_handshake(driver, client, server)
    driver.sent[client].clear()
    driver.sent[server].clear()

    # ── dual TLS handshake ─────────────────────────────────────────────────────
    tls_client = _tls_client(ca_file)
    tls_upstream = _tls_upstream(upstream_cert, upstream_key)
    peers = [(tls_client, client), (tls_upstream, server)]
    tls_client.step()
    _pump(driver, peers, handshake=True)
    assert tls_client.done and tls_upstream.done, "dual TLS handshake did not complete"

    # ── HTTP Upgrade: websocket ────────────────────────────────────────────────
    tls_client.app_write(
        b"GET /websocket HTTP/1.1\r\n"
        b"Host: ws-api.oneme.ru\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: websocket\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
    )
    _pump(driver, peers)
    upstream_req = tls_upstream.app_read()
    assert b"GET /websocket HTTP/1.1" in upstream_req, upstream_req
    assert b"upgrade" in upstream_req.lower(), "upgrade request not forwarded to upstream"

    tls_upstream.app_write(
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        b"\r\n"
    )
    _pump(driver, peers)
    client_resp = tls_client.app_read()
    assert b"101 Switching Protocols" in client_resp, client_resp

    # ── WebSocket frames, both directions ──────────────────────────────────────
    # client → server: a masked TEXT frame "hello world"
    tls_client.app_write(_masked_frame(b"\x81\x0bhello world"))
    _pump(driver, peers)
    assert tls_upstream.app_read(), "forwarded client frame never reached the upstream"

    # server → client: an (unmasked) BINARY frame "hello back"
    tls_upstream.app_write(b"\x82\nhello back")
    _pump(driver, peers)
    assert tls_client.app_read(), "forwarded server frame never reached the client"

    # The capture hook saw both frames, decrypted, correctly attributed.
    assert (True, b"hello world") in ws_spy.messages, ws_spy.messages
    assert (False, b"hello back") in ws_spy.messages, ws_spy.messages
