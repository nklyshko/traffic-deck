"""Tests for SocksUpstreamLayer and the addon's SOCKS5 detection.

These are synthetic integration tests — they drive the SOCKS5 state machine directly
with byte sequences, without a live proxy or network.  The TLS layer stack is verified
structurally (correct layer types, address update, proxy metadata) but not functionally,
since actual TLS interception requires the full mitmproxy framework (tlsconfig addon,
SSL contexts, hooks) which isn't available in isolation.
"""

from __future__ import annotations

import struct

from mitmproxy import connection
from mitmproxy.options import Options
from mitmproxy.proxy import context, events, commands
from mitmproxy.proxy.layers import tls as tls_layer
from mitmproxy import tcp

from capture_mitmproxy.socks_upstream import (
    SocksUpstreamLayer,
    looks_like_socks5,
    _parse_addr,
    _C_GREETING,
    _C_AUTH,
    _C_REQUEST,
    _C_DONE,
    _S_GREETING,
    _S_AUTH,
    _S_REQUEST,
    _S_DONE,
    _MethodNone,
    _MethodUserPass,
    _AtypIPv4,
    _AtypDomain,
    _AtypIPv6,
)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _run(gen):
    """Drain a command generator, collecting all yielded commands."""
    cmds = []
    try:
        while True:
            cmds.append(next(gen))
    except StopIteration:
        pass
    return cmds


def _make_ctx(proxy_addr=("upstream-proxy.example", 2639)):
    opts = Options()
    opts.rawtcp = True
    client = connection.Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8888))
    # The client socket is live by the time the SOCKS5 handshake runs; ClientTLSLayer only
    # enters its handshake state on Start when the (client) tunnel connection is open.
    client.state = connection.ConnectionState.OPEN
    server = connection.Server(address=proxy_addr)
    server.state = connection.ConnectionState.OPEN
    ctx = context.Context(client, opts)
    ctx.server = server
    return ctx, client, server


def _socks5_connect_req(host: bytes, port: int) -> bytes:
    """Build a SOCKS5 CONNECT request for host:port (domain ATYP)."""
    return bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host + struct.pack("!H", port)


def _socks5_reply(rep: int = 0) -> bytes:
    """Build a SOCKS5 CONNECT reply (REP=0 = succeeded, BND.ADDR=0.0.0.0:0)."""
    return bytes([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])


# ─── looks_like_socks5 ───────────────────────────────────────────────────────

class TestLooksLikeSocks5:
    def test_greeting_no_auth(self):
        assert looks_like_socks5(bytes([0x05, 0x01, 0x00]))

    def test_greeting_with_auth(self):
        assert looks_like_socks5(bytes([0x05, 0x02, 0x00, 0x02]))

    def test_reject_empty_methods(self):
        assert not looks_like_socks5(bytes([0x05, 0x00]))

    def test_reject_ff_method(self):
        assert not looks_like_socks5(bytes([0x05, 0x01, 0xFF]))

    def test_accepts_trailing_bytes(self):
        """Clients commonly pipeline greeting + CONNECT + TLS in one segment."""
        assert looks_like_socks5(bytes([0x05, 0x01, 0x00, 0x05]))

    def test_reject_tls(self):
        assert not looks_like_socks5(bytes([0x16, 0x03, 0x01]))

    def test_reject_http(self):
        assert not looks_like_socks5(b"GET / HTTP/1.1")

    def test_reject_empty(self):
        assert not looks_like_socks5(b"")

    def test_reject_short(self):
        assert not looks_like_socks5(bytes([0x05]))


# ─── _parse_addr ─────────────────────────────────────────────────────────────

class TestParseAddr:
    def test_ipv4(self):
        assert _parse_addr(_AtypIPv4, bytes([1, 2, 3, 4])) == "1.2.3.4"

    def test_domain(self):
        assert _parse_addr(_AtypDomain, b"ws-api.oneme.ru") == "ws-api.oneme.ru"

    def test_ipv6(self):
        addr = _parse_addr(_AtypIPv6, bytes(16))
        assert "::" in addr


# ─── SocksUpstreamLayer state machine ────────────────────────────────────────

class TestNoAuthHandshake:
    """No-auth SOCKS5: greeting → choice → CONNECT → reply → establish."""

    def test_full_handshake(self):
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)

        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        assert s._c_phase == _C_GREETING  # waiting for server choice

        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        assert s._method == _MethodNone
        assert s._c_phase == _C_REQUEST
        assert s._s_phase == _S_REQUEST

        req = _socks5_connect_req(b"ws-api.oneme.ru", 443)
        _run(s._handle_event(events.DataReceived(client, req)))
        assert s._target == ("ws-api.oneme.ru", 443)
        assert s._c_phase == _C_DONE

        _run(s._handle_event(events.DataReceived(server, _socks5_reply())))
        assert s._s_phase == _S_DONE
        assert s._child is not None
        assert isinstance(s._child, tls_layer.ServerTLSLayer)
        assert isinstance(s._child.child_layer, tls_layer.ClientTLSLayer)
        assert ctx.server.address == ("ws-api.oneme.ru", 443)

    def test_relay_is_transparent(self):
        """All SOCKS5 bytes must be relayed to the other side unchanged."""
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)

        greeting = bytes([0x05, 0x01, 0x00])
        cmds = _run(s._handle_event(events.DataReceived(client, greeting)))
        assert len(cmds) == 1
        assert isinstance(cmds[0], commands.SendData)
        assert cmds[0].connection == server
        assert cmds[0].data == greeting

        choice = bytes([0x05, 0x00])
        cmds = _run(s._handle_event(events.DataReceived(server, choice)))
        assert len(cmds) == 1
        assert isinstance(cmds[0], commands.SendData)
        assert cmds[0].connection == client
        assert cmds[0].data == choice

    def test_proxy_metadata_stashed(self):
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)

        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        _run(s._handle_event(events.DataReceived(client, _socks5_connect_req(b"ws-api.oneme.ru", 443))))
        _run(s._handle_event(events.DataReceived(server, _socks5_reply())))

        proxy = getattr(ctx.server, "_socks_proxy", None)
        assert proxy is not None
        assert proxy["addr"] == "upstream-proxy.example:2639"
        assert proxy["type"] == "socks"
        assert proxy["username"] == ""
        assert proxy["password"] == ""
        # Stamped on the client connection too — the stable anchor the addon falls back to
        # when mitmproxy's HTTP pool hands the inner request a different Server.
        assert getattr(ctx.client, "_socks_proxy", None) is proxy


class TestSocksProxyReadback:
    """build_flow's _socks_proxy reads the stash back from whichever connection kept it."""

    def test_reads_from_client_when_server_swapped(self):
        from mitmproxy.test import tflow
        from capture_mitmproxy.addon import _socks_proxy

        f = tflow.tflow()
        info = {"addr": "p:1080", "type": "socks", "username": "u", "password": "pw"}
        # Simulate the pool swap: only the client connection kept the stamp.
        f.client_conn._socks_proxy = info
        assert not hasattr(f.server_conn, "_socks_proxy")

        proxy = _socks_proxy(f)
        assert proxy is not None
        assert proxy.addr == "p:1080"
        assert proxy.username == "u" and proxy.password == "pw"

    def test_none_when_neither_stamped(self):
        from mitmproxy.test import tflow
        from capture_mitmproxy.addon import _socks_proxy

        assert _socks_proxy(tflow.tflow()) is None


class TestUserPassAuth:
    """RFC 1929 username/password auth."""

    def test_full_handshake(self):
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)

        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x02, 0x00, 0x02]))))
        assert s._c_phase == _C_GREETING

        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x02]))))
        assert s._method == _MethodUserPass
        assert s._c_phase == _C_AUTH
        assert s._s_phase == _S_AUTH

        user, pwd = b"bob", b"secret"
        auth_req = bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd
        _run(s._handle_event(events.DataReceived(client, auth_req)))
        assert s._username == "bob"
        assert s._password == "secret"
        assert s._c_phase == _C_REQUEST

        _run(s._handle_event(events.DataReceived(client, _socks5_connect_req(b"ws-api.oneme.ru", 443))))
        assert s._target == ("ws-api.oneme.ru", 443)

        _run(s._handle_event(events.DataReceived(server, bytes([0x01, 0x00]))))
        assert s._s_phase == _S_REQUEST

        _run(s._handle_event(events.DataReceived(server, _socks5_reply())))
        assert s._s_phase == _S_DONE
        assert s._child is not None
        assert ctx.server.address == ("ws-api.oneme.ru", 443)
        assert ctx.server._socks_proxy["username"] == "bob"
        assert ctx.server._socks_proxy["password"] == "secret"

    def test_auth_failure(self):
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)

        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x02, 0x00, 0x02]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x02]))))
        user, pwd = b"bob", b"wrong"
        auth_req = bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd
        _run(s._handle_event(events.DataReceived(client, auth_req)))

        # Server rejects auth (STATUS != 0)
        _run(s._handle_event(events.DataReceived(server, bytes([0x01, 0x01]))))
        assert s._s_phase == _S_DONE
        assert s._child is None


class TestEdgeCases:
    def test_server_refused(self):
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)
        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        _run(s._handle_event(events.DataReceived(client, _socks5_connect_req(b"ws-api.oneme.ru", 443))))
        _run(s._handle_event(events.DataReceived(server, _socks5_reply(rep=0x04))))
        assert s._s_phase == _S_DONE
        assert s._child is None

    def test_no_acceptable_methods(self):
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)
        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0xFF]))))
        assert s._s_phase == _S_DONE
        assert s._child is None

    def test_ipv4_target(self):
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)
        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        ipv4_req = bytes([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4]) + struct.pack("!H", 443)
        _run(s._handle_event(events.DataReceived(client, ipv4_req)))
        assert s._target == ("1.2.3.4", 443)

    def test_leftover_bytes_preserved(self):
        """Bytes after the SOCKS5 handshake (e.g. TLS ClientHello) must be buffered,
        NOT relayed — the TLS layers will handle them."""
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)
        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        combined = _socks5_connect_req(b"ws-api.oneme.ru", 443) + tls_hello
        cmds = _run(s._handle_event(events.DataReceived(client, combined)))
        # Only the SOCKS5 CONNECT request should be relayed; the TLS ClientHello
        # must stay buffered for the child TLS layer.
        relayed = [c for c in cmds if isinstance(c, commands.SendData)]
        assert len(relayed) == 1, f"Expected 1 SendData (CONNECT req), got {len(relayed)}"
        assert relayed[0].connection == server
        assert relayed[0].data == _socks5_connect_req(b"ws-api.oneme.ru", 443)
        assert len(s._client_buf) == len(tls_hello)
        assert s._target == ("ws-api.oneme.ru", 443)

    def test_out_of_order_reply(self):
        """Server reply before client CONNECT — establish should wait."""
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)
        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, _socks5_reply())))
        assert s._s_phase == _S_DONE
        assert s._target is None
        assert s._child is None
        # Now client sends CONNECT
        _run(s._handle_event(events.DataReceived(client, _socks5_connect_req(b"ws-api.oneme.ru", 443))))
        assert s._target == ("ws-api.oneme.ru", 443)
        assert s._child is not None

    def test_non_connect_command_falls_back(self):
        """BIND/UDP ASSOCIATE — no stream to decode, fall back to raw relay."""
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)
        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        # CMD=0x02 (BIND), not CONNECT
        bind_req = bytes([0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4]) + struct.pack("!H", 443)
        _run(s._handle_event(events.DataReceived(client, bind_req)))
        assert s._c_phase == _C_DONE
        assert s._target is None

    def test_establish_feeds_leftover_to_child(self):
        """Leftover bytes after the SOCKS5 handshake (typically the inner TLS ClientHello)
        must be forwarded to the child ClientTLSLayer, not left in the SOCKS buffer. Here
        the leftover is an incomplete TLS record, so the child ClientTLSLayer buffers it in
        its handshake recv_buffer awaiting the rest — which proves the bytes reached the TLS
        stack.  (A full ClientHello driving the handshake to completion is covered
        end-to-end in test_socks_tls_integration.py.)"""
        ctx, client, server = _make_ctx()
        s = SocksUpstreamLayer(ctx)
        _run(s._handle_event(events.DataReceived(client, bytes([0x05, 0x01, 0x00]))))
        _run(s._handle_event(events.DataReceived(server, bytes([0x05, 0x00]))))
        # Incomplete TLS record: header claims a 256-byte body, none of which follows.
        tls_hello = bytes([0x16, 0x03, 0x01, 0x01, 0x00])
        combined = _socks5_connect_req(b"ws-api.oneme.ru", 443) + tls_hello
        _run(s._handle_event(events.DataReceived(client, combined)))
        _run(s._handle_event(events.DataReceived(server, _socks5_reply())))

        assert isinstance(s._child, tls_layer.ServerTLSLayer)
        client_tls = s._child.child_layer
        assert isinstance(client_tls, tls_layer.ClientTLSLayer)
        assert ctx.server.address == ("ws-api.oneme.ru", 443)
        # The leftover was handed to the child TLS stack (not left behind in the SOCKS buffer).
        assert len(s._client_buf) == 0
        assert bytes(client_tls.recv_buffer) == tls_hello


# --- addon integration ---

class TestAddonNextLayer:
    """Verify the addon's next_layer hook detects SOCKS5 and installs SocksUpstreamLayer."""

    def _make_nextlayer(self, client_data: bytes):
        from unittest.mock import MagicMock
        from mitmproxy.proxy import layer as proxy_layer

        ctx, client, server = _make_ctx()
        nl = MagicMock(spec=proxy_layer.NextLayer)
        nl.context = ctx
        nl.layer = None
        nl.data_client.return_value = client_data
        return nl

    def test_detects_socks5_greeting(self):
        from capture_mitmproxy.addon import GatewayPusher
        pusher = GatewayPusher()
        nl = self._make_nextlayer(bytes([0x05, 0x01, 0x00]))
        pusher.next_layer(nl)
        assert nl.layer is not None
        assert isinstance(nl.layer, SocksUpstreamLayer)

    def test_ignores_tls(self):
        from capture_mitmproxy.addon import GatewayPusher
        pusher = GatewayPusher()
        nl = self._make_nextlayer(bytes([0x16, 0x03, 0x01, 0x00, 0x05]))
        pusher.next_layer(nl)
        assert nl.layer is None

    def test_ignores_http(self):
        from capture_mitmproxy.addon import GatewayPusher
        pusher = GatewayPusher()
        nl = self._make_nextlayer(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
        pusher.next_layer(nl)
        assert nl.layer is None

    def test_respects_existing_non_tcp_layer(self):
        from capture_mitmproxy.addon import GatewayPusher
        from unittest.mock import MagicMock
        pusher = GatewayPusher()
        nl = self._make_nextlayer(bytes([0x05, 0x01, 0x00]))
        nl.layer = MagicMock()  # a non-TCPLayer already chosen
        pusher.next_layer(nl)
        assert not isinstance(nl.layer, SocksUpstreamLayer)

    def test_overrides_existing_tcp_layer(self):
        """The built-in NextLayer picks TCPLayer for SOCKS5 bytes (rawtcp=True).
        Our hook must override that fallback."""
        from capture_mitmproxy.addon import GatewayPusher
        from mitmproxy.proxy.layers import tcp as tcp_layer
        pusher = GatewayPusher()
        nl = self._make_nextlayer(bytes([0x05, 0x01, 0x00]))
        nl.layer = tcp_layer.TCPLayer(nl.context)  # what NextLayer would pick
        pusher.next_layer(nl)
        assert isinstance(nl.layer, SocksUpstreamLayer)


class TestAddonProxyMetadata:
    """Verify build_flow extracts _socks_proxy metadata into the proto Flow."""

    def test_proxy_field_populated(self):
        from capture_mitmproxy.addon import build_flow
        from mitmproxy import http as mitm_http

        flow = mitm_http.HTTPFlow(
            client_conn=connection.Client(
                peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8888)
            ),
            server_conn=connection.Server(address=("ws-api.oneme.ru", 443)),
        )
        flow.server_conn._socks_proxy = {  # type: ignore[attr-defined]
            "addr": "upstream-proxy.example:2639",
            "type": "socks",
            "username": "bob",
            "password": "secret",
        }
        flow.request = mitm_http.Request.make(
            "GET", "https://ws-api.oneme.ru/v1/max", headers={"user-agent": "test"}
        )
        flow.response = mitm_http.Response.make(200, b"ok")

        pf = build_flow(flow)
        assert pf.proxy.addr == "upstream-proxy.example:2639"
        assert pf.proxy.type == "socks"
        assert pf.proxy.username == "bob"
        assert pf.proxy.password == "secret"
        assert pf.authority == "ws-api.oneme.ru"
        assert pf.tls_decrypted is True

    def test_no_proxy_field_without_socks(self):
        from capture_mitmproxy.addon import build_flow
        from mitmproxy import http as mitm_http

        flow = mitm_http.HTTPFlow(
            client_conn=connection.Client(
                peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8888)
            ),
            server_conn=connection.Server(address=("example.com", 443)),
        )
        flow.request = mitm_http.Request.make("GET", "https://example.com/")
        flow.response = mitm_http.Response.make(200, b"ok")

        pf = build_flow(flow)
        assert pf.proxy.addr == ""
        assert pf.proxy.type == ""


class TestAddonTcpClose:
    """Verify tcp_end/tcp_error hooks compute duration, set error, and re-push."""

    def _make_tcp_flow(self):
        client = connection.Client(
            peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8888)
        )
        client.timestamp_start = __import__("time").time() - 1.5
        return tcp.TCPFlow(
            client_conn=client,
            server_conn=connection.Server(address=("example.com", 443)),
        )

    def test_tcp_end_computes_duration(self):
        import asyncio
        from unittest.mock import AsyncMock
        from capture_mitmproxy.addon import GatewayPusher
        from mitmproxy import flow as mitm_flow

        pusher = GatewayPusher()
        pusher.session_id = "test-session"
        pusher._send = AsyncMock()

        flow = self._make_tcp_flow()
        pusher._tcp_started[flow.id] = flow.timestamp_start

        asyncio.run(pusher.tcp_end(flow))
        assert flow.id not in pusher._tcp_started
        pusher._send.assert_called_once()
        pf = pusher._send.call_args.kwargs["flows"][0]
        assert pf.duration_micros > 0

    def test_tcp_error_sets_error_field(self):
        import asyncio
        from unittest.mock import AsyncMock, patch
        from capture_mitmproxy.addon import GatewayPusher
        from mitmproxy import flow as mitm_flow

        pusher = GatewayPusher()
        pusher.session_id = "test-session"
        pusher._send = AsyncMock()

        flow = self._make_tcp_flow()
        pusher._tcp_started[flow.id] = flow.timestamp_start
        flow.error = mitm_flow.Error("connection reset")

        # ctx.log is only available inside a running mitmproxy master.
        with patch("mitmproxy.ctx.log", create=True):
            asyncio.run(pusher.tcp_error(flow))
        assert flow.id not in pusher._tcp_started
        pusher._send.assert_called_once()
        pf = pusher._send.call_args.kwargs["flows"][0]
        assert pf.error == "connection reset"
