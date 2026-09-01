"""A mitmproxy layer that transparently relays a SOCKS5 handshake to an upstream SOCKS5
proxy, parses it to learn the real tunnel target, then hands off to
mitmproxy's built-in TLS layers so the inner connection is intercepted and decoded.

mitmproxy has no built-in upstream SOCKS5 client.  Without this layer, a CONNECT tunnel
to a SOCKS5 proxy is treated as raw TCP: the SOCKS5 handshake, inner TLS, and everything
inside flows as opaque bytes, so the addon never sees decoded HTTP/WebSocket flows.  This
layer sits where TCPLayer would go, peels the SOCKS5 handshake (the same state machine as
``gateway/internal/decode/livesocks.go``), updates ``context.server.address`` to the real
target, and transitions to mitmproxy's ``ServerTLSLayer`` → ``ClientTLSLayer`` stack — the
same layers it uses to intercept a plain ``CONNECT host:443`` (the client side is
decrypted, the server side re-encrypted over the SOCKS tunnel).

The layer is installed by a ``next_layer`` addon hook (see ``addon.py``) that detects the
SOCKS5 greeting in the first client bytes after a CONNECT tunnel is established.
"""

from __future__ import annotations

import socket
import struct

from mitmproxy.proxy import commands, events, layer
from mitmproxy.proxy.layers import tls as tls_layer
from mitmproxy.proxy.utils import expect

# SOCKS5 protocol constants (RFC 1928 / 1929).
_SocksV5 = 0x05

_CmdConnect = 0x01

_AtypIPv4 = 0x01
_AtypDomain = 0x03
_AtypIPv6 = 0x04

_MethodNone = 0x00
_MethodUserPass = 0x02
_MethodNoAcceptable = 0xFF

_RepSucceeded = 0x00

# Client-side phases (what the client sends, in wire order).
_C_GREETING = 0   # method negotiation: VER, NMETHODS, METHODS
_C_AUTH = 1        # RFC 1929 credentials: VER(0x01), ULEN, UNAME, PLEN, PASSWD
_C_REQUEST = 2     # CONNECT request: VER, CMD, RSV, ATYP, ADDR, PORT
_C_DONE = 3        # nothing left to parse from the client

# Server-side phases (what the server sends, in wire order).
_S_GREETING = 0   # method selection: VER, METHOD
_S_AUTH = 1        # auth status: VER(0x01), STATUS
_S_REQUEST = 2     # CONNECT reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
_S_DONE = 3        # nothing left to parse from the server

def looks_like_socks5(data: bytes) -> bool:
    """Quick structural check for a SOCKS5 greeting (client's first bytes).

    Checks VER=5, NMETHODS>0, the method list is at least fully present, and
    0xFF (a reply-only value) is not among the offered methods.  Trailing bytes
    after the greeting are allowed — clients commonly pipeline the greeting,
    CONNECT request, and even the TLS ClientHello in a single TCP segment.
    """
    if len(data) < 2 or data[0] != _SocksV5:
        return False
    n = data[1]
    if n == 0 or len(data) < 2 + n:
        return False
    return _MethodNoAcceptable not in data[2 : 2 + n]


class SocksUpstreamLayer(layer.Layer):
    """Relays a SOCKS5 handshake to an upstream proxy, then delegates to TLS layers.

    Phase 1 (handshake): all bytes are transparently relayed between client and server
    while a state machine parses the SOCKS5 exchange to extract the real target.  The
    relay is necessary because the upstream proxy handles the SOCKS5
    negotiation — we only sniff it.

    Phase 2 (TLS): once the proxy grants the CONNECT, ``context.server.address`` is
    updated to the real target and a ``ServerTLSLayer`` → ``ClientTLSLayer`` (child:
    ``NextLayer``) stack is created as the child layer — the same stack mitmproxy's own
    ``next_layer`` addon builds for an intercepted HTTPS connection.  ``ClientTLSLayer``
    decrypts the client side; ``ServerTLSLayer`` re-encrypts toward the real target over
    the already-open SOCKS tunnel.  Leftover bytes (typically the inner TLS ClientHello)
    and all subsequent events — including the ``CommandCompleted`` replies that resume the
    TLS layers' blocking hooks — are forwarded to the child, so the inner connection is
    intercepted and decoded exactly like a direct ``CONNECT host:443``.

    The client and server sides of the handshake are tracked with independent phase
    variables (``_c_phase`` / ``_s_phase``) because SOCKS5 is lock-step but the client
    may pipeline its CONNECT request before the server sends the auth status — a single
    shared phase would mis-parse the server's auth reply as a CONNECT reply.
    """

    def __init__(self, context: layer.Context) -> None:
        super().__init__(context)
        self._c_phase = _C_GREETING
        self._s_phase = _S_GREETING
        self._method: int | None = None  # auth method chosen by the proxy
        self._client_buf = bytearray()   # client→server bytes not yet consumed by the parser
        self._server_buf = bytearray()   # server→client bytes not yet consumed by the parser
        self._target: tuple[str, int] | None = None  # real (host, port) from the CONNECT request
        self._child: layer.Layer | None = None
        self._username = ""
        self._password = ""
        # Save the proxy's address before we overwrite context.server.address with the
        # real target, so we can stamp it on the flow's Proxy metadata.
        addr = context.server.address
        self._proxy_addr = f"{addr[0]}:{addr[1]}" if addr else ""

    # ── public interface ──────────────────────────────────────────────────

    @expect(events.Start, events.DataReceived, events.ConnectionClosed, events.CommandCompleted)
    def _handle_event(self, event: events.Event) -> layer.CommandGenerator[None]:
        if self._child is not None:
            # Phase 2: forward everything (data, connection-closed, and the
            # CommandCompleted replies that resume paused TLS hooks) to the child stack.
            yield from self._child.handle_event(event)
            return

        if isinstance(event, events.Start):
            return

        if isinstance(event, events.DataReceived):
            if event.connection == self.context.client:
                yield from self._on_client_data(event.data)
            else:
                yield from self._on_server_data(event.data)
        elif isinstance(event, events.ConnectionClosed):
            yield commands.CloseConnection(self.context.client)
            yield commands.CloseConnection(self.context.server)

    # ── phase 1: relay + parse ─────────────────────────────────────────────

    def _on_client_data(self, data: bytes) -> layer.CommandGenerator[None]:
        """Buffer client→server bytes, relay the SOCKS5 portion, feed the rest to TLS."""
        if self._child is not None:
            # Phase 2: the TLS layers own the connection now.
            yield from self._child.handle_event(
                events.DataReceived(self.context.client, data)
            )
            return
        self._client_buf.extend(data)
        yield from self._parse_client()

    def _on_server_data(self, data: bytes) -> layer.CommandGenerator[None]:
        """Buffer server→client bytes, relay the SOCKS5 portion, feed the rest to TLS."""
        if self._child is not None:
            yield from self._child.handle_event(
                events.DataReceived(self.context.server, data)
            )
            return
        self._server_buf.extend(data)
        yield from self._parse_server()

    def _parse_client(self) -> layer.CommandGenerator[None]:
        if self._c_phase == _C_GREETING:
            # VER, NMETHODS, METHODS
            if len(self._client_buf) < 2:
                return
            n = self._client_buf[1]
            if len(self._client_buf) < 2 + n:
                return
            yield commands.SendData(self.context.server, bytes(self._client_buf[: 2 + n]))
            del self._client_buf[: 2 + n]
            # Wait for the server to pick a method before advancing; _parse_server
            # sets _method and re-drives us.
            if self._method is not None:
                self._c_phase = _C_AUTH if self._method == _MethodUserPass else _C_REQUEST
                yield from self._parse_client()
        elif self._c_phase == _C_AUTH:
            # RFC 1929: VER(0x01), ULEN, UNAME, PLEN, PASSWD
            if len(self._client_buf) < 2:
                return
            ulen = self._client_buf[1]
            if len(self._client_buf) < 3 + ulen:
                return
            plen = self._client_buf[2 + ulen]
            total = 3 + ulen + plen
            if len(self._client_buf) < total:
                return
            self._username = self._client_buf[2 : 2 + ulen].decode("utf-8", "replace")
            self._password = self._client_buf[3 + ulen : total].decode("utf-8", "replace")
            yield commands.SendData(self.context.server, bytes(self._client_buf[:total]))
            del self._client_buf[:total]
            self._c_phase = _C_REQUEST
            yield from self._parse_client()
        elif self._c_phase == _C_REQUEST:
            # VER, CMD, RSV, ATYP, ADDR, PORT
            if len(self._client_buf) < 4:
                return
            if self._client_buf[0] != _SocksV5:
                self._c_phase = _C_DONE
                return
            if self._client_buf[1] != _CmdConnect:
                self._c_phase = _C_DONE
                return
            atyp = self._client_buf[3]
            if atyp == _AtypIPv4:
                need = 4 + 4 + 2
            elif atyp == _AtypIPv6:
                need = 4 + 16 + 2
            elif atyp == _AtypDomain:
                if len(self._client_buf) < 5:
                    return
                dlen = self._client_buf[4]
                need = 4 + 1 + dlen + 2
            else:
                self._c_phase = _C_DONE
                return
            if len(self._client_buf) < need:
                return
            msg = bytes(self._client_buf[:need])
            yield commands.SendData(self.context.server, msg)
            del self._client_buf[:need]
            addr_off = 5 if atyp == _AtypDomain else 4  # domain has a 1-byte length prefix
            host = _parse_addr(atyp, msg[addr_off:-2])
            port = struct.unpack("!H", msg[-2:])[0]
            self._target = (host, port)
            self._c_phase = _C_DONE
            # If the server already sent its reply, we can establish now.
            if self._s_phase == _S_DONE:
                yield from self._establish()

    def _parse_server(self) -> layer.CommandGenerator[None]:
        if self._s_phase == _S_GREETING:
            # VER, METHOD
            if len(self._server_buf) < 2:
                return
            if self._server_buf[0] != _SocksV5:
                self._s_phase = _S_DONE
                return
            self._method = self._server_buf[1]
            yield commands.SendData(self.context.client, bytes(self._server_buf[:2]))
            del self._server_buf[:2]
            if self._method == _MethodNoAcceptable:
                self._s_phase = _S_DONE
                return
            if self._method not in (_MethodNone, _MethodUserPass):
                self._s_phase = _S_DONE
                return
            # Advance the server phase; also drive the client parser, which may
            # have auth/request bytes already buffered.
            self._s_phase = _S_AUTH if self._method == _MethodUserPass else _S_REQUEST
            if self._method == _MethodNone:
                self._s_phase = _S_REQUEST  # skip auth on server side
            # Drive client parser
            if self._method == _MethodUserPass:
                self._c_phase = _C_AUTH
            else:
                self._c_phase = _C_REQUEST
            yield from self._parse_client()
        elif self._s_phase == _S_AUTH:
            # VER(0x01), STATUS
            if len(self._server_buf) < 2:
                return
            if self._server_buf[0] != 0x01:
                self._s_phase = _S_DONE
                return
            status = self._server_buf[1]
            yield commands.SendData(self.context.client, bytes(self._server_buf[:2]))
            del self._server_buf[:2]
            if status != 0:
                self._s_phase = _S_DONE
                return
            self._s_phase = _S_REQUEST
            yield from self._parse_client()
        elif self._s_phase == _S_REQUEST:
            # VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            if len(self._server_buf) < 4:
                return
            if self._server_buf[0] != _SocksV5:
                self._s_phase = _S_DONE
                return
            atyp = self._server_buf[3]
            if atyp == _AtypIPv4:
                need = 4 + 4 + 2
            elif atyp == _AtypIPv6:
                need = 4 + 16 + 2
            elif atyp == _AtypDomain:
                if len(self._server_buf) < 5:
                    return
                dlen = self._server_buf[4]
                need = 4 + 1 + dlen + 2
            else:
                self._s_phase = _S_DONE
                return
            if len(self._server_buf) < need:
                return
            rep = self._server_buf[1]
            yield commands.SendData(self.context.client, bytes(self._server_buf[:need]))
            del self._server_buf[:need]
            if rep != _RepSucceeded:
                self._s_phase = _S_DONE
                return
            self._s_phase = _S_DONE
            # If the client CONNECT request has already been parsed, establish now.
            if self._target is not None:
                yield from self._establish()

    # ── phase 2: transition to TLS ─────────────────────────────────────────

    def _establish(self) -> layer.CommandGenerator[None]:
        """SOCKS5 CONNECT granted — switch to the TLS layer stack."""
        self._c_phase = _C_DONE
        self._s_phase = _S_DONE

        # The real destination is the SOCKS5 CONNECT target; the physical peer is the proxy.
        # The server connection is already open (CONNECT tunnel), and mitmproxy forbids
        # changing .address on an open connection — but the physical socket is unchanged;
        # we're only updating the logical identity so ServerTLSLayer connects TLS to the
        # right host (SNI) and the addon sees the real authority.  Bypass the guard via
        # __dict__.
        self.context.server.__dict__["address"] = self._target

        # Record the proxy the inner connection rode, so the addon's build_flow can
        # attach a Proxy field (matching the pcap decoder's behaviour). Stash it on both
        # the server and the client connection: the server is the natural place, but
        # mitmproxy's HTTP connection pool may hand the inner request a *different* Server
        # than this one (it re-keys/re-creates the upstream Server per stream), which drops
        # the attribute. The client connection is the stable anchor — the pool never swaps
        # it, and flow.client_conn is exactly this context.client — so the addon falls back
        # to it. Set the same dict on both.
        proxy_info = {
            "addr": self._proxy_addr,
            "type": "socks",
            "username": self._username,
            "password": self._password,
        }
        self.context.server._socks_proxy = proxy_info  # type: ignore[attr-defined]
        self.context.client._socks_proxy = proxy_info  # type: ignore[attr-defined]

        # Mark the server connection as expecting TLS.  The tlsconfig addon reads
        # this when the TlsClienthello hook fires inside ClientTLSLayer.
        self.context.server.tls = True

        # Build the same TLS stack mitmproxy's own next_layer addon builds for an
        # intercepted HTTPS connection: ServerTLSLayer wrapping ClientTLSLayer.  The
        # ClientTLSLayer decrypts the client side; the ServerTLSLayer re-encrypts toward
        # the real target over the already-open SOCKS tunnel.  Both are needed — with
        # ClientTLSLayer alone the decrypted request is forwarded upstream in cleartext,
        # and an HTTPS server answers "Client sent an HTTP request to an HTTPS server".
        #
        # The server connection is already open (the SOCKS tunnel), so ServerTLSLayer must
        # establish TLS over it without re-opening a socket.  mitmproxy does exactly this
        # in its eager, "server-TLS-first" path (see mitmproxy's test_tls.test_server_required
        # with server_state="open"): on the ClientHello, ClientTLSLayer asks for server TLS
        # first, ServerTLSLayer runs the handshake over the existing connection, and no
        # OpenConnection ever reaches the driver.  The addon's tls_clienthello hook forces
        # establish_server_tls_first=True for this connection so that path is taken
        # regardless of the global connection_strategy option.
        server_tls = tls_layer.ServerTLSLayer(self.context)
        server_tls.child_layer = tls_layer.ClientTLSLayer(self.context)
        self._child = server_tls

        # Leftover bytes that arrived after the SOCKS5 handshake — typically the inner
        # TLS ClientHello.  These were buffered (not relayed) during phase 1, so the TLS
        # layers see them as fresh data.  The child is fed Start + DataReceived.
        yield from self._child.handle_event(events.Start())

        if self._client_buf:
            yield from self._child.handle_event(
                events.DataReceived(self.context.client, bytes(self._client_buf))
            )
            self._client_buf.clear()
        if self._server_buf:
            yield from self._child.handle_event(
                events.DataReceived(self.context.server, bytes(self._server_buf))
            )
            self._server_buf.clear()


def _parse_addr(atyp: int, raw: bytes) -> str:
    """Parse a SOCKS5 address payload (without the ATYP byte) into a host string."""
    if atyp == _AtypIPv4:
        return socket.inet_ntop(socket.AF_INET, raw)
    if atyp == _AtypIPv6:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return raw.decode("ascii", "replace")
