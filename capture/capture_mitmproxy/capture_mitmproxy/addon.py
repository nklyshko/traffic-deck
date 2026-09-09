"""mitmproxy addon that streams decoded flows to the gateway.

Loaded into mitmproxy with `mitmdump -s addon.py` (the `trafficdeck-capture-mitmproxy` launcher
does this). mitmproxy terminates TLS, so flows arrive fully decoded; this addon pushes
them to the gateway's IngestService.PushFlows for live view + persistence — no pcap,
no key.log (the supplied RECORD path).

WireGuard mode is just `--mode wireguard`: same addon, the device routes traffic
through mitmproxy's WireGuard server instead of a system proxy.

Config via env (set by the launcher): GATEWAY_ADDR, CAPTURE_LABEL.
"""

from __future__ import annotations

import os
import uuid

import grpc
from mitmproxy import ctx, http, tcp

from mitmproxy.proxy import layer as proxy_layer

from capture_mitmproxy.socks_upstream import looks_like_socks5, SocksUpstreamLayer

from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip
from capture_sdk.proto import ingest_pb2_grpc as ig

# Bound each push so a slow/unreachable gateway can't wedge a hook — and, importantly,
# can't block mitmproxy's shutdown on the first Ctrl+C.
PUSH_TIMEOUT = 5.0

def _s(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _peer(addr) -> str:
    if not addr:
        return ""
    host, port = addr[0], addr[1]
    return f"{host}:{port}"


def _norm_proto(v: str) -> str:
    # "HTTP/2.0" -> "HTTP/2", "HTTP/1.1" stays, "HTTP/3.0" -> "HTTP/3"
    return {"HTTP/2.0": "HTTP/2", "HTTP/3.0": "HTTP/3"}.get(v, v or "HTTP/1.1")


def _content(msg) -> bytes:
    """Best-effort decoded body bytes (decompressed); falls back to raw/empty."""
    try:
        return msg.get_content(strict=False) or b""
    except Exception:  # noqa: BLE001 (undecodable / streamed)
        return msg.raw_content or b""


def _wire_encoding(msg) -> str:
    """The transport encoding the body had on the wire ("gzip", "br"…), "" if none.

    Recorded alongside the (decoded) bytes _content returns, so a reader is told what
    they were rather than having to trust the header — which stays on the flow either
    way and can name an encoding the body was not actually sent in. "identity" is
    spelled-out absence.
    """
    enc = (msg.headers.get("content-encoding", "") or "").strip().lower()
    return "" if enc == "identity" else enc


def _is_ws_upgrade(resp) -> bool:
    return bool(resp and resp.status_code == 101 and
                resp.headers.get("upgrade", "").lower() == "websocket")


def _socks_proxy(flow: http.HTTPFlow) -> cp.Proxy | None:
    """Extract SOCKS5 proxy metadata stashed by SocksUpstreamLayer, if present."""
    # SocksUpstreamLayer stashes the same dict on both the server and the client
    # connection. The server is the natural place, but mitmproxy's HTTP connection pool
    # can hand the inner request a *different* Server than the one the layer stamped
    # (it re-keys connections and may build a fresh Server for the stream), which drops
    # the attribute. The client connection is the stable anchor — the pool never swaps
    # it — so fall back to it. flow.client_conn is the SocksUpstreamLayer's context.client.
    info = (getattr(flow.server_conn, "_socks_proxy", None)
            or getattr(flow.client_conn, "_socks_proxy", None))
    if not info:
        return None
    return cp.Proxy(
        addr=info.get("addr", ""),
        type=info.get("type", "socks"),
        username=info.get("username", ""),
        password=info.get("password", ""),
    )


def build_flow(flow: http.HTTPFlow) -> cp.Flow:
    """Translate a mitmproxy HTTPFlow into the gateway's proto Flow."""
    req, resp = flow.request, flow.response
    path, _, query = (req.path or "/").partition("?")

    pf = cp.Flow(
        id=flow.id,
        method=req.method or "",
        scheme=req.scheme or "",
        authority=req.host or "",
        path=path,
        query=query,
        protocol=_norm_proto(req.http_version),
        status=resp.status_code if resp else 0,
        src_addr=_peer(flow.client_conn.peername),
        dst_addr=_peer(flow.server_conn.address),
        ts_unix_micros=int((req.timestamp_start or 0) * 1_000_000),
        tls_decrypted=(req.scheme == "https"),
        user_agent=req.headers.get("user-agent", ""),
        websocket=_is_ws_upgrade(resp),
    )
    for k, v in req.headers.fields:
        pf.request_headers.append(cp.Header(name=_s(k), value=_s(v)))
    if resp:
        for k, v in resp.headers.fields:
            pf.response_headers.append(cp.Header(name=_s(k), value=_s(v)))
        pf.content_type = resp.headers.get("content-type", "")
    if not pf.content_type:
        pf.content_type = req.headers.get("content-type", "")

    rbody = _content(req)
    pf.request_bytes = len(rbody)
    if rbody:
        pf.request_body.CopyFrom(cp.Body(size=len(rbody), content_type=req.headers.get("content-type", ""),
                                         inline=rbody, content_encoding=_wire_encoding(req)))
    if resp:
        sbody = _content(resp)
        if sbody:
            pf.response_body.CopyFrom(cp.Body(size=len(sbody), content_type=resp.headers.get("content-type", ""),
                                              inline=sbody, content_encoding=_wire_encoding(resp)))

    # Forward any source-supplied metadata. Other addons (e.g. a scrape manager
    # that knows which proxy/provider served the request) stash it on
    # flow.metadata; we pass it through verbatim for the viewer to display.
    for k, v in (flow.metadata or {}).items():
        pf.metadata[_s(k)] = _s(v)

    # Attach proxy metadata when the flow rode a SOCKS5 tunnel intercepted by
    # SocksUpstreamLayer (set on the flow's server connection context).
    proxy = _socks_proxy(flow)
    if proxy:
        pf.proxy.CopyFrom(proxy)

    # Record why a request failed (connection reset, timeout, TLS/upstream error, …) so
    # the viewer can explain a flow with no response — mitmproxy sets flow.error on the
    # `error` hook.
    if flow.error and flow.error.msg:
        pf.error = _s(flow.error.msg)

    # Request→response elapsed, once the response is complete; left 0 while in flight so
    # the viewer shows a live stopwatch from ts_unix_micros instead.
    if resp and resp.timestamp_end and req.timestamp_start:
        pf.duration_micros = max(int((resp.timestamp_end - req.timestamp_start) * 1_000_000), 0)
    return pf


def build_tcp_flow(flow: tcp.TCPFlow) -> cp.Flow:
    """Synthesize a Flow for a raw (non-HTTP) TCP connection mitmproxy tunneled. Its byte
    stream is surfaced as directional messages (like WebSocket), so websocket=True reuses
    the message-timeline UI."""
    addr = flow.server_conn.address
    host = addr[0] if addr else ""
    sni = getattr(flow.server_conn, "sni", "") or ""
    authority = sni or (f"{host}:{addr[1]}" if addr else "")
    return cp.Flow(
        id=flow.id,
        protocol="TCP",
        authority=authority,
        src_addr=_peer(flow.client_conn.peername),
        dst_addr=_peer(addr),
        ts_unix_micros=int((flow.client_conn.timestamp_start or 0) * 1_000_000),
        tls_decrypted=bool(getattr(flow.server_conn, "tls_established", False)),
        websocket=True,
    )


def _ws_opcode(msg) -> str:
    name = getattr(getattr(msg, "type", None), "name", "") or ""
    return "text" if name.upper() == "TEXT" else "binary"


def _message(flow_id: str, from_client: bool, opcode: str, content: bytes, ts: float) -> cp.WsMessage:
    content = content or b""
    return cp.WsMessage(
        id=str(uuid.uuid4()),
        flow_id=flow_id,
        from_client=bool(from_client),
        opcode=opcode,
        ts_unix_micros=int((ts or 0) * 1_000_000),
        payload=cp.Body(size=len(content), inline=content),
    )


class GatewayPusher:
    """Pushes completed flows to the gateway; opens the session on startup."""

    def __init__(self) -> None:
        self.addr = os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331")
        self.label = os.environ.get("CAPTURE_LABEL", "mitmproxy")
        # Metadata keys this source stashes on flows that the viewer should show as table
        # columns by default (comma-separated); declared to the gateway at OpenSession.
        self.viewer_columns = os.environ.get("VIEWER_COLUMNS", "")
        self._channel: grpc.aio.Channel | None = None
        self._stub: ig.IngestServiceStub | None = None
        self.session_id: str | None = None
        # Track TCP flow start timestamps so tcp_end can compute duration.
        self._tcp_started: dict[str, float] = {}

    async def running(self) -> None:
        if self.session_id is not None:
            return  # `running` can fire more than once
        # Allow large messages: a captured download body can far exceed gRPC's 4 MiB default.
        self._channel = grpc.aio.insecure_channel(self.addr, options=[
            ("grpc.max_send_message_length", 256 * 1024 * 1024),
            ("grpc.max_receive_message_length", 256 * 1024 * 1024),
        ])
        self._stub = ig.IngestServiceStub(self._channel)
        metadata = {"viewer.columns": self.viewer_columns} if self.viewer_columns else {}
        handle = await self._stub.OpenSession(
            ip.OpenSessionRequest(label=self.label, source="mitmproxy",
                                  shape=cp.SOURCE_SHAPE_FLOWS, metadata=metadata)
        )
        self.session_id = handle.session_id
        ctx.log.info(f"gateway: session {self.session_id} @ {self.addr}")
        # A supervisor (serve-mode source) parses this line to learn the session id;
        # harmless noise otherwise.
        print(f"SESSION {self.session_id}", flush=True)

    async def request(self, flow: http.HTTPFlow) -> None:
        # Push the flow as soon as the request is seen, so an in-flight request (no
        # response yet) shows up immediately with a live stopwatch. response()/error()
        # re-push the same flow id with the outcome (the gateway upserts by id).
        await self._send(flows=[build_flow(flow)])

    async def response(self, flow: http.HTTPFlow) -> None:
        await self._send(flows=[build_flow(flow)])

    async def error(self, flow: http.HTTPFlow) -> None:
        # Push request-only flows too (connection reset, upstream error, …).
        if isinstance(flow, http.HTTPFlow):
            await self._send(flows=[build_flow(flow)])

    async def websocket_message(self, flow: http.HTTPFlow) -> None:
        # The parent Upgrade flow was pushed on `response` (101). Push each frame as it
        # arrives; flow.websocket.messages[-1] is the newest.
        if not flow.websocket or not flow.websocket.messages:
            return
        m = flow.websocket.messages[-1]
        await self._send(messages=[_message(flow.id, m.from_client, _ws_opcode(m), m.content, m.timestamp)])

    async def tcp_start(self, flow: tcp.TCPFlow) -> None:
        # Raw (non-HTTP) TCP connection: push the synthetic connection flow up front so its
        # byte-stream messages have a parent.
        self._tcp_started[flow.id] = flow.timestamp_start or 0
        await self._send(flows=[build_tcp_flow(flow)])

    async def tcp_message(self, flow: tcp.TCPFlow) -> None:
        if not flow.messages:
            return
        m = flow.messages[-1]
        await self._send(messages=[_message(flow.id, m.from_client, "binary", m.content, m.timestamp)])

    async def tcp_end(self, flow: tcp.TCPFlow) -> None:
        # The connection closed — re-push the flow with a duration so the viewer stops
        # the live stopwatch and marks it as done.
        await self._close_tcp_flow(flow)

    async def tcp_error(self, flow: tcp.TCPFlow) -> None:
        if flow.error and flow.error.msg:
            ctx.log.info(f"tcp error on {flow.id}: {flow.error.msg}")
        await self._close_tcp_flow(flow)

    async def websocket_end(self, flow: http.HTTPFlow) -> None:
        # WebSocket closed — re-push the parent flow so the viewer reflects the final state.
        if flow.websocket:
            await self._send(flows=[build_flow(flow)])

    async def _close_tcp_flow(self, flow: tcp.TCPFlow) -> None:
        start = self._tcp_started.pop(flow.id, None)
        pf = build_tcp_flow(flow)
        if start:
            import time
            pf.duration_micros = max(int((time.time() - start) * 1_000_000), 0)
        if flow.error and flow.error.msg:
            pf.error = _s(flow.error.msg)
        await self._send(flows=[pf])

    def tls_clienthello(self, data) -> None:
        # For a SOCKS-intercepted connection the upstream socket is an already-open tunnel
        # (SocksUpstreamLayer created a ServerTLSLayer → ClientTLSLayer stack over it).
        # Force mitmproxy to establish server TLS *first*, over that tunnel, before
        # replying to the client handshake.  Otherwise — with the default connection
        # strategy — the client side is decrypted but the request is forwarded upstream in
        # cleartext, and the HTTPS server answers "Client sent an HTTP request to an HTTPS
        # server".  This runs after the core tlsconfig hook (user scripts load last), so it
        # overrides tlsconfig's connection_strategy-derived default.
        if any(isinstance(layer, SocksUpstreamLayer) for layer in data.context.layers):
            data.establish_server_tls_first = True

    def next_layer(self, nextlayer: proxy_layer.NextLayer) -> None:
        # Detect a SOCKS5 greeting in the first client bytes after a CONNECT tunnel is
        # established (proxy-chain mode: social-parser → mitmproxy → SOCKS5 proxy → target).
        # Without this, mitmproxy treats the SOCKS5 + inner TLS as opaque TCP and never
        # intercepts the inner connection.  By inserting SocksUpstreamLayer, the SOCKS5
        # handshake is relayed transparently, the real target is extracted, and mitmproxy's
        # own TLS layers intercept the inner connection — so the addon sees normal decoded
        # HTTP/WebSocket flows with the real authority (e.g. ws-api.oneme.ru).
        #
        # The built-in NextLayer addon runs before user scripts (core addons register
        # first), so it has already picked TCPLayer for the SOCKS5 greeting (rawtcp=True +
        # non-HTTP first bytes).  We override that fallback — but only TCPLayer, never a
        # TLS/HTTP layer that a legitimate protocol sniff correctly identified.
        from mitmproxy.proxy.layers import tcp as tcp_layer
        if nextlayer.layer and not isinstance(nextlayer.layer, tcp_layer.TCPLayer):
            return  # a non-TCP layer was already chosen — don't clobber it
        if looks_like_socks5(nextlayer.data_client()):
            nextlayer.layer = SocksUpstreamLayer(nextlayer.context)

    async def _send(self, flows=None, messages=None) -> None:
        if self._stub is None or self.session_id is None:
            return
        try:
            call = self._stub.PushFlows(timeout=PUSH_TIMEOUT)
            await call.write(ip.FlowBatch(
                session_id=self.session_id, flows=flows or [], messages=messages or []))
            await call.done_writing()
            await call
        except Exception as exc:  # noqa: BLE001 (never break the proxy on a push error)
            ctx.log.warn(f"gateway push failed: {exc}")

    def done(self) -> None:
        # Shutdown: close the session over a short-lived sync channel (the async loop
        # is tearing down, so don't rely on it here).
        if self.session_id is None:
            return
        try:
            with grpc.insecure_channel(self.addr) as ch:
                ig.IngestServiceStub(ch).CloseSession(
                    ip.CloseSessionRequest(session_id=self.session_id), timeout=10
                )
        except Exception:  # noqa: BLE001
            pass


addons = [GatewayPusher()]
