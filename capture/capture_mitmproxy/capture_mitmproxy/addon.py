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


def _is_ws_upgrade(resp) -> bool:
    return bool(resp and resp.status_code == 101 and
                resp.headers.get("upgrade", "").lower() == "websocket")


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
        pf.request_body.CopyFrom(cp.Body(size=len(rbody), content_type=req.headers.get("content-type", ""), inline=rbody))
    if resp:
        sbody = _content(resp)
        if sbody:
            pf.response_body.CopyFrom(cp.Body(size=len(sbody), content_type=resp.headers.get("content-type", ""), inline=sbody))

    # Forward any source-supplied metadata. Other addons (e.g. a scrape manager
    # that knows which proxy/provider served the request) stash it on
    # flow.metadata; we pass it through verbatim for the viewer to display.
    for k, v in (flow.metadata or {}).items():
        pf.metadata[_s(k)] = _s(v)

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
        self.addr = os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080")
        self.label = os.environ.get("CAPTURE_LABEL", "mitmproxy")
        # Metadata keys this source stashes on flows that the viewer should show as table
        # columns by default (comma-separated); declared to the gateway at OpenSession.
        self.viewer_columns = os.environ.get("VIEWER_COLUMNS", "")
        self._channel: grpc.aio.Channel | None = None
        self._stub: ig.IngestServiceStub | None = None
        self.session_id: str | None = None

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
            ip.OpenSessionRequest(label=self.label, source_kind=cp.SOURCE_KIND_MITMPROXY,
                                  metadata=metadata)
        )
        self.session_id = handle.session_id
        ctx.log.info(f"gateway: session {self.session_id} @ {self.addr}")

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
        await self._send(flows=[build_tcp_flow(flow)])

    async def tcp_message(self, flow: tcp.TCPFlow) -> None:
        if not flow.messages:
            return
        m = flow.messages[-1]
        await self._send(messages=[_message(flow.id, m.from_client, "binary", m.content, m.timestamp)])

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
