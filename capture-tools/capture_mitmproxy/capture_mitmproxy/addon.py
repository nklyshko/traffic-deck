"""mitmproxy addon that streams decoded flows to the traffic-gateway (plan §7.2).

Loaded into mitmproxy with `mitmdump -s addon.py` (the `capture-mitmproxy` launcher
does this). mitmproxy terminates TLS, so flows arrive fully decoded; this addon pushes
them to the gateway's IngestService.PushFlows for live view + persistence — no pcap,
no key.log (the supplied RECORD path, plan §6.1).

WireGuard mode is just `--mode wireguard`: same addon, the device routes traffic
through mitmproxy's WireGuard server instead of a system proxy.

Config via env (set by the launcher): GATEWAY_ADDR, CAPTURE_LABEL.
"""

from __future__ import annotations

import os

import grpc
from mitmproxy import ctx, http

from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip
from capture_sdk.proto import ingest_pb2_grpc as ig


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
    return pf


class GatewayPusher:
    """Pushes completed flows to the gateway; opens the session on startup."""

    def __init__(self) -> None:
        self.addr = os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080")
        self.label = os.environ.get("CAPTURE_LABEL", "mitmproxy")
        self._channel: grpc.aio.Channel | None = None
        self._stub: ig.IngestServiceStub | None = None
        self.session_id: str | None = None

    async def running(self) -> None:
        if self.session_id is not None:
            return  # `running` can fire more than once
        self._channel = grpc.aio.insecure_channel(self.addr)
        self._stub = ig.IngestServiceStub(self._channel)
        handle = await self._stub.OpenSession(
            ip.OpenSessionRequest(label=self.label, source_kind=cp.SOURCE_KIND_MITMPROXY)
        )
        self.session_id = handle.session_id
        ctx.log.info(f"traffic-gateway: session {self.session_id} @ {self.addr}")

    async def response(self, flow: http.HTTPFlow) -> None:
        await self._push(flow)

    async def error(self, flow: http.HTTPFlow) -> None:
        # Push request-only flows too (connection reset, upstream error, …).
        if isinstance(flow, http.HTTPFlow):
            await self._push(flow)

    async def _push(self, flow: http.HTTPFlow) -> None:
        if self._stub is None or self.session_id is None:
            return
        try:
            pf = build_flow(flow)
            call = self._stub.PushFlows()
            await call.write(ip.FlowBatch(session_id=self.session_id, flows=[pf]))
            await call.done_writing()
            await call
        except Exception as exc:  # noqa: BLE001 (never break the proxy on a push error)
            ctx.log.warn(f"traffic-gateway push failed: {exc}")

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
