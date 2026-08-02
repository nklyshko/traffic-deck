"""Async gRPC client for the gateway ViewerService.

The generated stubs live in the sibling `gen/` tree (absolute `traffic.v1.*`
imports), so we put it on sys.path before importing them.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import AsyncIterator

_GEN = Path(__file__).resolve().parent.parent / "gen"
if str(_GEN) not in sys.path:
    sys.path.insert(0, str(_GEN))

import grpc  # noqa: E402
from traffic.v1 import (  # noqa: E402
    control_pb2,
    control_pb2_grpc,
    ingest_pb2,
    ingest_pb2_grpc,
    viewer_pb2,
    viewer_pb2_grpc,
)

Session = viewer_pb2  # re-exported module for callers that need message types
Flow = viewer_pb2


class GatewayClient:
    """Thin async wrapper over ViewerServiceStub + ControlServiceStub."""

    def __init__(self, address: str) -> None:
        self._address = address
        self._channel: grpc.aio.Channel | None = None
        self._stub: viewer_pb2_grpc.ViewerServiceStub | None = None
        self._control: control_pb2_grpc.ControlServiceStub | None = None
        self._ingest: ingest_pb2_grpc.IngestServiceStub | None = None

    def _ensure(self) -> viewer_pb2_grpc.ViewerServiceStub:
        # Lazily create the aio channel/stub on first use (inside the event loop).
        if self._stub is None:
            self._channel = grpc.aio.insecure_channel(self._address)
            self._stub = viewer_pb2_grpc.ViewerServiceStub(self._channel)
        return self._stub

    def _ctrl(self) -> control_pb2_grpc.ControlServiceStub:
        if self._control is None:
            self._ensure()  # shares the channel
            self._control = control_pb2_grpc.ControlServiceStub(self._channel)
        return self._control

    def _ing(self) -> ingest_pb2_grpc.IngestServiceStub:
        if self._ingest is None:
            self._ensure()  # shares the channel
            self._ingest = ingest_pb2_grpc.IngestServiceStub(self._channel)
        return self._ingest

    async def force_close_session(self, session_id: str) -> None:
        """Finalize a session stuck open (capture died without CloseSession)."""
        await self._ing().ForceCloseSession(ingest_pb2.CloseSessionRequest(session_id=session_id))

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()

    async def list_sessions(self, limit: int = 200):
        resp = await self._ensure().ListSessions(viewer_pb2.ListSessionsRequest(limit=limit))
        return list(resp.sessions)

    async def query_flows(self, session_id: str, filter_expr: str = "", limit: int = 250,
                          after=None, before=None, last: bool = False):
        """One page of a session's flows, filtered by the gateway.

        Navigation is by cursor, never by an offset computed from a total: `last` starts
        at the end of the list, so jumping there needs no idea how many rows match — which
        is what lets the match count stay approximate (ADR-0012).
        """
        req = viewer_pb2.QueryFlowsRequest(
            session_id=session_id, filter=filter_expr, limit=limit, last=last)
        if after is not None:
            req.after.CopyFrom(after)
        if before is not None:
            req.before.CopyFrom(before)
        return await self._ensure().QueryFlows(req)

    async def stream_flows(self, session_id: str, follow: bool = False,
                           filter_expr: str = "") -> AsyncIterator:
        """Yield FlowEvents for a session, filtered by the gateway.

        The same filter as query_flows, so following and filtering compose. Events include
        flow_unmatched, which says a flow has left this subscription's filtered view — not
        that it was deleted. Ignoring it leaves stale rows on screen.
        """
        call = self._ensure().StreamFlows(
            viewer_pb2.StreamFlowsRequest(
                session_id=session_id, follow=follow, filter=filter_expr
            )
        )
        async for event in call:
            yield event

    async def get_flow(self, session_id: str, flow_id: str):
        return await self._ensure().GetFlow(
            viewer_pb2.GetFlowRequest(session_id=session_id, flow_id=flow_id)
        )

    async def get_body(self, session_id: str, flow_id: str, response: bool) -> tuple[bytes, bool]:
        """Fetch a full body (any size) via the streaming GetBody RPC. Returns the bytes
        and whether they are only the body's start — what a live decode has for a body
        that outran its preview cap while the session is still capturing."""
        call = self._ensure().GetBody(
            viewer_pb2.GetBodyRequest(session_id=session_id, flow_id=flow_id, response=response)
        )
        chunks: list[bytes] = []
        truncated = False
        async for c in call:
            chunks.append(c.payload)
            truncated = truncated or c.truncated
        return b"".join(chunks), truncated

    async def list_messages(self, session_id: str, flow_id: str, filter_expr: str = ""):
        """WebSocket frames for an Upgrade flow, in timeline order, filtered by the
        gateway. Returns (messages, hints) — the message filter is its own dialect of the
        DSL (payload/opcode/direction/annotations), so a flow term comes back as an error
        rather than matching the payload."""
        resp = await self._ensure().ListMessages(
            viewer_pb2.ListMessagesRequest(
                session_id=session_id, flow_id=flow_id, filter=filter_expr)
        )
        return list(resp.messages), list(resp.hints)

    async def get_message(self, session_id: str, message_id: str):
        """One message with its annotations attached (for refreshing a row)."""
        return await self._ensure().GetMessage(
            viewer_pb2.GetMessageRequest(session_id=session_id, message_id=message_id)
        )

    async def stream_messages(self, session_id: str, flow_id: str, follow: bool = True,
                              filter_expr: str = ""):
        """Yield MessageEvents for an Upgrade flow: backfill of stored frames, then
        (if follow and the session is live) new frames until the session closes.

        The filter applies to both, so a filtered timeline stays filtered as it grows. Any
        advisory hints for the expression arrive as a filter_hints event before the frames.
        """
        call = self._ensure().StreamMessages(
            viewer_pb2.StreamMessagesRequest(
                session_id=session_id, flow_id=flow_id, follow=follow, filter=filter_expr
            )
        )
        async for event in call:
            yield event

    async def get_message_body(self, session_id: str, message_id: str) -> bytes:
        """Fetch a full WebSocket payload (any size) via streaming GetMessageBody."""
        call = self._ensure().GetMessageBody(
            viewer_pb2.GetMessageBodyRequest(session_id=session_id, message_id=message_id)
        )
        chunks = [c.payload async for c in call]
        return b"".join(chunks)

    async def export_session(self, session_id: str, dest_path: str) -> int:
        """Stream a session bundle (.tar.gz) from the gateway to dest_path.
        Returns the number of bytes written."""
        call = self._ctrl().ExportSession(
            control_pb2.ExportSessionRequest(session_id=session_id)
        )
        total = 0
        with open(dest_path, "wb") as fp:
            async for chunk in call:
                fp.write(chunk.data)
                total += len(chunk.data)
        return total

    # --- annotations (ControlService) ---------------------------

    async def list_tags(self):
        resp = await self._ctrl().ListTags(control_pb2.ListTagsRequest())
        return list(resp.tags)

    async def create_tag(self, name: str, color: str):
        return await self._ctrl().CreateTag(control_pb2.CreateTagRequest(name=name, color=color))

    async def delete_tag(self, tag_id: str) -> None:
        await self._ctrl().DeleteTag(control_pb2.DeleteTagRequest(id=tag_id))

    async def set_tags(self, session_id: str, record_ids, add=(), remove=()) -> None:
        await self._ctrl().SetTags(control_pb2.SetTagsRequest(
            session_id=session_id, record_ids=list(record_ids),
            add_tag_ids=list(add), remove_tag_ids=list(remove)))

    async def toggle_favorite(self, session_id: str, record_ids) -> None:
        await self._ctrl().ToggleFavorite(control_pb2.ToggleFavoriteRequest(
            session_id=session_id, record_ids=list(record_ids)))

    async def add_comment(self, session_id: str, record_id: str, body: str):
        return await self._ctrl().AddComment(control_pb2.AddCommentRequest(
            session_id=session_id, record_id=record_id, body=body))

    async def edit_comment(self, session_id: str, comment_id: str, body: str):
        return await self._ctrl().EditComment(control_pb2.EditCommentRequest(
            session_id=session_id, id=comment_id, body=body))

    async def delete_comment(self, session_id: str, comment_id: str) -> None:
        await self._ctrl().DeleteComment(control_pb2.DeleteCommentRequest(
            session_id=session_id, id=comment_id))

    async def set_mark(self, session_id: str, record_ids, color: str) -> None:
        await self._ctrl().SetMark(control_pb2.SetMarkRequest(
            session_id=session_id, record_ids=list(record_ids), color=color))

    async def clear_mark(self, session_id: str, record_ids) -> None:
        await self._ctrl().ClearMark(control_pb2.ClearMarkRequest(
            session_id=session_id, record_ids=list(record_ids)))

    async def list_groups(self):
        resp = await self._ctrl().ListGroups(control_pb2.ListGroupsRequest())
        return list(resp.groups)

    async def create_group(self, name: str, color: str, parent_id: str = ""):
        return await self._ctrl().CreateGroup(control_pb2.CreateGroupRequest(
            name=name, color=color, parent_id=parent_id))

    async def set_groups(self, session_id: str, record_ids, add=(), remove=()) -> None:
        await self._ctrl().SetGroups(control_pb2.SetGroupsRequest(
            session_id=session_id, record_ids=list(record_ids),
            add_group_ids=list(add), remove_group_ids=list(remove)))

    async def set_session_group(self, session_id: str, group: str) -> None:
        """Assign the session to a free-text group ("" clears it)."""
        await self._ctrl().SetSessionGroup(control_pb2.SetSessionGroupRequest(
            session_id=session_id, group=group))

    async def set_session_label(self, session_id: str, label: str) -> None:
        """Rename a session."""
        await self._ctrl().SetSessionLabel(control_pb2.SetSessionLabelRequest(
            session_id=session_id, label=label))

    async def delete_session(self, session_id: str) -> None:
        """Permanently delete a recorded session (catalog row + bundle)."""
        await self._ctrl().DeleteSession(control_pb2.DeleteSessionRequest(session_id=session_id))

    async def import_session(self, src_path: str):
        """Upload a .tar.gz session bundle; returns the imported Session."""
        call = self._ctrl().ImportSession()
        with open(src_path, "rb") as fp:
            while True:
                b = fp.read(1 << 16)
                if not b:
                    break
                await call.write(control_pb2.ImportChunk(data=b))
        await call.done_writing()
        resp = await call
        return resp.session

    async def import_capture(self, pcap_path: str, keylog_path: str, label: str, engine: str):
        """Decode a pre-captured pcap (+ optional key.log) on the gateway with the chosen
        engine ("tshark" | "native"); returns the imported Session. Paths resolve on the
        gateway host (the local host under one-command mode)."""
        resp = await self._ctrl().ImportCapture(control_pb2.ImportCaptureRequest(
            pcap_path=pcap_path, keylog_path=keylog_path, label=label, engine=engine))
        return resp.session

    async def get_session_artifacts(self, session_id: str):
        """Where the session's pcap + key.log live on the gateway host (empty paths when
        the session has none), for handing to an external analyzer like Wireshark."""
        return await self._ctrl().GetSessionArtifacts(
            control_pb2.GetSessionArtifactsRequest(session_id=session_id))

    # --- capture control (ADR-0010) -------------------------------------

    async def list_capture_sources(self):
        """The sources the gateway can drive (name, label, keep_warm)."""
        resp = await self._ctrl().ListCaptureSources(control_pb2.Empty())
        return list(resp.sources)

    async def describe_capture_source(self, source: str, params: dict | None = None):
        """A source's option form for the partial selection so far; re-called as fields
        fill in (cascading)."""
        return await self._ctrl().DescribeCaptureSource(
            control_pb2.DescribeCaptureSourceRequest(source=source, params=params or {}))

    async def start_capture(self, source: str, label: str, params: dict) -> str:
        """Start a capture on `source`; returns the opened session id."""
        resp = await self._ctrl().StartCapture(
            control_pb2.StartCaptureRequest(source=source, label=label, params=params))
        return resp.session_id

    async def stop_capture(self, session_id: str) -> None:
        """Stop a running capture by session id."""
        await self._ctrl().StopCapture(control_pb2.StopCaptureRequest(session_id=session_id))

    # --- auxiliary services (MCP, module UIs) ---------------------------

    async def list_services(self):
        """The gateway-owned auxiliary services and whether each is running."""
        resp = await self._ctrl().ListServices(control_pb2.Empty())
        return list(resp.services)

    async def start_service(self, name: str):
        """Start an auxiliary service; returns its ServiceInfo (running, url, detail)."""
        return await self._ctrl().StartService(control_pb2.ServiceRequest(name=name))

    async def stop_service(self, name: str) -> None:
        await self._ctrl().StopService(control_pb2.ServiceRequest(name=name))

    # --- child logs (gateway, capture sources, services) ----------------

    async def list_logs(self):
        """The logs the gateway can serve (name, label, size, mtime), those that exist."""
        resp = await self._ctrl().ListLogs(control_pb2.Empty())
        return list(resp.logs)

    async def get_log(self, name: str, max_bytes: int = 0) -> bytes:
        """The tail of a named log (0 = server default cap), streamed and joined."""
        call = self._ctrl().GetLog(
            control_pb2.GetLogRequest(name=name, max_bytes=max_bytes))
        chunks = [c.payload async for c in call]
        return b"".join(chunks)
