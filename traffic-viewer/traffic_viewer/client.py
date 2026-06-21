"""Async gRPC client for the traffic-gateway ViewerService.

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

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()

    async def list_sessions(self, limit: int = 200):
        resp = await self._ensure().ListSessions(viewer_pb2.ListSessionsRequest(limit=limit))
        return list(resp.sessions)

    async def stream_flows(self, session_id: str, follow: bool = False) -> AsyncIterator:
        """Yield FlowEvents: backfill of stored flows, then (if follow) live events."""
        call = self._ensure().StreamFlows(
            viewer_pb2.StreamFlowsRequest(
                session_id=session_id, include_backfill=True, follow=follow
            )
        )
        async for event in call:
            yield event

    async def get_flow(self, session_id: str, flow_id: str):
        return await self._ensure().GetFlow(
            viewer_pb2.GetFlowRequest(session_id=session_id, flow_id=flow_id)
        )

    async def get_body(self, session_id: str, flow_id: str, response: bool) -> bytes:
        """Fetch a full body (any size) via the streaming GetBody RPC."""
        call = self._ensure().GetBody(
            viewer_pb2.GetBodyRequest(session_id=session_id, flow_id=flow_id, response=response)
        )
        chunks = [c.payload async for c in call]
        return b"".join(chunks)

    async def list_messages(self, session_id: str, flow_id: str):
        """WebSocket frames for an Upgrade flow, in timeline order."""
        resp = await self._ensure().ListMessages(
            viewer_pb2.ListMessagesRequest(session_id=session_id, flow_id=flow_id)
        )
        return list(resp.messages)

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

    # --- annotations (ControlService, plan §12) ---------------------------

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
