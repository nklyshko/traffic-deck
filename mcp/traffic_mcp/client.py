"""Async gRPC client for the gateway, used by the MCP server.

Read-only: ViewerService (sessions/flows/bodies/ws messages) plus ControlService's
ListTags/ListGroups so name-based annotation filters resolve. The generated stubs
live in the sibling `gen/` tree (absolute `traffic.v1.*` imports).
"""

from __future__ import annotations

import sys
from pathlib import Path

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


class GatewayClient:
    """Thin async wrapper over ViewerServiceStub (+ ControlService reads)."""

    def __init__(self, address: str) -> None:
        self._address = address
        self._channel: grpc.aio.Channel | None = None
        self._viewer: viewer_pb2_grpc.ViewerServiceStub | None = None
        self._control: control_pb2_grpc.ControlServiceStub | None = None

    def _v(self) -> viewer_pb2_grpc.ViewerServiceStub:
        if self._viewer is None:
            self._channel = grpc.aio.insecure_channel(self._address)
            self._viewer = viewer_pb2_grpc.ViewerServiceStub(self._channel)
        return self._viewer

    def _c(self) -> control_pb2_grpc.ControlServiceStub:
        if self._control is None:
            self._v()  # shares the channel
            self._control = control_pb2_grpc.ControlServiceStub(self._channel)
        return self._control

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()

    async def list_sessions(self, limit: int = 200):
        resp = await self._v().ListSessions(viewer_pb2.ListSessionsRequest(limit=limit))
        return list(resp.sessions)

    async def list_flows(self, session_id: str):
        """All stored flow summaries for a session (StreamFlows backfill, no follow)."""
        call = self._v().StreamFlows(
            viewer_pb2.StreamFlowsRequest(session_id=session_id, include_backfill=True, follow=False)
        )
        flows = []
        async for ev in call:
            if ev.WhichOneof("event") == "flow_added":
                flows.append(ev.flow_added)
        return flows

    async def get_flow(self, session_id: str, flow_id: str):
        return await self._v().GetFlow(
            viewer_pb2.GetFlowRequest(session_id=session_id, flow_id=flow_id)
        )

    async def get_body(self, session_id: str, flow_id: str, response: bool) -> bytes:
        call = self._v().GetBody(
            viewer_pb2.GetBodyRequest(session_id=session_id, flow_id=flow_id, response=response)
        )
        return b"".join([c.payload async for c in call])

    async def list_messages(self, session_id: str, flow_id: str):
        resp = await self._v().ListMessages(
            viewer_pb2.ListMessagesRequest(session_id=session_id, flow_id=flow_id)
        )
        return list(resp.messages)

    async def get_message_body(self, session_id: str, message_id: str, raw: bool = False) -> bytes:
        call = self._v().GetMessageBody(
            viewer_pb2.GetMessageBodyRequest(session_id=session_id, message_id=message_id, raw=raw)
        )
        return b"".join([c.payload async for c in call])

    async def list_tags(self):
        resp = await self._c().ListTags(control_pb2.ListTagsRequest())
        return list(resp.tags)

    async def list_groups(self):
        resp = await self._c().ListGroups(control_pb2.ListGroupsRequest())
        return list(resp.groups)

    async def set_session_group(self, session_id: str, group: str) -> None:
        await self._c().SetSessionGroup(control_pb2.SetSessionGroupRequest(
            session_id=session_id, group=group))
