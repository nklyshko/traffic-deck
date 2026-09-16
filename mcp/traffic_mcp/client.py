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

    async def query_flows(self, session_id: str, filter_expr: str = "", limit: int = 100,
                          after=None, before=None, last: bool = False,
                          since_micros: int = 0, until_micros: int = 0):
        """One page of a session's flows, filtered and paged by the gateway.

        Paging is by cursor rather than offset: a live session grows while it is read, so
        an offset shifts rows under the reader. `last` starts at the end of the list.
        """
        req = viewer_pb2.QueryFlowsRequest(
            session_id=session_id, filter=filter_expr, limit=limit, last=last,
            since_micros=since_micros or 0, until_micros=until_micros or 0)
        if after is not None:
            req.after.CopyFrom(after)
        if before is not None:
            req.before.CopyFrom(before)
        return await self._v().QueryFlows(req)

    async def get_flow(self, session_id: str, flow_id: str):
        return await self._v().GetFlow(
            viewer_pb2.GetFlowRequest(session_id=session_id, flow_id=flow_id)
        )

    def stream_flows(self, session_id: str, filter_expr: str = "", follow: bool = True):
        """Live FlowEvents for a session. Delta-only by construction — backfill is
        query_flows' job — so everything this yields arrived after the call. Returns the
        streaming call itself (an async iterator); cancel it to stop following."""
        return self._v().StreamFlows(
            viewer_pb2.StreamFlowsRequest(
                session_id=session_id, filter=filter_expr, follow=follow)
        )

    async def query_sql(self, session_id: str, sql: str, params: list[str] | None = None,
                        limit: int = 0, timeout_millis: int = 0):
        """One read-only SQL statement against a session bundle (or the catalog when
        session_id is empty). The gateway opens the file read-only; see ViewerService."""
        return await self._v().QuerySQL(
            viewer_pb2.QuerySQLRequest(
                session_id=session_id, sql=sql, params=params or [],
                limit=limit, timeout_millis=timeout_millis)
        )

    async def get_body(self, session_id: str, flow_id: str, response: bool) -> tuple[bytes, bool]:
        """The body's bytes, and whether they are only its start — which a live decode
        yields for a body that ran past its preview cap while the session is capturing."""
        call = self._v().GetBody(
            viewer_pb2.GetBodyRequest(session_id=session_id, flow_id=flow_id, response=response)
        )
        chunks: list[bytes] = []
        truncated = False
        async for c in call:
            chunks.append(c.payload)
            truncated = truncated or c.truncated
        return b"".join(chunks), truncated

    async def list_messages(self, session_id: str, flow_id: str, filter_expr: str = ""):
        """A flow's frames, filtered by the gateway. Returns (messages, hints)."""
        resp = await self._v().ListMessages(
            viewer_pb2.ListMessagesRequest(
                session_id=session_id, flow_id=flow_id, filter=filter_expr)
        )
        return list(resp.messages), list(resp.hints)

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

    async def set_session_label(self, session_id: str, label: str) -> None:
        await self._c().SetSessionLabel(control_pb2.SetSessionLabelRequest(
            session_id=session_id, label=label))
