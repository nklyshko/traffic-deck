"""Async gRPC client for the gateway, used by the MCP server.

Mostly read-only: ViewerService (sessions/flows/bodies/ws messages) plus ControlService's
ListTags/ListGroups so name-based annotation filters resolve. The exceptions are the
session-metadata writes and the capture-control calls at the bottom, which the MCP server
only exposes when it is not in read-only mode.
"""

from __future__ import annotations

import grpc
from traffic.v1 import (
    control_pb2,
    control_pb2_grpc,
    viewer_pb2,
    viewer_pb2_grpc,
)


#: Deadline for a unary call that names none, so a gateway that accepts a call but never
#: answers fails the tool call instead of hanging the agent. Above QuerySQL's 60 s ceiling.
#: The capture-control calls below set their own; streams (wait_for_flows) set theirs.
DEFAULT_UNARY_TIMEOUT = 90.0


class _DefaultDeadline(grpc.aio.UnaryUnaryClientInterceptor):
    async def intercept_unary_unary(self, continuation, client_call_details, request):
        if client_call_details.timeout is None:
            client_call_details = client_call_details._replace(timeout=DEFAULT_UNARY_TIMEOUT)
        return await continuation(client_call_details, request)


class GatewayClient:
    """Thin async wrapper over ViewerServiceStub (+ the ControlService calls below)."""

    def __init__(self, address: str) -> None:
        self._address = address
        self._channel: grpc.aio.Channel | None = None
        self._viewer: viewer_pb2_grpc.ViewerServiceStub | None = None
        self._control: control_pb2_grpc.ControlServiceStub | None = None

    def _v(self) -> viewer_pb2_grpc.ViewerServiceStub:
        if self._viewer is None:
            self._channel = grpc.aio.insecure_channel(
                self._address, interceptors=[_DefaultDeadline()])
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
                          since_micros: int = 0, until_micros: int = 0,
                          include_hidden: bool = False):
        """One page of a session's flows, filtered and paged by the gateway.

        Paging is by cursor rather than offset: a live session grows while it is read, so
        an offset shifts rows under the reader. `last` starts at the end of the list.
        """
        req = viewer_pb2.QueryFlowsRequest(
            session_id=session_id, filter=filter_expr, limit=limit, last=last,
            since_micros=since_micros or 0, until_micros=until_micros or 0,
            include_hidden=include_hidden)
        if after is not None:
            req.after.CopyFrom(after)
        if before is not None:
            req.before.CopyFrom(before)
        return await self._v().QueryFlows(req)

    async def get_flow(self, session_id: str, flow_id: str):
        return await self._v().GetFlow(
            viewer_pb2.GetFlowRequest(session_id=session_id, flow_id=flow_id)
        )

    def stream_flows(self, session_id: str, filter_expr: str = "", follow: bool = True,
                     include_hidden: bool = False):
        """Live FlowEvents for a session. Delta-only by construction — backfill is
        query_flows' job — so everything this yields arrived after the call. Returns the
        streaming call itself (an async iterator); cancel it to stop following."""
        return self._v().StreamFlows(
            viewer_pb2.StreamFlowsRequest(
                session_id=session_id, filter=filter_expr, follow=follow,
                include_hidden=include_hidden)
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

    async def get_body(self, session_id: str, flow_id: str, side: str) -> bytes:
        call = self._v().GetBody(viewer_pb2.GetBodyRequest(
            session_id=session_id, flow_id=flow_id, response=side == "response"))
        return b"".join([c.payload async for c in call])

    async def list_undecoded(self, session_id: str, reason: str = "", host: str = "",
                             limit: int = 100, offset: int = 0):
        """A session's undecoded-connection index (pcap sessions), largest first."""
        return await self._v().ListUndecodedConnections(viewer_pb2.ListUndecodedRequest(
            session_id=session_id, reason=reason, host=host, limit=limit, offset=offset))

    async def get_connection_bytes(self, session_id: str, connection_id: str, sender: str,
                                   byte_offset: int = 0, limit: int = 0):
        """One undecoded connection's bytes, read back from the session's capture."""
        return await self._v().GetConnectionBytes(viewer_pb2.GetConnectionBytesRequest(
            session_id=session_id, connection_id=connection_id, from_client=sender == "client",
            byte_offset=byte_offset, limit=limit))

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

    # --- capture control ---------------------------------------------------
    #
    # Writes, like the session-metadata calls above. Each call carries its own deadline,
    # because the first describe or start of a source *spawns* it: the built-ins launch
    # through `uv`, which on a cold environment resolves and builds the tool's
    # dependencies first (the gateway allows two minutes for that — sourcemgr.readyTimeout,
    # and the TUI paints a "this can take a minute" notice over the same wait). The client
    # default (DEFAULT_UNARY_TIMEOUT) would give up in the middle of that build and leave
    # the source coming up behind it.

    #: Deadline for a call that may have to spawn a source. Matches the gateway's own
    #: patience, plus a margin so the gateway's error arrives instead of our timeout.
    SPAWN_DEADLINE = 150.0

    async def list_capture_sources(self):
        """The sources the gateway can drive right now. A source the user has to start by
        hand (see modules.md) is absent while it is not listening, so this is "what will
        work", not "what is configured"."""
        resp = await self._c().ListCaptureSources(control_pb2.Empty(), timeout=30.0)
        return list(resp.sources)

    async def describe_capture_source(self, source: str, params: dict[str, str] | None = None):
        """One step of a source's option form, for the answers so far. Cascading: answering
        a param can change which params come back next."""
        return await self._c().DescribeCaptureSource(
            control_pb2.DescribeCaptureSourceRequest(source=source, params=params or {}),
            timeout=self.SPAWN_DEADLINE)

    async def start_capture(self, source: str, label: str = "",
                            params: dict[str, str] | None = None) -> str:
        resp = await self._c().StartCapture(
            control_pb2.StartCaptureRequest(source=source, label=label, params=params or {}),
            timeout=self.SPAWN_DEADLINE)
        return resp.session_id

    async def stop_capture(self, session_id: str):
        """Stop a capture the gateway started, returning the closed session. The source
        tears its capture down and closes the session before this returns, so the counts
        on the result are final."""
        resp = await self._c().StopCapture(
            control_pb2.StopCaptureRequest(session_id=session_id), timeout=120.0)
        return resp.session
