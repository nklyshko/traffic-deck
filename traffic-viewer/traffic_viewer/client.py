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
from traffic.v1 import viewer_pb2, viewer_pb2_grpc  # noqa: E402

Session = viewer_pb2  # re-exported module for callers that need message types
Flow = viewer_pb2


class GatewayClient:
    """Thin async wrapper over ViewerServiceStub."""

    def __init__(self, address: str) -> None:
        self._address = address
        self._channel: grpc.aio.Channel | None = None
        self._stub: viewer_pb2_grpc.ViewerServiceStub | None = None

    def _ensure(self) -> viewer_pb2_grpc.ViewerServiceStub:
        # Lazily create the aio channel/stub on first use (inside the event loop).
        if self._stub is None:
            self._channel = grpc.aio.insecure_channel(self._address)
            self._stub = viewer_pb2_grpc.ViewerServiceStub(self._channel)
        return self._stub

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()

    async def list_sessions(self, limit: int = 200):
        resp = await self._ensure().ListSessions(viewer_pb2.ListSessionsRequest(limit=limit))
        return list(resp.sessions)

    async def stream_flows(self, session_id: str) -> AsyncIterator:
        call = self._ensure().StreamFlows(
            viewer_pb2.StreamFlowsRequest(session_id=session_id, include_backfill=True)
        )
        async for event in call:
            if event.HasField("flow_added"):
                yield event.flow_added

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
