"""A gateway that accepts a call and never answers must fail the tool call, not hang the
agent: unary calls without their own deadline get a default one."""
from __future__ import annotations

import asyncio

import grpc
import pytest

from traffic_mcp import client as client_mod
from traffic_mcp.client import GatewayClient
from traffic.v1 import viewer_pb2_grpc


class _WedgedViewer(viewer_pb2_grpc.ViewerServiceServicer):
    async def ListSessions(self, request, context):
        await asyncio.sleep(3600)  # accepted, never answered


def test_a_wedged_gateway_times_out_instead_of_hanging(monkeypatch):
    monkeypatch.setattr(client_mod, "DEFAULT_UNARY_TIMEOUT", 0.3)

    async def run():
        server = grpc.aio.server()
        viewer_pb2_grpc.add_ViewerServiceServicer_to_server(_WedgedViewer(), server)
        port = server.add_insecure_port("127.0.0.1:0")
        await server.start()
        c = GatewayClient(f"127.0.0.1:{port}")
        try:
            with pytest.raises(grpc.aio.AioRpcError) as err:
                await asyncio.wait_for(c.list_sessions(), timeout=10)
            assert err.value.code() == grpc.StatusCode.DEADLINE_EXCEEDED
        finally:
            await c.close()
            await server.stop(0)

    asyncio.run(run())
