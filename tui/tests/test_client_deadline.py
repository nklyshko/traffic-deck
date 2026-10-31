"""A gateway that accepts a call and never answers must not hang the viewer: unary calls
get a default deadline, except the ones that legitimately run long."""
from __future__ import annotations

import asyncio

import grpc
import pytest

from traffic_viewer import client as client_mod
from traffic_viewer.client import GatewayClient, control_pb2, viewer_pb2, viewer_pb2_grpc


class _WedgedViewer(viewer_pb2_grpc.ViewerServiceServicer):
    async def ListSessions(self, request, context):
        await asyncio.sleep(3600)  # accepted, never answered


async def test_a_wedged_gateway_times_out_instead_of_hanging(monkeypatch):
    monkeypatch.setattr(client_mod, "DEFAULT_UNARY_TIMEOUT", 0.3)
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


async def test_long_running_calls_get_no_default_deadline():
    seen = {}

    async def continuation(details, request):
        seen[details.method] = details.timeout

    ic = client_mod._DefaultDeadline()

    def details(method):
        return grpc.aio.ClientCallDetails(method, None, None, None, None)

    await ic.intercept_unary_unary(continuation, details(b"/traffic.v1.ControlService/ImportCapture"),
                                   control_pb2.ImportCaptureRequest())
    await ic.intercept_unary_unary(continuation, details(b"/traffic.v1.ViewerService/ListSessions"),
                                   viewer_pb2.ListSessionsRequest())
    assert seen[b"/traffic.v1.ControlService/ImportCapture"] is None
    assert seen[b"/traffic.v1.ViewerService/ListSessions"] == client_mod.DEFAULT_UNARY_TIMEOUT
