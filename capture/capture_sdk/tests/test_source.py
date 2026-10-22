"""The CaptureSourceService serve harness (capture_sdk.source): a fake source served on a
real gRPC channel, exercised through the generated stub."""

from __future__ import annotations

import grpc
import pytest

from capture_sdk import source
from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.proto import source_pb2_grpc as sp_grpc


class FakeSource(source.CaptureSource):
    """Minimal source: one CHOICE param that cascades, capture is just id bookkeeping."""

    def __init__(self):
        super().__init__()
        self.started: list[tuple[str, dict]] = []
        self.stopped: list[str] = []
        self.released = 0
        self._n = 0

    def describe(self, params):
        # Cascading: the second param only appears once the first is chosen.
        params_out = [source.param("target", "Target", source.CHOICE,
                                   choices=[source.choice("a"), source.choice("b")])]
        if params.get("target"):
            params_out.append(source.param("mode", "Mode", source.STRING, default="fast"))
        return source.descriptor(params_out)

    def start_capture(self, label, params):
        self._n += 1
        sid = f"sess-{self._n}"
        self.started.append((label, dict(params)))
        return sid

    def stop_capture(self, session_id):
        self.stopped.append(session_id)

    def release(self):
        self.released += 1


@pytest.fixture
def served():
    src = FakeSource()
    server, port = source.serve(src, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    yield src, stub
    chan.close()
    server.stop(None)


def test_describe_cascades(served):
    src, stub = served
    d0 = stub.Describe(ctl.DescribeRequest())
    assert [p.key for p in d0.params] == ["target"]
    assert d0.readiness == ctl.READINESS_READY
    assert [c.value for c in d0.params[0].choices] == ["a", "b"]

    d1 = stub.Describe(ctl.DescribeRequest(params={"target": "a"}))
    assert [p.key for p in d1.params] == ["target", "mode"]
    assert d1.params[1].default == "fast"


def test_start_tracks_session_and_status(served):
    src, stub = served
    assert stub.Status(ctl.StatusRequest()).state == ctl.SOURCE_STATE_READY

    resp = stub.StartCapture(ctl.StartCaptureRequest(label="run1", params={"target": "b"}))
    assert resp.session_id == "sess-1"
    assert src.started == [("run1", {"target": "b"})]

    st = stub.Status(ctl.StatusRequest())
    assert st.state == ctl.SOURCE_STATE_CAPTURING
    assert list(st.active_sessions) == ["sess-1"]


def test_stop_untracks_session(served):
    src, stub = served
    sid = stub.StartCapture(ctl.StartCaptureRequest(label="r", params={})).session_id
    stub.StopCapture(ctl.StopCaptureRequest(session_id=sid))
    assert src.stopped == [sid]
    assert stub.Status(ctl.StatusRequest()).state == ctl.SOURCE_STATE_READY


def test_provisioning_state(served):
    src, stub = served
    src.provisioning = True
    assert stub.Status(ctl.StatusRequest()).state == ctl.SOURCE_STATE_PROVISIONING


def test_release(served):
    src, stub = served
    stub.ReleaseSource(ctl.ReleaseSourceRequest())
    assert src.released == 1


def test_source_error_becomes_grpc_status(served):
    src, stub = served

    def boom(label, params):
        raise ValueError("no device")
    src.start_capture = boom

    with pytest.raises(grpc.RpcError) as ei:
        stub.StartCapture(ctl.StartCaptureRequest(label="x", params={}))
    assert ei.value.code() == grpc.StatusCode.INTERNAL
    assert "no device" in ei.value.details()


def test_shutdown_stops_live_captures_and_releases():
    # The signal path: every live capture is stopped and the resource released, so a
    # supervised tool finalizes instead of stranding sessions.
    src = FakeSource()
    src._track("sess-1")
    src._track("sess-2")
    src._shutdown()
    assert sorted(src.stopped) == ["sess-1", "sess-2"]
    assert src.released == 1
    assert src._status().state == ctl.SOURCE_STATE_READY  # nothing left active


# --- several sources over one connection --------------------------------------
#
# A module whose tools share one expensive resource (Android: one emulator, per-app and
# browser capture) serves them from one process, so requests carry the source name.


@pytest.fixture
def served_pair():
    srcs = {"one": FakeSource(), "two": FakeSource()}
    server, port = source.serve(srcs, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    yield srcs, sp_grpc.CaptureSourceServiceStub(chan)
    chan.close()
    server.stop(None)


def test_requests_are_routed_by_source_name(served_pair):
    srcs, stub = served_pair
    stub.StartCapture(ctl.StartCaptureRequest(source="two", label="run", params={"x": "1"}))
    assert srcs["two"].started == [("run", {"x": "1"})]
    assert srcs["one"].started == []
    # Status is per source, so one tool capturing doesn't make the other look busy.
    assert stub.Status(ctl.StatusRequest(source="two")).state == ctl.SOURCE_STATE_CAPTURING
    assert stub.Status(ctl.StatusRequest(source="one")).state == ctl.SOURCE_STATE_READY


def test_stop_is_routed_by_session_id(served_pair):
    """StopCapture carries no source name — the session id already identifies one capture
    across the module, so the harness finds its owner."""
    srcs, stub = served_pair
    resp = stub.StartCapture(ctl.StartCaptureRequest(source="two", label="run"))
    stub.StopCapture(ctl.StopCaptureRequest(session_id=resp.session_id))
    assert srcs["two"].stopped == [resp.session_id]
    assert srcs["one"].stopped == []


def test_release_is_routed_by_source_name(served_pair):
    srcs, stub = served_pair
    stub.ReleaseSource(ctl.ReleaseSourceRequest(source="one"))
    assert (srcs["one"].released, srcs["two"].released) == (1, 0)


def test_an_unserved_name_is_refused_with_what_is_served(served_pair):
    _, stub = served_pair
    with pytest.raises(grpc.RpcError) as ei:
        stub.Describe(ctl.DescribeRequest(source="three"))
    assert ei.value.code() == grpc.StatusCode.NOT_FOUND
    assert "one, two" in ei.value.details()


def test_an_unnamed_request_gets_the_first_source(served_pair):
    """Declaration order is the module's statement of which tool is the obvious one."""
    srcs, stub = served_pair
    stub.StartCapture(ctl.StartCaptureRequest(label="run"))
    assert len(srcs["one"].started) == 1 and srcs["two"].started == []


def test_a_single_source_answers_whatever_name_it_is_asked_for(served):
    """Back-compat, and the reason it is this way round: every other tool serves one source
    and does not know the name the gateway registered it under — while the gateway now always
    sends one. It has exactly one tool, so the name cannot be meant for anything else."""
    src, stub = served
    stub.StartCapture(ctl.StartCaptureRequest(source="chrome", label="run"))
    stub.StartCapture(ctl.StartCaptureRequest(source="anything-at-all", label="run"))
    assert len(src.started) == 2
    assert stub.Describe(ctl.DescribeRequest(source="chrome")).params


def test_shutdown_covers_every_source():
    srcs = {"one": FakeSource(), "two": FakeSource()}
    srcs["one"]._track("a")
    srcs["two"]._track("b")
    server, port = source.serve(srcs, "127.0.0.1:0")
    server.stop(None)
    # serve_forever's teardown, without the signal wait: each source stops its own captures.
    for src in srcs.values():
        src._shutdown()
    assert srcs["one"].stopped == ["a"] and srcs["two"].stopped == ["b"]
    assert (srcs["one"].released, srcs["two"].released) == (1, 1)


def test_serve_needs_at_least_one_source():
    with pytest.raises(ValueError):
        source.serve({}, "127.0.0.1:0")
