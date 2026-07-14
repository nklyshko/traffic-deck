"""MitmproxySource control surface with a fake mitmdump (no real proxy): the options form,
and start/stop through the served harness."""

from __future__ import annotations

import threading

import grpc

from capture_mitmproxy import source as mitm_source
from capture_mitmproxy.source import MitmproxySource
from capture_sdk import source as harness
from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.proto import source_pb2_grpc as sp_grpc


class FakeProc:
    """Stands in for a mitmdump process: emits a SESSION line, then blocks (the proxy is
    'running') until stopped."""

    def __init__(self):
        self.pid = 999999
        self._done = threading.Event()
        self._sent = False
        self._alive = True

    @property
    def stdout(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        if not self._sent:
            self._sent = True
            return "SESSION mm-1\n"
        self._done.wait(timeout=5)  # "running" until stopped
        raise StopIteration

    def poll(self):
        return None if self._alive else 0

    def stop(self):
        self._alive = False
        self._done.set()


def test_describe_offers_proxy_options():
    d = MitmproxySource("gw").describe({})
    assert [p.key for p in d.params] == ["mode", "listen_port", "listen_host"]
    assert [c.value for c in d.params[0].choices] == ["regular", "wireguard", "transparent", "local"]
    assert d.params[0].default == "regular"
    assert d.params[1].default == "8888"


def test_start_stop_through_the_served_harness(monkeypatch):
    procs = []
    monkeypatch.setattr(MitmproxySource, "_spawn", lambda self, cmd, env: procs.append(FakeProc()) or procs[-1])
    killed = []
    monkeypatch.setattr(mitm_source.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(mitm_source.os, "killpg", lambda pgid, sig: killed.append(pgid))

    src = MitmproxySource("gw")
    server, port = harness.serve(src, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    try:
        resp = stub.StartCapture(ctl.StartCaptureRequest(
            label="proxy-run", params={"mode": "regular", "listen_port": "8899"}))
        assert resp.session_id == "mm-1"

        st = stub.Status(ctl.StatusRequest())
        assert st.state == ctl.SOURCE_STATE_CAPTURING
        assert list(st.active_sessions) == ["mm-1"]

        stub.StopCapture(ctl.StopCaptureRequest(session_id="mm-1"))
        assert killed == [999999]  # SIGINT sent to mitmdump's group
        assert stub.Status(ctl.StatusRequest()).state == ctl.SOURCE_STATE_READY
    finally:
        procs[0].stop()
        chan.close()
        server.stop(None)


def test_start_capture_raises_if_mitmdump_never_opens_a_session(monkeypatch):
    class DeadProc:
        stdout = iter(["boot error\n"])  # exits without a SESSION line
        pid = 1

    monkeypatch.setattr(MitmproxySource, "_spawn", lambda self, cmd, env: DeadProc())
    try:
        MitmproxySource("gw").start_capture("x", {})
    except RuntimeError as e:
        assert "session" in str(e)
    else:
        raise AssertionError("expected a RuntimeError when no session opens")
