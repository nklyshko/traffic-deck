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

    def __init__(self, sid="mm-1"):
        self.pid = 999999
        self.sid = sid
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
            return f"SESSION {self.sid}\n"
        self._done.wait(timeout=5)  # "running" until stopped
        raise StopIteration

    def poll(self):
        return None if self._alive else 0

    def wait(self, timeout=None):
        if self._done.wait(timeout):
            return 0
        import subprocess
        raise subprocess.TimeoutExpired("mitmdump", timeout)

    def stop(self):
        self._alive = False
        self._done.set()


def test_describe_offers_proxy_options():
    d = MitmproxySource("gw").describe({})
    assert [p.key for p in d.params] == ["mode", "listen_port", "listen_host"]
    assert [c.value for c in d.params[0].choices] == ["regular", "socks5", "wireguard", "transparent", "local"]
    assert d.params[0].default == "regular"
    assert d.params[1].default == "8888"


def test_start_stop_through_the_served_harness(monkeypatch):
    procs = []
    monkeypatch.setattr(MitmproxySource, "_spawn", lambda self, cmd, env: procs.append(FakeProc()) or procs[-1])
    killed = []

    def fake_killpg(pgid, sig):
        killed.append(pgid)
        procs[-1].stop()  # graceful stop → the source's wait() returns, port freed

    monkeypatch.setattr(mitm_source.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(mitm_source.os, "killpg", fake_killpg)

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


def test_finish_then_start_a_new_capture(monkeypatch):
    # Stop one capture and start another: each spawns its own mitmdump, and stop waits for
    # the previous to exit so the proxy port is free for the next.
    procs = []

    def fake_spawn(self, cmd, env):
        p = FakeProc(sid=f"mm-{len(procs) + 1}")
        procs.append(p)
        return p

    monkeypatch.setattr(MitmproxySource, "_spawn", fake_spawn)
    monkeypatch.setattr(mitm_source.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(mitm_source.os, "killpg", lambda pgid, sig: procs[-1].stop())

    src = MitmproxySource("gw")
    sid1 = src.start_capture("first", {"listen_port": "8888"})
    assert sid1 == "mm-1"
    src.stop_capture(sid1)                       # finishes; waits for mitmdump exit
    assert procs[0].poll() is not None           # the first proxy really exited

    sid2 = src.start_capture("second", {"listen_port": "8888"})  # same port, works now
    assert sid2 == "mm-2"
    src.stop_capture(sid2)


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


def test_mitmdump_output_reaches_the_source_log(monkeypatch, capsys):
    """mitmdump's output is the only record of a connection that never became a flow (a
    pinned app's failed handshake), so it is passed on to the source's own output, which
    the gateway writes to mitmproxy.log — not drained to nowhere."""
    class ChattyProc:
        pid = 1
        stdout = iter(["HTTP(S) proxy listening\n", "SESSION mm-9\n",
                       "client TLS handshake failed: unknown ca\n"])
        def poll(self):
            return 0

    monkeypatch.setattr(MitmproxySource, "_spawn", lambda self, cmd, env: ChattyProc())
    src = MitmproxySource("gw")
    ended = threading.Event()
    monkeypatch.setattr(src, "session_ended", lambda sid: ended.set())
    assert src.start_capture("x", {}) == "mm-9"
    assert ended.wait(5)
    out = capsys.readouterr().out
    assert "HTTP(S) proxy listening" in out
    assert "client TLS handshake failed: unknown ca" in out


def test_mitmdump_runs_without_per_flow_output(monkeypatch):
    cmds = []
    monkeypatch.setattr(MitmproxySource, "_spawn",
                        lambda self, cmd, env: cmds.append(cmd) or FakeProc())
    src = MitmproxySource("gw")
    src.start_capture("x", {})
    assert "flow_detail=0" in cmds[0]
