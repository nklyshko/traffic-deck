"""ChromeSource control surface: Describe's discovery + cascade, and start/stop wiring
against a fake capture (no real browser/dumpcap)."""

from __future__ import annotations

import threading

import grpc

from capture_chrome import source as chrome_source
from capture_chrome.source import ChromeSource
from capture_sdk import source as harness
from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.proto import source_pb2 as sp
from capture_sdk.proto import source_pb2_grpc as sp_grpc


class FakeStore:
    def __init__(self, remembered=None):
        self._r = dict(remembered or {})
        self.saved = {}

    def get_valid(self, key, valid, default=None):
        v = self._r.get(key)
        return v if v in (valid or []) else default

    def remember(self, key, value):
        self.saved[key] = value
        return value


def make_source(monkeypatch, *, binaries, remembered=None):
    monkeypatch.setattr(chrome_source.platform, "chrome_binaries", lambda: list(binaries))
    src = ChromeSource("127.0.0.1:8080")
    src._store = FakeStore(remembered)
    return src


def test_describe_profile_choices_follow_the_chosen_binary(monkeypatch):
    src = make_source(monkeypatch, binaries=["/usr/bin/google-chrome", "/snap/bin/chromium"])
    # The chrome->profile dependency: profile choices differ per binary.
    monkeypatch.setattr(chrome_source.profiles, "profile_choices",
                        lambda c: [("temp", "Fresh")] if "chromium" in c
                        else [("default", "Default"), ("temp", "Fresh")])

    # With a binary determinable (defaults to the first), the full form appears — the
    # profile options being those of that default binary.
    d0 = src.describe({})
    assert [p.key for p in d0.params] == ["chrome", "profile", "new_profile_name", "url", "duration"]
    assert d0.params[0].default == "/usr/bin/google-chrome"
    assert [c.value for c in d0.params[1].choices] == ["default", "temp"]

    # Re-describe with a different binary → its profiles, not the first's.
    d1 = src.describe({"chrome": "/snap/bin/chromium"})
    assert [c.value for c in d1.params[1].choices] == ["temp"]


def test_describe_remembers_default_binary(monkeypatch):
    src = make_source(monkeypatch, binaries=["/a/chrome", "/b/chromium"],
                      remembered={"chrome": "/b/chromium"})
    monkeypatch.setattr(chrome_source.profiles, "profile_choices", lambda _c: [("temp", "Fresh")])
    assert src.describe({}).params[0].default == "/b/chromium"


def test_describe_path_param_when_no_binaries(monkeypatch):
    src = make_source(monkeypatch, binaries=[])
    d = src.describe({})
    assert d.params[0].key == "chrome"
    assert d.params[0].type == sp.PARAM_TYPE_PATH


class FakeCapture:
    """Stands in for ChromeCapture: wait() blocks until stop()/request_stop()."""
    instances: list["FakeCapture"] = []

    def __init__(self, **kw):
        self.kw = kw
        self.started = False
        self.stopped = False
        self._done = threading.Event()
        FakeCapture.instances.append(self)

    def start(self):
        self.started = True
        return f"sess-{len(FakeCapture.instances)}"

    def wait(self, stop_event=None):
        self._done.wait(timeout=2)

    def request_stop(self):
        self._done.set()

    def stop(self):
        self.stopped = True
        self._done.set()
        return None, None


def test_start_stop_through_the_served_harness(monkeypatch):
    # Drive the real path (StartCapture -> Status -> StopCapture over gRPC) so the harness's
    # session tracking is exercised; only the actual browser/dumpcap is faked.
    FakeCapture.instances.clear()
    src = make_source(monkeypatch, binaries=["/usr/bin/google-chrome"])
    monkeypatch.setattr(chrome_source.platform, "chrome_binary", lambda: "/usr/bin/google-chrome")
    monkeypatch.setattr(chrome_source, "ChromeCapture", FakeCapture)
    monkeypatch.setattr(chrome_source.profiles, "resolve_profile",
                        lambda chrome, val, new="": f"resolved:{val}")

    server, port = harness.serve(src, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    try:
        resp = stub.StartCapture(ctl.StartCaptureRequest(
            label="run1", params={"chrome": "/usr/bin/google-chrome", "profile": "temp"}))
        assert resp.session_id == "sess-1"
        cap = FakeCapture.instances[0]
        assert cap.kw["label"] == "run1" and cap.kw["profile"] == "resolved:temp"
        assert src._store.saved == {"chrome": "/usr/bin/google-chrome", "profile_value": "temp"}

        st = stub.Status(sp.StatusRequest())
        assert st.state == sp.SOURCE_STATE_CAPTURING
        assert list(st.active_sessions) == ["sess-1"]

        stub.StopCapture(ctl.StopCaptureRequest(session_id="sess-1"))
        assert cap.stopped
        assert stub.Status(sp.StatusRequest()).state == sp.SOURCE_STATE_READY
    finally:
        chan.close()
        server.stop(None)


def test_stop_capture_unknown_session_is_noop(monkeypatch):
    src = make_source(monkeypatch, binaries=[])
    src.stop_capture("nope")  # must not raise
