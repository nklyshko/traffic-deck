"""FirefoxSource control surface: Describe's discovery + cascade, and start/stop wiring
against a fake capture (no real browser/dumpcap)."""

from __future__ import annotations

import threading

import grpc

from capture_firefox import source as firefox_source
from capture_firefox.source import FirefoxSource
from capture_sdk import source as harness
from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.proto import source_pb2_grpc as sp_grpc


class FakeStore:
    def __init__(self, remembered=None):
        self._r = dict(remembered or {})
        self.saved = {}

    def get(self, key, default=None):
        return self._r.get(key, default)

    def get_valid(self, key, valid, default=None):
        v = self._r.get(key)
        return v if v in (valid or []) else default

    def remember(self, key, value):
        self.saved[key] = value
        return value


def make_source(monkeypatch, *, binaries, remembered=None):
    monkeypatch.setattr(firefox_source.platform, "firefox_binaries", lambda: list(binaries))
    src = FirefoxSource("127.0.0.1:8080")
    src._store = FakeStore(remembered)
    return src


def _keys(descriptor):
    return [p.key for p in descriptor.params]


def test_describe_offers_kind_then_drills_in_by_redescribe(monkeypatch):
    src = make_source(monkeypatch, binaries=["/usr/bin/firefox"])
    monkeypatch.setattr(firefox_source.platform, "firefox_profiles",
                        lambda _f: [("/u/.mozilla/firefox", "default", "a.default"),
                                    ("/u/.mozilla/firefox", "work", "b.work")])
    monkeypatch.setattr(firefox_source.profiles, "saved_profiles", lambda _f: ["research"])

    # Top level: binary + profile_kind (+ the capture opts). No which-one field yet — that's
    # the single-mechanism point: nothing shown before its kind is picked.
    d0 = src.describe({})
    assert _keys(d0) == ["firefox", "profile_kind", "url", "duration"]
    kind_values = [c.value for c in d0.params[1].choices]
    assert kind_values == ["existing", "default", "temp", "custom"]  # existing: profiles exist

    # Pick "existing" → re-describe grows the which-existing param, keyed by profile name
    # (that's what -P takes), with the directory shown to disambiguate.
    d1 = src.describe({"profile_kind": "existing"})
    assert _keys(d1) == ["firefox", "profile_kind", "existing_profile", "url", "duration"]
    assert [c.value for c in d1.params[2].choices] == ["default", "work"]

    # Pick "custom" → the saved-profile param, ending in a "new" option.
    d2 = src.describe({"profile_kind": "custom"})
    assert _keys(d2) == ["firefox", "profile_kind", "saved_profile", "url", "duration"]
    assert [c.value for c in d2.params[2].choices] == ["research", "__new__"]

    # Pick "custom" + new → the name field appears (and only then).
    d3 = src.describe({"profile_kind": "custom", "saved_profile": "__new__"})
    assert _keys(d3) == ["firefox", "profile_kind", "saved_profile", "new_profile_name",
                         "url", "duration"]

    # default/temp are terminal — no extra field.
    assert _keys(src.describe({"profile_kind": "temp"})) == ["firefox", "profile_kind",
                                                             "url", "duration"]


def test_describe_hides_existing_kind_when_no_profiles(monkeypatch):
    src = make_source(monkeypatch, binaries=["/usr/bin/firefox"])
    monkeypatch.setattr(firefox_source.platform, "firefox_profiles", lambda _f: [])
    kinds = [c.value for c in src.describe({}).params[1].choices]
    assert kinds == ["default", "temp", "custom"]  # no "existing"


def test_describe_remembers_default_binary(monkeypatch):
    src = make_source(monkeypatch, binaries=["/a/firefox", "/b/librewolf"],
                      remembered={"firefox": "/b/librewolf"})
    monkeypatch.setattr(firefox_source.platform, "firefox_profiles", lambda _f: [])
    assert src.describe({}).params[0].default == "/b/librewolf"


def test_describe_path_param_when_no_binaries(monkeypatch):
    src = make_source(monkeypatch, binaries=[])
    d = src.describe({})
    assert d.params[0].key == "firefox"
    assert d.params[0].type == ctl.PARAM_TYPE_PATH


class FakeCapture:
    """Stands in for FirefoxCapture: wait() blocks until stop()/request_stop()."""
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
    src = make_source(monkeypatch, binaries=["/usr/bin/firefox"])
    monkeypatch.setattr(firefox_source.platform, "firefox_binary", lambda: "/usr/bin/firefox")
    monkeypatch.setattr(firefox_source, "FirefoxCapture", FakeCapture)
    monkeypatch.setattr(firefox_source.profiles, "temp_profile", lambda _f: "/tmp/prof")

    server, port = harness.serve(src, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    try:
        resp = stub.StartCapture(ctl.StartCaptureRequest(
            label="run1", params={"firefox": "/usr/bin/firefox", "profile_kind": "temp"}))
        assert resp.session_id == "sess-1"
        cap = FakeCapture.instances[0]
        assert cap.kw["label"] == "run1" and cap.kw["profile"] == "/tmp/prof"
        assert src._store.saved == {"firefox": "/usr/bin/firefox", "profile_kind": "temp"}

        st = stub.Status(ctl.StatusRequest())
        assert st.state == ctl.SOURCE_STATE_CAPTURING
        assert list(st.active_sessions) == ["sess-1"]

        stub.StopCapture(ctl.StopCaptureRequest(session_id="sess-1"))
        assert cap.stopped
        assert stub.Status(ctl.StatusRequest()).state == ctl.SOURCE_STATE_READY
    finally:
        chan.close()
        server.stop(None)


def test_resolve_profile_existing_maps_name_to_root(monkeypatch):
    src = make_source(monkeypatch, binaries=["/usr/bin/firefox"])
    monkeypatch.setattr(firefox_source.platform, "firefox_profiles",
                        lambda _f: [("/u/.mozilla/firefox", "work", "b.work")])
    got = src._resolve_profile("/usr/bin/firefox",
                               {"profile_kind": "existing", "existing_profile": "work"})
    assert got == ("/u/.mozilla/firefox", "work")


def test_stop_capture_unknown_session_is_noop(monkeypatch):
    src = make_source(monkeypatch, binaries=[])
    src.stop_capture("nope")  # must not raise
