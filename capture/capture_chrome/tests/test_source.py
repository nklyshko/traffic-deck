"""ChromeSource control surface: Describe's discovery + cascade, and start/stop wiring
against a fake capture (no real browser/dumpcap)."""

from __future__ import annotations

import threading

import grpc

from capture_chrome import source as chrome_source
from capture_chrome.source import ChromeSource
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
    monkeypatch.setattr(chrome_source.platform, "chrome_binaries", lambda: list(binaries))
    src = ChromeSource("127.0.0.1:8080")
    src._store = FakeStore(remembered)
    return src


def _keys(descriptor):
    return [p.key for p in descriptor.params]


def test_describe_offers_kind_then_drills_in_by_redescribe(monkeypatch):
    src = make_source(monkeypatch, binaries=["/usr/bin/google-chrome"])
    monkeypatch.setattr(chrome_source.platform, "chrome_profiles",
                        lambda _c: [("/u/dd", "Default", "Personal"), ("/u/dd", "Profile 2", "Work")])
    monkeypatch.setattr(chrome_source.profiles, "saved_profiles", lambda _c: ["research"])

    # Top level: binary + profile_kind (+ the capture opts). No which-one field yet — that's
    # the single-mechanism point: nothing shown before its kind is picked.
    d0 = src.describe({})
    assert _keys(d0) == ["chrome", "profile_kind", "incognito", "url", "duration"]
    kind_values = [c.value for c in d0.params[1].choices]
    assert kind_values == ["existing", "default", "temp", "custom"]  # existing offered: profiles exist

    # Pick "existing" → re-describe grows the which-existing param.
    d1 = src.describe({"profile_kind": "existing"})
    assert _keys(d1) == ["chrome", "profile_kind", "existing_profile", "incognito", "url", "duration"]
    assert [c.value for c in d1.params[2].choices] == ["Default", "Profile 2"]

    # Pick "custom" → the saved-profile param, ending in a "new" option.
    d2 = src.describe({"profile_kind": "custom"})
    assert _keys(d2) == ["chrome", "profile_kind", "saved_profile", "incognito", "url", "duration"]
    assert [c.value for c in d2.params[2].choices] == ["research", "__new__"]

    # Pick "custom" + new → the name field appears (and only then).
    d3 = src.describe({"profile_kind": "custom", "saved_profile": "__new__"})
    assert _keys(d3) == ["chrome", "profile_kind", "saved_profile", "new_profile_name", "incognito", "url", "duration"]

    # default/temp are terminal — no extra field.
    assert _keys(src.describe({"profile_kind": "temp"})) == ["chrome", "profile_kind", "incognito", "url", "duration"]


def test_describe_hides_existing_kind_when_no_profiles(monkeypatch):
    src = make_source(monkeypatch, binaries=["/usr/bin/google-chrome"])
    monkeypatch.setattr(chrome_source.platform, "chrome_profiles", lambda _c: [])
    kinds = [c.value for c in src.describe({}).params[1].choices]
    assert kinds == ["default", "temp", "custom"]  # no "existing"


def test_describe_remembers_default_binary(monkeypatch):
    src = make_source(monkeypatch, binaries=["/a/chrome", "/b/chromium"],
                      remembered={"chrome": "/b/chromium"})
    monkeypatch.setattr(chrome_source.platform, "chrome_profiles", lambda _c: [])
    assert src.describe({}).params[0].default == "/b/chromium"


def test_describe_path_param_when_no_binaries(monkeypatch):
    src = make_source(monkeypatch, binaries=[])
    d = src.describe({})
    assert d.params[0].key == "chrome"
    assert d.params[0].type == ctl.PARAM_TYPE_PATH


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
    monkeypatch.setattr(chrome_source.profiles, "temp_profile", lambda _c: "/tmp/prof")

    server, port = harness.serve(src, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    try:
        resp = stub.StartCapture(ctl.StartCaptureRequest(
            label="run1", params={"chrome": "/usr/bin/google-chrome", "profile_kind": "temp"}))
        assert resp.session_id == "sess-1"
        cap = FakeCapture.instances[0]
        assert cap.kw["label"] == "run1" and cap.kw["profile"] == "/tmp/prof"
        assert src._store.saved == {"chrome": "/usr/bin/google-chrome", "profile_kind": "temp"}

        st = stub.Status(ctl.StatusRequest())
        assert st.state == ctl.SOURCE_STATE_CAPTURING
        assert list(st.active_sessions) == ["sess-1"]

        stub.StopCapture(ctl.StopCaptureRequest(session_id="sess-1"))
        assert cap.stopped
        assert stub.Status(ctl.StatusRequest()).state == ctl.SOURCE_STATE_READY
    finally:
        chan.close()
        server.stop(None)


def test_stop_capture_unknown_session_is_noop(monkeypatch):
    src = make_source(monkeypatch, binaries=[])
    src.stop_capture("nope")  # must not raise


def test_incognito_rides_from_the_form_to_the_launch(monkeypatch):
    """The whole path: the answered param reaches the runner, and the runner puts the flag on
    Chrome's argv. The profile flags stay untouched — incognito says what is written back,
    the profile says which Chrome state is launched against."""
    FakeCapture.instances.clear()
    src = make_source(monkeypatch, binaries=["/usr/bin/google-chrome"])
    monkeypatch.setattr(chrome_source, "ChromeCapture", FakeCapture)
    monkeypatch.setattr(chrome_source.profiles, "temp_profile", lambda _c: "/tmp/prof")

    src.start_capture("run", {"chrome": "/usr/bin/google-chrome", "profile_kind": "temp",
                              "incognito": "true"})
    assert FakeCapture.instances[0].kw["incognito"] is True
    # Anything other than the wizard's "true" is off — an unanswered BOOL arrives as "".
    for answer in ({}, {"incognito": ""}):
        FakeCapture.instances.clear()
        src.start_capture("run", {"chrome": "/usr/bin/google-chrome", "profile_kind": "temp",
                                  **answer})
        assert FakeCapture.instances[0].kw["incognito"] is False


def test_launch_command_carries_incognito(monkeypatch, tmp_path):
    from capture_chrome.capture import ChromeCapture

    def cap(**kw):
        # A real ChromeCapture, but nothing is started: only its argv is under test.
        return ChromeCapture(gateway="127.0.0.1:1", label="t", chrome="/usr/bin/google-chrome",
                             profile=str(tmp_path / "prof"), **kw)

    argv = cap(incognito=True).launch_command("/tmp/key.log")
    assert "--incognito" in argv
    assert f"--user-data-dir={tmp_path / 'prof'}" in argv  # profile flags unaffected
    assert "--incognito" not in cap().launch_command("/tmp/key.log")


def test_open_metadata_records_the_capture_options(tmp_path):
    """What the session says about how it was produced. Keys are browser.* rather than
    chrome.*: a Firefox session reports the same ones, so the two can be compared."""
    from capture_chrome.capture import ChromeCapture

    md = ChromeCapture(gateway="127.0.0.1:1", label="t", chrome="/usr/bin/google-chrome",
                       profile=(str(tmp_path), "Profile 1"), url="https://example.com",
                       incognito=True, duration=30, extra_args=["--", "--lang=de"]
                       ).open_metadata()
    assert md == {
        "capture.duration_s": "30",
        "browser.binary": "/usr/bin/google-chrome",
        "browser.profile": f"{tmp_path} [Profile 1]",
        "browser.url": "https://example.com",
        "browser.extra_args": "--lang=de",  # the bare -- separator is not an option
        "browser.incognito": "true",
    }

    # Unset options are left out rather than reported empty — except incognito, where the
    # absence of a key could not be told from a session recorded before it existed.
    plain = ChromeCapture(gateway="127.0.0.1:1", label="t", chrome="/usr/bin/chromium",
                          profile=str(tmp_path)).open_metadata()
    assert plain == {"browser.binary": "/usr/bin/chromium",
                     "browser.profile": str(tmp_path),
                     "browser.incognito": "false"}
