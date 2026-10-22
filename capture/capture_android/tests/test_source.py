"""The two Android sources with a fake backend (no device/emulator/frida): the provision
flow they share, each one's own form, start/stop through the served harness, and the
release rule that keeps one from tearing the device out from under the other. The real
device path (RealAndroidBackend) is not exercised here."""

from __future__ import annotations

import threading
import time

import grpc

from capture_android.source import AndroidBrowserSource, sources
from capture_sdk import source as harness
from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.proto import source_pb2_grpc as sp_grpc


def describe_provisioned(src, action="attach"):
    """Consent, then poll Describe until the (background) provisioning is done and it goes
    READY — mirroring how the viewer polls."""
    src.describe({"provision": action})  # kicks off provisioning
    for _ in range(400):
        d = src.describe({"provision": action})
        if d.readiness == ctl.READINESS_READY:
            return d
        time.sleep(0.005)
    raise AssertionError("provisioning did not complete")


class FakeBackend:
    owns_resource = False

    def __init__(self, options=None):
        self.provisioned = 0
        self.provision_action = None
        self.options = options or [("attach", "Use the connected device")]
        self.packages = ["com.a", "com.b"]
        self.browsers = ["com.android.chrome"]
        self.started = []      # (package, label, params)
        self.released = 0
        self._n = 0

    def provision_options(self):
        return list(self.options)

    def provision(self, action):
        self.provisioned += 1
        self.provision_action = action

    def frida_versions(self):
        return ["16.7.19", "17.15.1"], "16.7.19"

    def list_packages(self):
        return list(self.packages)

    def list_browsers(self):
        return list(self.browsers)

    def start(self, package, label, params, on_session, stop_event):
        self._n += 1
        self.started.append((package, label, dict(params)))
        on_session(f"android-sess-{self._n}")
        stop_event.wait(timeout=5)  # "run" until stopped

    def release(self):
        self.released += 1


def two_sources(backend=None):
    """The module's sources over one shared device, as `serve` builds them."""
    return sources("gw", backend or FakeBackend())


def test_the_module_serves_two_named_sources():
    # The names are what the gateway registers; the first is the primary (what an unnamed
    # request addresses), so the per-app tool stays the obvious one.
    srcs = two_sources()
    assert list(srcs) == ["android", "android-browser"]
    assert all(s.keep_warm for s in srcs.values())


def test_describe_offers_provision_options_first():
    # No device chosen yet → the provision step, its choices from the backend (attach a
    # running device, or boot an emulator). Both sources ask the same question.
    srcs = two_sources(FakeBackend(options=[("attach", "Use device"),
                                            ("pixel", "Boot emulator: pixel")]))
    for src in srcs.values():
        d = src.describe({})
        assert d.readiness == ctl.READINESS_PROVISION_REQUIRED
        assert [p.key for p in d.params] == ["provision"]
        assert [c.value for c in d.params[0].choices] == ["attach", "pixel"]


def test_app_source_offers_frida_and_packages():
    b = FakeBackend()
    srcs = two_sources(b)
    d = describe_provisioned(srcs["android"])
    assert [p.key for p in d.params] == ["frida", "package", "url", "duration"]
    # Frida version is a choice, defaulting to the device recommendation, which is also
    # labelled "(recommended)" so viewers surface it like the CLI picker (not just preselect).
    assert [c.value for c in d.params[0].choices] == ["16.7.19", "17.15.1"]
    assert d.params[0].default == "16.7.19"
    frida_labels = {c.value: c.label for c in d.params[0].choices}
    assert "(recommended)" in frida_labels["16.7.19"]
    assert "(recommended)" not in frida_labels["17.15.1"]
    assert [c.value for c in d.params[1].choices] == ["com.a", "com.b"]
    assert b.provisioned == 1

    srcs["android"].describe({"provision": "attach"})  # re-describe
    assert b.provisioned == 1  # not re-provisioned — the resource is kept warm


def test_browser_source_offers_browsers_and_no_frida():
    """The browser tool uses no Frida, so it must not ask for a version — asking would imply
    a root requirement that isn't there. Its targets are browsers, not the installed apps."""
    b = FakeBackend()
    b.browsers = ["com.android.chrome", "com.chrome.beta"]
    d = describe_provisioned(two_sources(b)["android-browser"])

    assert [p.key for p in d.params] == ["package", "url", "duration"]
    pkg = d.params[0]
    assert [c.value for c in pkg.choices] == ["com.android.chrome", "com.chrome.beta"]
    assert pkg.default == "com.android.chrome"
    # The viewer is told what a terminating proxy costs, since it is not recoverable later.
    assert "fingerprint" in d.message


def test_one_device_is_provisioned_for_both_sources():
    """The whole reason these share a connection: the emulator is booted once. The second
    source finds it ready rather than booting one of its own."""
    b = FakeBackend()
    srcs = two_sources(b)
    describe_provisioned(srcs["android"])

    d = srcs["android-browser"].describe({"provision": "attach"})
    assert d.readiness == ctl.READINESS_READY  # already up — no second provisioning step
    assert b.provisioned == 1


def test_provisioning_state_is_shared_so_both_report_it():
    class SlowBackend(FakeBackend):
        def __init__(self):
            super().__init__()
            self.gate = threading.Event()

        def provision(self, action):
            self.gate.wait(timeout=5)  # block until released
            super().provision(action)

    b = SlowBackend()
    srcs = two_sources(b)
    d = srcs["android"].describe({"provision": "attach"})
    assert d.readiness == ctl.READINESS_PROVISION_REQUIRED
    assert list(d.params) == []           # nothing to answer — just working
    assert "Setting up" in d.message
    # Status on *either* source reads PROVISIONING: one device is coming up, and the browser
    # source is just as unusable until it has.
    assert srcs["android"].provisioning is True
    assert srcs["android-browser"].provisioning is True

    b.gate.set()
    describe_provisioned(srcs["android"])
    assert srcs["android"].provisioning is False
    assert srcs["android-browser"].provisioning is False


def test_describe_package_is_free_text_when_nothing_is_listed():
    b = FakeBackend()
    b.packages = []
    b.browsers = []
    srcs = two_sources(b)
    for name in ("android", "android-browser"):
        d = describe_provisioned(srcs[name])
        pkg = next(p for p in d.params if p.key == "package")
        assert pkg.type == ctl.PARAM_TYPE_STRING


def test_each_source_tells_the_backend_its_own_method():
    """The user no longer picks a method — the source *is* the method, which is what makes
    these two tools rather than one with a switch."""
    b = FakeBackend()
    srcs = two_sources(b)
    srcs["android"].start_capture("app", {"package": "com.a"})
    srcs["android-browser"].start_capture("web", {"package": "com.android.chrome"})

    methods = [params["method"] for _, _, params in b.started]
    assert methods == ["frida", "proxy"]


def test_start_and_stop_through_the_served_harness():
    """Both sources over one connection, each addressed by name — the gateway's view."""
    b = FakeBackend()
    srcs = two_sources(b)
    server, port = harness.serve(srcs, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    try:
        resp = stub.StartCapture(ctl.StartCaptureRequest(
            source="android-browser", label="run",
            params={"provision": "attach", "package": "com.android.chrome"}))
        assert resp.session_id == "android-sess-1"
        assert b.started[0][0] == "com.android.chrome"
        assert b.started[0][2]["method"] == "proxy"

        # Status is per source: the capture belongs to the browser tool, and the app tool is
        # idle, not busy.
        assert stub.Status(ctl.StatusRequest(source="android-browser")).state == \
            ctl.SOURCE_STATE_CAPTURING
        assert stub.Status(ctl.StatusRequest(source="android")).state == ctl.SOURCE_STATE_READY

        # Stop carries no source name — the session id routes it to the tool that owns it.
        stub.StopCapture(ctl.StopCaptureRequest(session_id="android-sess-1"))
        assert stub.Status(ctl.StatusRequest(source="android-browser")).state == \
            ctl.SOURCE_STATE_READY
        # keep_warm: stopping the capture doesn't release the device.
        assert b.released == 0
    finally:
        chan.close()
        server.stop(None)


def test_an_unknown_source_name_is_refused():
    srcs = two_sources()
    server, port = harness.serve(srcs, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    try:
        try:
            stub.Describe(ctl.DescribeRequest(source="android-ios"))
            raise AssertionError("an unserved source name should be refused")
        except grpc.RpcError as exc:
            assert exc.code() == grpc.StatusCode.NOT_FOUND
            assert "android-browser" in exc.details()  # says what it does serve
    finally:
        chan.close()
        server.stop(None)


def test_stop_capture_waits_for_the_session_to_close():
    """Stop returns only once the capture has finished tearing down (its CloseSession has
    run) — not while a detached capture is still racing to close. This is the fix for
    Android sessions stranded open on Stop / app exit; the same synchronous wait lets the
    served harness' _shutdown finish closing sessions before the source process exits."""
    torn_down = threading.Event()

    class SlowCloseBackend(FakeBackend):
        def start(self, package, label, params, on_session, stop_event):
            self.started.append((package, label, dict(params)))
            on_session("android-sess-1")
            stop_event.wait()   # run until stopped
            time.sleep(0.2)     # simulate teardown + CloseSession after the stop request
            torn_down.set()

    src = two_sources(SlowCloseBackend())["android"]
    sid = src.start_capture("run", {"provision": "attach", "package": "com.a"})
    src._track(sid)  # the harness servicer does this on StartCapture; mirror it here
    assert src._status().state == ctl.SOURCE_STATE_CAPTURING

    t0 = time.monotonic()
    src.stop_capture(sid)
    assert torn_down.is_set(), "stop returned before the capture finished tearing down"
    assert time.monotonic() - t0 >= 0.2
    # The capture thread's teardown ran session_ended, so Status is back to READY.
    assert src._status().state == ctl.SOURCE_STATE_READY


def test_release_tears_down_the_shared_device_once():
    b = FakeBackend()
    srcs = two_sources(b)
    describe_provisioned(srcs["android"])

    srcs["android"].release()
    assert b.released == 1
    # Both sources see the device as gone, so either can provision it afresh.
    assert srcs["android-browser"].describe({"provision": "attach"}).readiness == \
        ctl.READINESS_PROVISION_REQUIRED


def test_releasing_one_source_leaves_a_capture_on_the_other_alone():
    """The failure this prevents: stopping a browser capture (or the gateway releasing that
    source) would otherwise shut down the emulator an app capture is still recording on."""
    b = FakeBackend()
    srcs = two_sources(b)
    describe_provisioned(srcs["android"])

    sid = srcs["android"].start_capture("app", {"package": "com.a"})
    srcs["android"]._track(sid)

    srcs["android-browser"].release()
    assert b.released == 0, "the device was released under a running capture"

    srcs["android"].stop_capture(sid)
    srcs["android"].session_ended(sid)
    # Now nothing is capturing, so the last one out does tear it down.
    srcs["android-browser"].release()
    assert b.released == 1


def test_browser_source_is_the_one_that_drives_the_proxy():
    # Guards the wiring, not the behaviour: the class decides the method, so a mix-up here
    # would silently run the wrong capture for the tool the user picked.
    assert AndroidBrowserSource.method == "proxy"
