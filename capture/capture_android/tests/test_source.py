"""AndroidSource control surface with a fake backend (no device/emulator/frida): the
provision-consent flow, package listing, start/stop through the served harness, and
release. The real device path (RealAndroidBackend) is not exercised here."""

from __future__ import annotations

import grpc

from capture_android.source import AndroidSource
from capture_sdk import source as harness
from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.proto import source_pb2_grpc as sp_grpc


class FakeBackend:
    owns_resource = False

    def __init__(self, options=None):
        self.provisioned = 0
        self.provision_action = None
        self.options = options or [("attach", "Use the connected device")]
        self.packages = ["com.a", "com.b"]
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

    def start(self, package, label, params, on_session, stop_event):
        self._n += 1
        self.started.append((package, label, dict(params)))
        on_session(f"android-sess-{self._n}")
        stop_event.wait(timeout=5)  # "run" until stopped

    def release(self):
        self.released += 1


def test_keep_warm():
    assert AndroidSource.keep_warm is True


def test_describe_offers_provision_options_first():
    # No device chosen yet → the provision step, its choices from the backend (attach a
    # running device, or boot an emulator).
    src = AndroidSource("gw", FakeBackend(options=[("attach", "Use device"),
                                                   ("pixel", "Boot emulator: pixel")]))
    d = src.describe({})
    assert d.readiness == ctl.READINESS_PROVISION_REQUIRED
    assert [p.key for p in d.params] == ["provision"]
    assert [c.value for c in d.params[0].choices] == ["attach", "pixel"]


def test_describe_after_consent_offers_frida_and_packages():
    b = FakeBackend()
    src = AndroidSource("gw", b)
    d = src.describe({"provision": "attach"})
    assert d.readiness == ctl.READINESS_READY
    assert [p.key for p in d.params] == ["frida", "package", "url", "duration"]
    # Frida version is a choice, defaulting to the device recommendation.
    assert [c.value for c in d.params[0].choices] == ["16.7.19", "17.15.1"]
    assert d.params[0].default == "16.7.19"
    assert [c.value for c in d.params[1].choices] == ["com.a", "com.b"]
    assert b.provisioned == 1

    src.describe({"provision": "attach"})  # re-describe
    assert b.provisioned == 1  # not re-provisioned — the resource is kept warm


def test_describe_package_is_free_text_when_no_apps_listed():
    b = FakeBackend()
    b.packages = []
    d = AndroidSource("gw", b).describe({"provision": "attach"})
    pkg = next(p for p in d.params if p.key == "package")
    assert pkg.type == ctl.PARAM_TYPE_STRING


def test_start_and_stop_through_the_served_harness():
    b = FakeBackend()
    src = AndroidSource("gw", b)
    server, port = harness.serve(src, "127.0.0.1:0")
    chan = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = sp_grpc.CaptureSourceServiceStub(chan)
    try:
        resp = stub.StartCapture(ctl.StartCaptureRequest(
            label="run", params={"provision": "attach", "package": "com.a"}))
        assert resp.session_id == "android-sess-1"
        assert b.started[0][0] == "com.a"

        st = stub.Status(ctl.StatusRequest())
        assert st.state == ctl.SOURCE_STATE_CAPTURING
        assert list(st.active_sessions) == ["android-sess-1"]

        stub.StopCapture(ctl.StopCaptureRequest(session_id="android-sess-1"))
        assert stub.Status(ctl.StatusRequest()).state == ctl.SOURCE_STATE_READY
        # keep_warm: stopping the capture doesn't release the device.
        assert b.released == 0
    finally:
        chan.close()
        server.stop(None)


def test_release_tears_down_and_resets_provisioning():
    b = FakeBackend()
    src = AndroidSource("gw", b)
    src.describe({"provision": "attach"})
    assert src._provisioned
    src.release()
    assert b.released == 1 and not src._provisioned
