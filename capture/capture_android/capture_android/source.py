"""Android as a CaptureSourceService the gateway dials (ADR-0010).

Android is a *persistent* source: the emulator/device (plus frida-server and the adb
connection) is expensive to bring up and is kept warm across captures, so keep_warm is
True and the resource is only dropped on ReleaseSource. Because listing the installed apps
needs that resource running, Describe returns PROVISION_REQUIRED until the user consents to
bring it up; after that it lists packages.

The emulator/adb/capture operations sit behind AndroidBackend so the control logic here is
testable without a device. RealAndroidBackend wires it to the capture_android modules; that
path needs a real device/emulator and is not exercised in CI.
"""

from __future__ import annotations

import threading
from typing import Mapping, Protocol

from capture_sdk import source
from capture_sdk.proto import control_pb2 as ctl

# Value the "provision" choice carries once the user consents to bring the resource up.
_PROVISION_CONSENT = "start"


class AndroidBackend(Protocol):
    """The device-side operations AndroidSource drives. owns_resource says whether *we*
    booted the emulator (so ReleaseSource may tear it down) or merely attached to one the
    user already had running (which must be left alone)."""

    owns_resource: bool

    def provision(self) -> None:
        """Bring the emulator/device to a capture-ready state (root + frida-server + adb).
        Blocking; may take tens of seconds when it boots an emulator."""

    def list_packages(self) -> list[str]:
        """Installed app package names on the provisioned device."""

    def start(self, package: str, label: str, params: Mapping[str, str],
              on_session, stop_event: threading.Event) -> None:
        """Run one capture of `package` to completion. Calls on_session(session_id) once the
        session is open, and stops when stop_event is set."""

    def release(self) -> None:
        """Drop the warm resource — only what this backend provisioned."""


class AndroidSource(source.CaptureSource):
    """Persistent Android source. keep_warm keeps the emulator up between captures; the
    emulator is provisioned once the user consents, and released explicitly."""

    keep_warm = True

    def __init__(self, gateway: str, backend: AndroidBackend | None = None) -> None:
        super().__init__()
        self._gateway = gateway
        if backend is None:
            from capture_android.androidbackend import RealAndroidBackend
            backend = RealAndroidBackend(gateway)
        self._backend = backend
        self._provisioned = False
        self._captures: dict[str, threading.Event] = {}  # session id -> stop event
        self._caps_lock = threading.Lock()

    def describe(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        # Until the user consents, offer only the provision step (nothing can be listed
        # without the device up) — PROVISION_REQUIRED so the viewer frames it as consent.
        if params.get("provision") != _PROVISION_CONSENT:
            return ctl.SourceDescriptor(
                readiness=ctl.READINESS_PROVISION_REQUIRED,
                message="No Android device is set up yet — this will bring it up (can take ~30s).",
                params=[source.param(
                    "provision", "Set up the device", source.CHOICE, required=True,
                    choices=[source.choice(_PROVISION_CONSENT, "Set up the emulator/device")])])

        # Consented: bring the resource up once (blocking), then list apps.
        if not self._provisioned:
            self.provisioning = True
            try:
                self._backend.provision()
                self._provisioned = True
            finally:
                self.provisioning = False

        packages = self._backend.list_packages()
        pkg = (source.param("package", "App to capture", source.CHOICE, required=True,
                            choices=[source.choice(p) for p in packages])
               if packages else
               source.param("package", "App package", source.STRING, required=True))
        return source.descriptor([
            pkg,
            source.param("url", "Open URL (optional)", source.STRING),
            source.param("duration", "Auto-stop after (seconds)", source.INT),
        ])

    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        package = params.get("package")
        if not package:
            raise ValueError("no app package selected")
        stop = threading.Event()
        holder: dict[str, str] = {}
        opened = threading.Event()

        def on_session(sid: str) -> None:
            holder["sid"] = sid
            opened.set()

        def run() -> None:
            try:
                self._backend.start(package, label or package, params, on_session, stop)
            finally:
                sid = holder.get("sid")
                if sid:
                    with self._caps_lock:
                        self._captures.pop(sid, None)
                    self.session_ended(sid)  # capture ended (duration/stop/error)

        threading.Thread(target=run, daemon=True).start()
        if not opened.wait(timeout=120):
            raise RuntimeError("capture did not start (device not ready?)")
        sid = holder["sid"]
        with self._caps_lock:
            self._captures[sid] = stop
        return sid

    def stop_capture(self, session_id: str) -> None:
        with self._caps_lock:
            stop = self._captures.pop(session_id, None)
        if stop is not None:
            stop.set()  # keep_warm: the capture ends, the emulator stays up

    def release(self) -> None:
        self._backend.release()  # tears down only if it owns the emulator
        self._provisioned = False
