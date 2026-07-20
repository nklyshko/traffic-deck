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


class AndroidBackend(Protocol):
    """The device-side operations AndroidSource drives. owns_resource says whether *we*
    booted the emulator (so ReleaseSource may tear it down) or merely attached to one the
    user already had running (which must be left alone)."""

    owns_resource: bool

    def provision_options(self) -> list[tuple[str, str]]:
        """(value, label) choices for the provision step, from what's connected: attach to a
        running device, or boot/create an emulator. Cheap (no boot) — probes device state."""

    def provision(self, action: str) -> None:
        """Carry out the chosen provision action — attach to the running device, boot an AVD
        by name, or create+boot one. Blocking; booting can take tens of seconds."""

    def frida_versions(self) -> tuple[list[str], str]:
        """(offered frida versions, recommended default) for the connected device — frida
        must match the device's Android release, so the user picks per device."""

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
        # session id -> (stop, closed): set `stop` to ask the capture to wind down; `closed`
        # is set by the capture thread once teardown + CloseSession has finished, so a stop is
        # synchronous (the caller waits for the session to actually close).
        self._captures: dict[str, tuple[threading.Event, threading.Event]] = {}
        self._caps_lock = threading.Lock()
        # How long stop_capture waits for the capture to finish closing its session before
        # giving up. Comfortably covers the headless teardown (upload drain + CloseSession);
        # the gateway's own shutdown grace is set larger still, so a viewer-driven quit doesn't
        # SIGKILL a source mid-close. See gateway sourcemgr.sourceShutdownGrace.
        self._stop_timeout = 25.0
        # Provisioning runs in the background so Describe never blocks the viewer on a ~30s
        # emulator boot; the viewer polls Describe and shows progress.
        self._provision_lock = threading.Lock()
        self._provision_started = False
        self._provision_error: str | None = None

    def describe(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        # Until the user picks a device/emulator, offer only the provision step (nothing can
        # be listed without the device up) — PROVISION_REQUIRED so the viewer frames it as
        # consent. The choices depend on what's connected (attach vs boot an AVD).
        if not params.get("provision"):
            options = self._backend.provision_options()
            return ctl.SourceDescriptor(
                readiness=ctl.READINESS_PROVISION_REQUIRED,
                message="Choose the device or emulator to capture on (booting one can take ~30s).",
                params=[source.param(
                    "provision", "Device / emulator", source.CHOICE, required=True,
                    choices=[source.choice(v, label) for v, label in options])])

        # Chosen: provision in the background (may boot an emulator) and report progress —
        # Describe returns at once so the viewer stays responsive.
        if not self._provisioned:
            return self._provisioning_descriptor(params["provision"])

        versions, recommended = self._backend.frida_versions()
        packages = self._backend.list_packages()
        pkg = (source.param("package", "App to capture", source.CHOICE, required=True,
                            choices=[source.choice(p) for p in packages])
               if packages else
               source.param("package", "App package", source.STRING, required=True))
        return source.descriptor([
            # Frida must match the device's Android release; the recommended one is default,
            # picked interactively like the CLI.
            source.param("frida", "Frida version", source.CHOICE, required=True,
                         default=params.get("frida") or recommended,
                         choices=[source.choice(v) for v in versions]),
            pkg,
            source.param("url", "Open URL (optional)", source.STRING),
            source.param("duration", "Auto-stop after (seconds)", source.INT),
        ])

    def _provisioning_descriptor(self, action: str) -> ctl.SourceDescriptor:
        """Kick off provisioning in the background (once) and report progress. Returns a
        PROVISION_REQUIRED descriptor with a message and no params, which the viewer renders
        as "working…" and polls until it goes READY — so the viewer never blocks on the boot."""
        with self._provision_lock:
            if self._provision_error is not None:
                err, self._provision_error = self._provision_error, None
                self._provision_started = False  # allow a fresh attempt to retry
                raise RuntimeError(err)          # surfaced once; the next Describe restarts it
            if not self._provision_started:
                self._provision_started = True
                self.provisioning = True
                threading.Thread(target=self._run_provision, args=(action,), daemon=True).start()
        return ctl.SourceDescriptor(
            readiness=ctl.READINESS_PROVISION_REQUIRED,
            message="Setting up the device — this can take ~30s…")

    def _run_provision(self, action: str) -> None:
        try:
            self._backend.provision(action)
            self._provisioned = True
        except Exception as exc:  # noqa: BLE001 — reported to the viewer via Describe
            self._provision_error = str(exc)
        finally:
            self.provisioning = False

    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        package = params.get("package")
        if not package:
            raise ValueError("no app package selected")
        stop = threading.Event()
        closed = threading.Event()  # set once the capture has fully torn down + closed
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
                closed.set()  # unblock a stop_capture / shutdown waiting on the close

        threading.Thread(target=run, daemon=True).start()
        if not opened.wait(timeout=120):
            stop.set()  # never opened — make sure the run thread unwinds
            raise RuntimeError("capture did not start (device not ready?)")
        sid = holder["sid"]
        with self._caps_lock:
            self._captures[sid] = (stop, closed)
        return sid

    def stop_capture(self, session_id: str) -> None:
        with self._caps_lock:
            entry = self._captures.pop(session_id, None)
        if entry is None:
            return
        stop, closed = entry
        stop.set()  # keep_warm: the capture ends, the emulator stays up
        # Wait for the capture to actually finish closing its gateway session, so a
        # viewer's Stop (and shutdown's _shutdown) returns only once the session is closed —
        # not while the detached headless is still racing to CloseSession. Bounded, since the
        # backend escalates SIGINT→SIGTERM→SIGKILL if the capture won't wind down.
        if not closed.wait(timeout=self._stop_timeout):
            pass  # gave up waiting; the backend's escalation still tears the process down

    def release(self) -> None:
        self._backend.release()  # tears down only if it owns the emulator
        self._provisioned = False
        with self._provision_lock:
            self._provision_started = False  # a later capture can provision afresh
