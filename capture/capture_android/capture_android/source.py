"""Android as CaptureSourceServices the gateway dials (ADR-0010).

This module serves **two** sources over one connection, because one device supports two
unrelated capture techniques and a single form cannot honestly describe both:

  * ``android`` — per-app packets + Frida TLS keylog. Any app on the system TLS stack,
    needs root, keeps the app's own fingerprint and the conn/stream columns.
  * ``android-browser`` — a Chromium browser through mitmproxy. Needs no root, and is the
    only thing that decrypts Chrome at all (see chromeproxy for why).

They are two *tools*, not two settings of one: the targets differ (any app vs a browser),
the prerequisites differ (root vs none) and the recorded session differs (pcap + key.log vs
pushed flows). What they share is the expensive part — the emulator/device — so they share
one _Device and it is booted once and released once, however many of them are in use.

Android is a *persistent* source: the device is kept warm across captures (keep_warm), and
because listing the installed apps needs it running, Describe returns PROVISION_REQUIRED
until the user consents to bring it up.

The emulator/adb/capture operations sit behind AndroidBackend so the control logic here is
testable without a device. RealAndroidBackend wires it to the capture_android modules; that
path needs a real device/emulator and is not exercised in CI.
"""

from __future__ import annotations

import abc
import threading
from typing import Mapping, Protocol

from capture_sdk import source
from capture_sdk.proto import control_pb2 as ctl

# The one provision action that boots nothing: a device the user already has running is
# attached to as it is. Shared with RealAndroidBackend, which branches on the same value —
# so the window option is offered only when there is actually something to boot.
_ATTACH = "attach"


class AndroidBackend(Protocol):
    """The device-side operations the Android sources drive. owns_resource says whether *we*
    booted the emulator (so ReleaseSource may tear it down) or merely attached to one the
    user already had running (which must be left alone)."""

    owns_resource: bool

    def provision_options(self) -> list[tuple[str, str]]:
        """(value, label) choices for the provision step, from what's connected: attach to a
        running device, or boot/create an emulator. Cheap (no boot) — probes device state."""

    def provision(self, action: str, *, show_window: bool = False) -> None:
        """Carry out the chosen provision action — attach to the running device, boot an AVD
        by name, or create+boot one. Blocking; booting can take tens of seconds.
        show_window boots the emulator with a window; ignored when attaching to a device the
        user already has running, which is theirs as it is."""

    def frida_versions(self) -> tuple[list[str], str]:
        """(offered frida versions, recommended default) for the connected device — frida
        must match the device's Android release, so the user picks per device."""

    def list_packages(self) -> list[str]:
        """Installed app package names on the provisioned device."""

    def list_browsers(self) -> list[str]:
        """Installed Chromium-browser packages — the targets the browser source can capture.
        Separate from list_packages because a preinstalled browser is a *system* app, which
        the app listing (third-party only) leaves out."""

    def start(self, package: str, label: str, params: Mapping[str, str],
              on_session, stop_event: threading.Event) -> None:
        """Run one capture of `package` to completion. Calls on_session(session_id) once the
        session is open, and stops when stop_event is set."""

    def release(self) -> None:
        """Drop the warm resource — only what this backend provisioned."""


class _Device:
    """The device both sources capture on: provisioned once, released once.

    Provisioning is shared state rather than per-source because there is one emulator. The
    source that asks first boots it; the other one finds it ready. Release is the same bargain
    in reverse — the last source to let go is the one that tears it down, so stopping a
    browser capture cannot pull the emulator out from under a running app capture.
    """

    def __init__(self, backend: AndroidBackend) -> None:
        self.backend = backend
        self.provisioned = False
        #: True while the device is coming up, so both sources' Status read PROVISIONING.
        self.provisioning = False
        self._lock = threading.Lock()
        self._started = False
        self._error: str | None = None
        self._sources: list[source.CaptureSource] = []

    def register(self, src: source.CaptureSource) -> None:
        self._sources.append(src)

    def choice_descriptor(self) -> ctl.SourceDescriptor:
        """The provision step: nothing can be listed before the device is up, so this comes
        back as PROVISION_REQUIRED and the viewer frames it as consent. The choices depend on
        what's connected (attach vs boot an AVD)."""
        options = self.backend.provision_options()
        params = []
        if any(value != _ATTACH for value, _ in options):
            # Offered *before* the device choice, and that order is load-bearing: a viewer
            # fills one param per re-describe, and answering `provision` is what starts the
            # boot — anything asked after it would arrive too late to affect how it boots.
            params.append(source.param("show_window", "Show the emulator window", source.BOOL))
        params.append(source.param(
            "provision", "Device / emulator", source.CHOICE, required=True,
            choices=[source.choice(v, label) for v, label in options]))
        return ctl.SourceDescriptor(
            readiness=ctl.READINESS_PROVISION_REQUIRED,
            message="Choose the device or emulator to capture on (booting one can take ~30s).",
            params=params)

    def start_provisioning(self, action: str, *, show_window: bool = False) -> ctl.SourceDescriptor:
        """Kick off provisioning in the background (once, for all sources) and report
        progress. Returns a PROVISION_REQUIRED descriptor with a message and no params, which
        the viewer renders as "working…" and polls until it goes READY — so the viewer never
        blocks on a ~30s boot."""
        with self._lock:
            if self._error is not None:
                err, self._error = self._error, None
                self._started = False  # allow a fresh attempt to retry
                raise RuntimeError(err)  # surfaced once; the next Describe restarts it
            if not self._started:
                self._started = True
                self.provisioning = True
                threading.Thread(target=self._run, args=(action, show_window),
                                 daemon=True).start()
        return ctl.SourceDescriptor(
            readiness=ctl.READINESS_PROVISION_REQUIRED,
            message="Setting up the device — this can take ~30s…")

    def _run(self, action: str, show_window: bool) -> None:
        try:
            self.backend.provision(action, show_window=show_window)
            self.provisioned = True
        except Exception as exc:  # noqa: BLE001 — reported to the viewer via Describe
            self._error = str(exc)
        finally:
            self.provisioning = False

    def busy_apart_from(self, src: source.CaptureSource) -> bool:
        """Whether any *other* source on this device still has a capture running."""
        return any(s._status().active_sessions for s in self._sources if s is not src)

    def release(self, src: source.CaptureSource) -> None:
        if self.busy_apart_from(src):
            return  # someone else is still capturing on it — not ours to take down
        self.backend.release()  # tears down only if it owns the emulator
        self.provisioned = False
        with self._lock:
            self._started = False  # a later capture can provision afresh


class _AndroidSource(source.CaptureSource):
    """What the two Android sources have in common: the shared device, the provision gate,
    and the capture lifecycle. Subclasses differ only in the form they offer once the device
    is up, and in which capture method the backend then runs."""

    keep_warm = True

    #: The backend's capture method for this source — what `headless --method` takes.
    method: str = ""

    def __init__(self, gateway: str, device: _Device) -> None:
        # Before super(): `provisioning` is a property backed by the device, and
        # CaptureSource.__init__ assigns to it.
        self._device = device
        super().__init__()
        self._gateway = gateway
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
        device.register(self)

    @property
    def provisioning(self) -> bool:
        return self._device.provisioning

    @provisioning.setter
    def provisioning(self, value: bool) -> None:
        self._device.provisioning = value

    @property
    def _backend(self) -> AndroidBackend:
        return self._device.backend

    def describe(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        if not params.get("provision"):
            return self._device.choice_descriptor()
        if not self._device.provisioned:
            return self._device.start_provisioning(
                params["provision"], show_window=params.get("show_window") == "true")
        return self._options(params)

    @abc.abstractmethod
    def _options(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        """The capture options this source offers, the device being up."""

    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        package = params.get("package")
        if not package:
            raise ValueError("no app package selected")
        # The source *is* the method, so the backend is told which one rather than the user
        # choosing: that is the whole point of these being two tools.
        params = {**params, "method": self.method}
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
        self._device.release(self)


class AndroidAppSource(_AndroidSource):
    """Per-app packets + Frida TLS keylog: any app on the system TLS stack, needs root."""

    method = "frida"

    def _options(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        versions, recommended = self._backend.frida_versions()
        packages = self._backend.list_packages()
        pkg = (source.param("package", "App to capture", source.CHOICE, required=True,
                            choices=[source.choice(p) for p in packages])
               if packages else
               source.param("package", "App package", source.STRING, required=True))
        return source.descriptor([
            # Frida must match the device's Android release; the recommended one is the
            # default (preselected) and labelled "(recommended)" so every viewer surfaces it
            # the way the CLI picker does — the descriptor is the single option model.
            source.param("frida", "Frida version", source.CHOICE, required=True,
                         default=params.get("frida") or recommended,
                         choices=[source.choice(v, f"{v}  (recommended)" if v == recommended else v)
                                  for v in versions]),
            pkg,
            source.param("url", "Open URL (optional)", source.STRING),
            source.param("duration", "Auto-stop after (seconds)", source.INT),
        ])


class AndroidBrowserSource(_AndroidSource):
    """A Chromium browser through mitmproxy: no root, no Frida version to pick, and the
    targets are browsers rather than the installed-app list."""

    method = "proxy"

    def _options(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        browsers = self._backend.list_browsers()
        pkg = (source.param("package", "Browser to capture", source.CHOICE, required=True,
                            default=params.get("package") or browsers[0],
                            choices=[source.choice(p) for p in browsers])
               if browsers else
               source.param("package", "Browser package", source.STRING, required=True))
        return source.descriptor([
            pkg,
            source.param("url", "Open URL (optional)", source.STRING),
            source.param("duration", "Auto-stop after (seconds)", source.INT),
        ], message="mitmproxy terminates TLS, so bodies are readable but the browser's own "
                   "fingerprint and the conn/stream columns are lost. The browser is "
                   "restarted, with certificate checks off, for the capture.")


def sources(gateway: str, backend: AndroidBackend | None = None) -> dict[str, _AndroidSource]:
    """The sources this module serves, keyed by the name the gateway registered. One device,
    two tools. Order matters: the first is the primary, which is what an unnamed request
    (a single-source gateway) addresses."""
    if backend is None:
        from capture_android.androidbackend import RealAndroidBackend
        backend = RealAndroidBackend(gateway)
    device = _Device(backend)
    return {
        "android": AndroidAppSource(gateway, device),
        "android-browser": AndroidBrowserSource(gateway, device),
    }
