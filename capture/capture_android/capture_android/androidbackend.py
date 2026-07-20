"""RealAndroidBackend — AndroidSource's device-side operations.

This process never imports frida: provision/list use adb (and the SDK's emulator tools)
only, and each capture runs as a subprocess under the frida version chosen for the device
(`uv run --with frida==<ver> python -m capture_android.headless …`), exactly as the
interactive CLI does — client and frida-server versions must match, and frida 17 can't
spawn on Android ≤ 11, so the version has to be per-device.

Provisioning attaches to a running device, or boots/creates an emulator (the same
emulator.Sdk the CLI uses, which is tested there). When we boot an emulator we own it, so
ReleaseSource stops it; a device we merely attached to is left alone. This whole path needs
a real device or emulator and is not exercised in CI.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from pathlib import Path
from typing import Mapping

from capture_android import frida_versions
from capture_android.adb import AdbClient
from capture_android.emulator import DEFAULT_AVD, Sdk, parse_devices

_PROJECT = str(Path(__file__).resolve().parents[1])  # the capture_android project dir
_CREATE = "__create__"  # provision-choice value: create + boot a new emulator


class RealAndroidBackend:
    def __init__(self, gateway: str) -> None:
        self._gateway = gateway
        self._serial: str | None = None
        self._release = ""  # Android version, for the frida recommendation
        self.owns_resource = False  # set True when we boot an emulator ourselves
        self._sdk_inst: Sdk | None = None

    def _sdk(self) -> Sdk:
        if self._sdk_inst is None:
            self._sdk_inst = Sdk()  # locates the Android SDK ($ANDROID_HOME / ~/Android/Sdk)
        return self._sdk_inst

    def _running_serials(self) -> list[str]:
        # adb only (no full SDK needed): serials in the "device" state.
        adb = AdbClient().adb
        out = subprocess.run([adb, "devices", "-l"], text=True, capture_output=True).stdout
        return [d.serial for d in parse_devices(out) if d.state == "device"]

    def provision_options(self) -> list[tuple[str, str]]:
        running = self._running_serials()
        if running:
            return [("attach", f"Use the connected device ({running[0]})")]
        # Nothing connected → offer the emulators to boot (needs the SDK).
        avds = self._sdk().list_avds()
        opts = [(a, f"Boot emulator: {a}") for a in avds]
        opts.append((_CREATE, "Create + boot a new emulator (~1GB on first run)"))
        return opts

    def provision(self, action: str) -> None:
        if action == "attach":
            running = self._running_serials()
            if not running:
                raise RuntimeError("no connected device to attach to")
            self._serial = running[0]
            self.owns_resource = False
        else:
            sdk = self._sdk()
            if action == _CREATE:
                if not sdk.system_image_installed():
                    sdk.install_system_image(log=lambda _m: None)
                sdk.create_avd(log=lambda _m: None)
                avd = DEFAULT_AVD
            else:
                avd = action
            sdk.boot(avd, headless=True)
            self._serial = sdk.wait_for_boot()
            self.owns_resource = True  # we booted it → ReleaseSource stops it
        self._release = AdbClient(serial=self._serial).shell(
            "getprop", "ro.build.version.release").strip()

    def frida_versions(self) -> tuple[list[str], str]:
        """(offered versions, recommended default) for the provisioned device."""
        rec = frida_versions.recommended(self._release)
        return frida_versions.choices(rec), rec

    def list_packages(self) -> list[str]:
        return AdbClient(serial=self._serial).list_packages()

    def start(self, package: str, label: str, params: Mapping[str, str],
              on_session, stop_event: threading.Event) -> None:
        fver = params.get("frida") or self.frida_versions()[1]
        cmd = ["uv", "run", "--project", _PROJECT, "--with", f"frida=={fver}",
               "python", "-m", "capture_android.headless",
               "--package", package, "--gateway", self._gateway]
        if self._serial:
            cmd += ["--serial", self._serial]
        if label:
            cmd += ["--label", label]
        if params.get("url"):
            cmd += ["--url", params["url"]]
        if params.get("duration"):
            cmd += ["--duration", params["duration"]]

        # Own process group so a stop signal reaches the capture even through `uv run`.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, start_new_session=True)
        try:
            self._relay_session(proc, on_session)
            # Run until the capture exits on its own (duration) or a stop is requested.
            while proc.poll() is None and not stop_event.wait(0.5):
                pass
        finally:
            self._reap(proc)  # signal + wait for a graceful close, then escalate

    @staticmethod
    def _relay_session(proc, on_session) -> None:
        """Read the subprocess's stdout until it prints its session id (SESSION <id>), then
        keep draining so its pipe never fills."""
        for line in proc.stdout:
            if line.startswith("SESSION "):
                on_session(line[len("SESSION "):].strip())
                break
        threading.Thread(target=lambda: [None for _ in proc.stdout], daemon=True).start()

    @staticmethod
    def _reap(proc) -> None:
        """Bring the (detached) capture process down and wait for it to finish, so its
        session is closed on the gateway before we return. A single SIGINT asks the headless
        run to wind down gracefully — stop tcpdump/frida, drain the upload, CloseSession (see
        capture_sdk.shutdown.GracefulInterrupt) — then we wait. A *second* SIGINT would abort
        that close, so we never send one: if the graceful window overruns we escalate to
        SIGTERM, then SIGKILL, so a wedged capture can't hang a Stop or the gateway shutdown."""
        if proc.poll() is not None:
            return
        for sig, grace in ((signal.SIGINT, 15.0), (signal.SIGTERM, 3.0)):
            try:
                os.killpg(os.getpgid(proc.pid), sig)
                proc.wait(timeout=grace)
                return
            except ProcessLookupError:
                return  # already gone
            except subprocess.TimeoutExpired:
                continue
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=2)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

    def release(self) -> None:
        # Teardown follows ownership: stop only an emulator we booted; a device the user had
        # running is left alone.
        if self.owns_resource and self._serial:
            try:
                self._sdk().stop_emulator(self._serial)
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass
        self._serial = None
        self.owns_resource = False
