"""RealAndroidBackend — AndroidSource's device-side operations.

This process never imports frida: provision/list use adb only, and each capture runs as a
subprocess under the frida version chosen for the device (`uv run --with frida==<ver>
python -m capture_android.headless …`), exactly as the interactive CLI does — client and
frida-server versions must match, and frida 17 can't spawn on Android ≤ 11, so the version
has to be per-device. The device path needs real hardware and isn't exercised in CI.

v1 attaches to a device/emulator that is already running (owns_resource is False, so
ReleaseSource leaves it alone); booting an AVD non-interactively is a follow-up.
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

_PROJECT = str(Path(__file__).resolve().parents[1])  # the capture_android project dir


class RealAndroidBackend:
    owns_resource = False  # v1 attaches to a running device; we didn't boot it

    def __init__(self, gateway: str) -> None:
        self._gateway = gateway
        self._serial: str | None = None
        self._release = ""  # Android version, for the frida recommendation

    def provision(self) -> None:
        # adb only: attach to the running device and read its Android release (used to
        # recommend a frida version). frida-server is set up per capture, under the chosen
        # version. Raises if no device is connected — surfaced as the describe error.
        adb = AdbClient()
        self._serial = adb.serial
        self._release = adb.shell("getprop", "ro.build.version.release").strip()

    def frida_versions(self) -> tuple[list[str], str]:
        """(offered versions, recommended default) for the connected device."""
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

        # Own process group so a stop (SIGINT) reaches the capture even through `uv run`.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, start_new_session=True)
        try:
            self._relay_session(proc, on_session)
            self._await_stop(proc, stop_event)
        finally:
            if proc.poll() is None:
                proc.wait(timeout=30)

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
    def _await_stop(proc, stop_event: threading.Event) -> None:
        """Wait until the capture exits on its own (duration) or a stop is requested, then
        SIGINT the group so run_capture finalizes gracefully (closes its session)."""
        while proc.poll() is None:
            if stop_event.wait(0.5):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                except ProcessLookupError:
                    pass
                return

    def release(self) -> None:
        # We only attached to a running device; teardown follows ownership, so there is
        # nothing of ours to tear down.
        self._serial = None
