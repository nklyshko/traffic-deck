"""RealAndroidBackend — AndroidSource's device-side operations, wired to the capture_android
modules. This path needs a real device/emulator + frida and is not exercised in CI; it's
imported lazily by AndroidSource so tests can run with a fake backend and never import frida.

v1 attaches to a device/emulator that is already running (so owns_resource is False and
ReleaseSource leaves it alone); booting an AVD non-interactively is a follow-up.
"""

from __future__ import annotations

import threading
from typing import Mapping

from capture_android.adb import AdbClient
from capture_android.capture import run_capture
from capture_android.frida_server import ensure_target_ready


class RealAndroidBackend:
    owns_resource = False  # v1 attaches to a running device; we didn't boot it

    def __init__(self, gateway: str) -> None:
        self._gateway = gateway
        self._adb: AdbClient | None = None

    def provision(self) -> None:
        # Attach to the running device/emulator and make it capture-ready (root +
        # frida-server). Raises if none is connected — surfaced to the viewer as the
        # describe error.
        self._adb = AdbClient()
        ensure_target_ready(self._adb)

    def list_packages(self) -> list[str]:
        assert self._adb is not None, "provision first"
        return self._adb.list_packages()

    def start(self, package: str, label: str, params: Mapping[str, str],
              on_session, stop_event: threading.Event) -> None:
        assert self._adb is not None, "provision first"
        duration = float(params["duration"]) if params.get("duration") else None
        run_capture(
            self._adb, package, gateway=self._gateway, label=label,
            url=params.get("url") or None, duration=duration,
            stop_event=stop_event, on_session=on_session,
            log=lambda m: None)

    def release(self) -> None:
        # We only attached to a running device; teardown follows ownership, so there is
        # nothing of ours to tear down. (Booting our own AVD would tear it down here.)
        self._adb = None
