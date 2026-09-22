"""The Chrome capture runner, shared by the interactive CLI and serve mode.

`ChromeCapture` is the SDK's dumpcap + `SSLKEYLOGFILE` engine
([KeylogCapture][capture_sdk.livecapture.KeylogCapture]) with Chrome's launch on top: the
key-log flag, the profile flags, and any extra Chrome arguments. Everything else — the
session, the pcap/keylog streaming, and teardown — is the shared engine.
"""

from __future__ import annotations

import os
import subprocess

from capture_chrome import platform, profiles
from capture_sdk import snap
from capture_sdk.browser import BUILTIN_PROFILE, profile_desc  # noqa: F401 — re-exported
from capture_sdk.livecapture import KeylogCapture


class AlreadyRunning(RuntimeError):
    """Chrome is already running on the profile we were asked to capture, so launching it
    would hand off to that instance and record nothing. Carries an actionable message."""


class ChromeCapture(KeylogCapture):
    """One live Chrome capture. `start` opens the session and launches everything (returns
    the session id, non-blocking); `wait` blocks until Chrome closes / duration elapses /
    stop is requested; `stop` tears down and closes the session (idempotent)."""

    name = "chrome"

    def __init__(self, *, gateway: str, label: str, chrome: str, profile,
                 iface: str | None = None, dumpcap: str | None = None,
                 capture_filter: str = "", url: str | None = None,
                 duration: float | None = None, extra_args=()) -> None:
        # A snap-confined Chrome has a private /tmp, so its keylog has to go under the
        # snap's own writable area or the TLS keys never reach us.
        super().__init__(gateway=gateway, label=label, iface=iface, dumpcap=dumpcap,
                         capture_filter=capture_filter, duration=duration,
                         keylog_dir=snap.writable_base(chrome))
        self.chrome = chrome
        self.profile = profile
        self.url = url
        self.extra_args = list(extra_args)

    def start(self) -> str:
        # Chrome is a singleton per user-data-dir. If one is already running on the profile
        # we're about to capture, our launch just hands the URL to it and exits — no TLS
        # keys, and the capture tears down the moment that handoff process quits. Refuse
        # before opening a gateway session, so a bad run leaves no empty session behind.
        udd = profiles.user_data_dir(self.chrome, self.profile)
        if udd and (pid := platform.running_instance(udd)):
            name = os.path.basename(self.chrome)
            raise AlreadyRunning(
                f"{name} is already running on this profile (pid {pid}) — a second launch "
                f"hands off to it and logs no TLS keys. Quit it fully (Cmd+Q on macOS; "
                f"closing the windows is not enough) and retry, or capture with a "
                f"temporary profile.")
        return super().start()

    def launch_command(self, keylog: str) -> list[str]:
        """The Chrome argv for this capture: the key-log flag, the profile flags, the URL.
        Split from `launch` so a variant that spawns Chrome differently — the macOS pktap
        source, which runs as root and must drop to the invoking user — reuses it."""
        cmd = [
            self.chrome,
            f"--ssl-key-log-file={keylog}",
            "--no-first-run",
            "--no-default-browser-check",
            *[a for a in self.extra_args if a != "--"],
        ]
        # Pin a user-data-dir only for temp/explicit/persistent profiles; for the browser
        # default we pass nothing so each binary uses its own path. A tuple additionally
        # selects a specific profile within that dir via --profile-directory.
        if isinstance(self.profile, tuple):
            udd, profile_directory = self.profile
            cmd[2:2] = [f"--user-data-dir={udd}", f"--profile-directory={profile_directory}"]
        elif self.profile is not BUILTIN_PROFILE:
            cmd.insert(2, f"--user-data-dir={self.profile}")
        if self.url:
            cmd.append(self.url)
        return cmd

    def launch(self, keylog: str) -> subprocess.Popen:
        return subprocess.Popen(self.launch_command(keylog))

