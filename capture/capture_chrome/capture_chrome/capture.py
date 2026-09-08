"""The Chrome capture runner, shared by the interactive CLI and serve mode.

`ChromeCapture` is the SDK's dumpcap + `SSLKEYLOGFILE` engine
([KeylogCapture][capture_sdk.livecapture.KeylogCapture]) with Chrome's launch on top: the
key-log flag, the profile flags, and any extra Chrome arguments. Everything else — the
session, the pcap/keylog streaming, and teardown — is the shared engine.
"""

from __future__ import annotations

import subprocess

from capture_sdk import snap
from capture_sdk.browser import BUILTIN_PROFILE, profile_desc  # noqa: F401 — re-exported
from capture_sdk.livecapture import KeylogCapture
from capture_sdk.proto import common_pb2 as cp


class ChromeCapture(KeylogCapture):
    """One live Chrome capture. `start` opens the session and launches everything (returns
    the session id, non-blocking); `wait` blocks until Chrome closes / duration elapses /
    stop is requested; `stop` tears down and closes the session (idempotent)."""

    source_kind = cp.SOURCE_KIND_CHROME
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

    def launch(self, keylog: str) -> subprocess.Popen:
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
        return subprocess.Popen(cmd)
