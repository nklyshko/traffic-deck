"""The Firefox capture runner, shared by the interactive CLI and serve mode.

`FirefoxCapture` is the SDK's dumpcap + `SSLKEYLOGFILE` engine
([KeylogCapture][capture_sdk.livecapture.KeylogCapture]) with Firefox's launch on top.
Two things differ from the Chrome runner and they are the whole of this file: NSS reads
the key-log path from the **environment**, not from a command-line flag, and a profile is
selected either by registered name (`-P`) or by directory (`--profile`).
"""

from __future__ import annotations

import os
import subprocess

from capture_sdk import snap
from capture_sdk.browser import BUILTIN_PROFILE, profile_desc  # noqa: F401 — re-exported
from capture_sdk.livecapture import KeylogCapture


class FirefoxCapture(KeylogCapture):
    """One live Firefox capture. `start` opens the session and launches everything (returns
    the session id, non-blocking); `wait` blocks until Firefox closes / duration elapses /
    stop is requested; `stop` tears down and closes the session (idempotent)."""

    name = "firefox"

    def __init__(self, *, gateway: str, label: str, firefox: str, profile,
                 iface: str | None = None, dumpcap: str | None = None,
                 capture_filter: str = "", url: str | None = None,
                 duration: float | None = None, extra_args=()) -> None:
        # A snap-confined Firefox has a private /tmp, so its keylog has to go under the
        # snap's own writable area or the TLS keys never reach us.
        super().__init__(gateway=gateway, label=label, iface=iface, dumpcap=dumpcap,
                         capture_filter=capture_filter, duration=duration,
                         keylog_dir=snap.writable_base(firefox))
        self.firefox = firefox
        self.profile = profile
        self.url = url
        self.extra_args = list(extra_args)

    def launch(self, keylog: str) -> subprocess.Popen:
        # --no-remote: don't hand the URL to an already-running Firefox and exit (which
        # would leave us capturing a browser we never launched and can't wait on). It also
        # means a profile already open elsewhere refuses to start — the same "quit the
        # running browser first" caveat Chrome has.
        cmd = [self.firefox, "--no-remote", *[a for a in self.extra_args if a != "--"]]
        # A tuple is one of the browser's own registered profiles, selected by name; a path
        # is a tool-managed directory. For the browser default we pass neither, so Firefox
        # opens whatever profile it would have opened on its own.
        if isinstance(self.profile, tuple):
            cmd += ["-P", self.profile[1]]
        elif self.profile is not BUILTIN_PROFILE:
            cmd += ["--profile", self.profile]
        if self.url:
            cmd.append(self.url)
        # NSS writes the TLS secrets to $SSLKEYLOGFILE; there is no equivalent flag.
        return subprocess.Popen(cmd, env={**os.environ, "SSLKEYLOGFILE": keylog})
