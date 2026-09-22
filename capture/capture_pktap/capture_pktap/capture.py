"""The pktap capture runner: a Chrome capture that records only Chrome's own packets.

`PktapCapture` is [ChromeCapture][capture_chrome.capture.ChromeCapture] with two things
swapped — the capture command (Apple tcpdump on a pktap interface, filtered to the
browser's NetworkService process, instead of dumpcap on the whole NIC) and the browser
launch (dropped to the invoking user, because we hold root for the capture). Chrome's
flags, the profile handling, the `AlreadyRunning` preflight, the key-log streaming and the
session lifecycle are all inherited unchanged.
"""

from __future__ import annotations

import os
import pwd
import subprocess

from capture_chrome.capture import ChromeCapture

from capture_pktap import pktap, privdrop


class PktapCapture(ChromeCapture):
    """One live Chrome capture recording only that browser's packets. Same start/wait/stop
    contract as every other capture; see `KeylogCapture`."""

    name = "pktap"

    def __init__(self, *, run_as: tuple[int, int] | None = None, tcpdump: str | None = None,
                 **kw) -> None:
        super().__init__(**kw)
        self.run_as = run_as  # honoured by KeylogCapture (keylog dir) and launch() below
        self.tcpdump = tcpdump
        # The browser writes the keylog, and it runs as the user — so the dir must be one
        # they can reach. Root's $TMPDIR is not (see privdrop.user_tempdir).
        if user_tmp := privdrop.user_tempdir(run_as):
            self.keylog_dir = user_tmp
        #: The process the metadata filter matches — the browser's NetworkService helper,
        #: not the browser itself. Recorded so the CLI and logs can show what was filtered.
        self.proc_name = pktap.helper_process_name(self.chrome)
        #: Pids of that name already running when the capture started, excluded from the
        #: filter so only the browser we launch is recorded. Filled in by capture_command.
        self.excluded_pids: list[int] = []

    def capture_command(self, iface: str) -> list[str]:
        # Called immediately before tcpdump starts and before the browser is launched, so
        # every process matching the name right now is somebody else's — ours does not
        # exist yet. Excluding them is what makes this capture *our* Chrome rather than
        # every Chrome. capture_filter (BPF) stays unused: the metadata filter is the point,
        # and a BPF expression would narrow by port/host on top of it.
        self.excluded_pids = pktap.matching_pids(self.proc_name)
        expr = pktap.filter_expression(self.proc_name, self.excluded_pids)
        return pktap.capture_command(iface, expr, tcpdump=self.tcpdump)

    def launch(self, keylog: str) -> subprocess.Popen:
        cmd = self.launch_command(keylog)
        if self.run_as is None:
            return subprocess.Popen(cmd)
        uid, gid = self.run_as
        pw = pwd.getpwuid(uid)
        # user/group demote the child itself (stdlib, 3.9+); HOME has to come along or
        # Chrome resolves its default profile against root's home despite running as them.
        return subprocess.Popen(
            cmd, user=uid, group=gid,
            env={**os.environ, "HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name})
