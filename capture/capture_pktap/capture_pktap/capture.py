"""The pktap capture runner: a Chrome capture that records only Chrome's own packets.

`PktapCapture` is [ChromeCapture][capture_chrome.capture.ChromeCapture] with three things
swapped — the capture command (Apple tcpdump on a pktap interface, filtered to the
browser's NetworkService process, instead of dumpcap on the whole NIC), the browser launch
(dropped to the invoking user, because we hold root for the capture), and a watcher that
records which processes actually owned this browser's sockets. Chrome's flags, the profile
handling, the `AlreadyRunning` preflight, the key-log streaming and the session lifecycle
are all inherited unchanged.

The narrowing happens in two places on purpose. The kernel filter is fixed when tcpdump
starts, which is before the browser exists, so the best it can do is "this process name,
excluding the instances already running" — cheap, and enough to drop every other app on
the machine. What it cannot do is exclude a browser the user opens *later*. The watcher
closes that gap by collecting the pids as they appear, and the gateway prunes the stored
pcap to them when the session closes. Filtering broadly and pruning exactly beats doing
either alone: a pid-only kernel filter would go blind if Chrome replaced its network
process, and a broad filter alone leaves another browser's traffic in the bundle.
"""

from __future__ import annotations

import os
import pwd
import subprocess
import threading

from capture_chrome import profiles
from capture_chrome.capture import ChromeCapture

from capture_pktap import pktap, privdrop

#: How often to re-check which processes own the browser's sockets. A NetworkService
#: appears about a second after launch and is replaced only if it crashes, so this is
#: about not missing a short-lived one rather than about reacting quickly.
_WATCH_INTERVAL = 2.0


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
        #: Every pid this browser's NetworkService has used, accumulated while the capture
        #: runs and reported at close so the gateway can prune the pcap to exactly them.
        #: A set because the browser may replace that process, and both owned packets.
        self.helper_pids: set[int] = set()
        #: The --user-data-dir this capture launches against, which is the mark that tells
        #: our browser's network process from another Chrome's. None when it can't be
        #: resolved (a built-in profile on an unknown binary); the watcher falls back to
        #: parentage then.
        self._user_data_dir = profiles.user_data_dir(self.chrome, self.profile)

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
        proc = self._launch_browser(keylog)
        # Start watching only now: before this there is no browser, and the pids matching
        # the name all belong to somebody else.
        self._watcher = threading.Thread(
            target=self._watch_helpers, args=(proc.pid,), daemon=True, name="pktap-helpers")
        self._watcher.start()
        return proc

    def _launch_browser(self, keylog: str) -> subprocess.Popen:
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

    def _watch_helpers(self, browser_pid: int) -> None:
        """Collect this browser's NetworkService pids for as long as the capture runs.

        Polling rather than waiting for one answer: the process does not exist at launch,
        and a browser that crashes its network service gets a new one whose packets are
        just as much ours. The set only grows — a pid that has exited still owned the
        packets already on disk."""
        while not self._stop.is_set():
            found = pktap.network_service_pids(self._user_data_dir, browser_pid)
            if new := found - self.helper_pids:
                self.helper_pids |= new
                print(f"pktap: capturing network process {sorted(new)} "
                      f"(browser pid {browser_pid})", flush=True)
            self._stop.wait(_WATCH_INTERVAL)

    def close_metadata(self) -> dict[str, str]:
        # The kernel filter could only exclude the pids that existed before launch, so the
        # pcap may still hold a browser started midway through. These pids are the exact
        # answer, and the gateway prunes to them once the capture is closed.
        if not self.helper_pids:
            # Nothing identified: report nothing rather than an empty list, which the
            # gateway would have to treat as "drop every packet".
            print("pktap: never identified the browser's network process — "
                  "the capture keeps every Chrome-family packet", flush=True)
            return {}
        return {pktap.PIDS_KEY: ",".join(str(p) for p in sorted(self.helper_pids))}
