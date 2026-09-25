"""macOS per-process packet capture via PKTAP.

Every other capture source in this repo records a whole interface and lets the key-log
decide what decodes — correct, but the pcap still carries every other app's packets, so a
tiny Chrome session can produce a huge bundle. macOS has a native answer: PKTAP, a pseudo
interface that tags each packet with the process that sent or received it, and Apple's
tcpdump can filter on that tag (`-Q 'proc = "…"'`). This is the macOS twin of the Android
source's per-app nflog capture.

Two facts shape everything here:

* **PKTAP needs root, every time.** The interface is created per capture via SIOCIFCREATE,
  which is privileged — Wireshark's ChmodBPF does not help (it grants /dev/bpf*, not
  interface creation) and it cannot be pre-created at boot and reused. So this source runs
  as root and is started by hand, once, rather than spawned by the gateway.
* **The process to filter on is not the browser.** Chrome does all of its networking in
  the NetworkService utility process, whose name is `<Browser> Helper`; the main process
  owns no sockets. And the kernel truncates a process name to MAXCOMLEN (16) characters,
  which is the form the metadata filter matches — so Chrome is `Google Chrome He`.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess

#: MAXCOMLEN. The kernel stores a process name in `pth_comm[MAXCOMLEN+1]`, so anything
#: longer is truncated — and the truncated form is what `-Q 'proc = "…"'` compares against.
MAXCOMLEN = 16

#: Session-metadata key carrying the pids this capture's browser actually used, reported at
#: CloseSession. Mirrors gateway/internal/server/ingest.go.
PIDS_KEY = "capture.pids"

#: The Chromium switch that marks the one child process owning the browser's sockets.
#: Renderers, the GPU process and the rest never appear on the network.
_NETWORK_SERVICE = "--utility-sub-type=network.mojom.NetworkService"


def tcpdump_binary() -> str:
    """Apple's tcpdump, which is the one that speaks PKTAP and the `-Q` metadata filter.

    Wireshark's dumpcap cannot be used here: it has no metadata filter, so it would record
    every process on the pktap interface and lose the entire point. Honours TCPDUMP_BIN,
    else the system binary — deliberately *not* PATH, since a Homebrew libpcap tcpdump
    lacks Apple's extensions."""
    if env := os.environ.get("TCPDUMP_BIN"):
        return env
    if os.path.exists("/usr/sbin/tcpdump"):
        return "/usr/sbin/tcpdump"
    if p := shutil.which("tcpdump"):
        return p
    raise RuntimeError("tcpdump not found (expected /usr/sbin/tcpdump); set TCPDUMP_BIN")


def helper_process_name(binary: str) -> str:
    """The process name to filter on for a Chrome-family browser at `binary`.

    Chrome's sockets belong to its NetworkService utility process — never to the main
    process, so filtering on the browser's own name captures nothing at all. Truncated to
    MAXCOMLEN because that is the form the kernel records and the filter matches.

    The name is read out of the app bundle rather than derived from the browser's filename,
    because the two disagree on every release channel that keeps the base product's
    branding in its framework. `Google Chrome Canary.app` ships
    `Google Chrome Framework.framework`, whose helper is `Google Chrome Helper` — so
    deriving it gives `Google Chrome Canary Helper`, which truncates to `Google Chrome Ca`,
    a name no process on the machine has. The filter then matches nothing and the capture
    is empty with every other part of the system working perfectly.

    Deriving it remains the fallback, for a layout this does not recognise."""
    if found := _bundled_helper_name(binary):
        return found[:MAXCOMLEN]
    return f"{os.path.basename(binary)} Helper"[:MAXCOMLEN]


def _bundled_helper_name(binary: str) -> str | None:
    """The NetworkService helper's executable name as the bundle actually spells it.

    Chromium puts its helpers in the framework, not the app:
    `<app>/Contents/Frameworks/<product> Framework.framework/Versions/<v>/Helpers/`. Only
    the plain `… Helper.app` is wanted — the bracketed siblings (`(Renderer)`, `(GPU)`,
    `(Alerts)`) are the other child process types and own no sockets. Several `Versions`
    directories coexist during an update and agree on the name, so the first will do.

    None when nothing matches, which includes every non-macOS layout."""
    contents = os.path.dirname(os.path.dirname(binary))  # …/X.app/Contents/MacOS/X → Contents
    pattern = os.path.join(glob.escape(contents), "Frameworks", "*.framework",
                           "Versions", "*", "Helpers", "*Helper.app")
    for path in sorted(glob.glob(pattern)):
        name = os.path.basename(path).removesuffix(".app")
        if name.endswith(" Helper"):
            return name
    return None


def _named_pids(proc: str) -> list[int]:
    """Every pid whose truncated process name matches `proc`.

    `ps -axco pid,comm` reports the accounting name — the same string the kernel puts in
    pth_comm — so this compares exactly what the metadata filter will compare."""
    try:
        out = subprocess.run(["ps", "-axco", "pid,comm"], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    pids = []
    for line in out.splitlines()[1:]:  # skip the header
        pid, _, comm = line.strip().partition(" ")
        if pid.isdigit() and comm.strip()[:MAXCOMLEN] == proc:
            pids.append(int(pid))
    return pids


def _socket_owning_pids() -> set[int] | None:
    """Pids currently holding an internet socket, or None if that can't be established."""
    try:
        out = subprocess.run(["lsof", "-nP", "-i", "-F", "p"], capture_output=True, text=True,
                             timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    pids = {int(ln[1:]) for ln in out.splitlines() if ln[:1] == "p" and ln[1:].isdigit()}
    return pids or None


def matching_pids(proc: str) -> list[int]:
    """Pids that would match the name filter *and* can actually emit packets.

    The name is shared far more widely than it looks: Chrome's renderers are
    `<Browser> Helper (Renderer)`, which truncates to the same 16 characters as the
    NetworkService helper, so a busy browser contributes ~200 matching pids. Listing them
    all would build a multi-kilobyte filter expression evaluated per packet, for no gain —
    renderers own no sockets, so pktap never tags a packet to them. Intersecting with the
    processes that actually hold one leaves the handful that matter (one per browser).

    Returns [] when the socket owners can't be determined, so the filter stays valid and
    falls back to matching by name alone."""
    named = _named_pids(proc)
    if not named:
        return []
    owners = _socket_owning_pids()
    if owners is None:
        return []
    return sorted(set(named) & owners)


def _flag_present(command: str, flag: str) -> bool:
    """Whether `command` carries exactly `flag`, not a longer one starting the same way.

    `--user-data-dir=/a` must not match `--user-data-dir=/ab`, and a plain `in` would.
    Trailing spaces make the end of the line behave like any other separator."""
    return f"{flag} " in f"{command} "


def network_service_pids(user_data_dir: str | None, browser_pid: int | None = None) -> set[int]:
    """Pids of the NetworkService processes belonging to *our* browser.

    This is the per-instance identity the metadata filter cannot express. `proc` matches a
    16-character name shared by every Chrome-family browser on the machine; a pid is exact,
    but the one we want does not exist until after we launch, and can be replaced if the
    network process crashes. So it is resolved here, repeatedly, while the capture runs.

    The mark is the `--user-data-dir` we chose: Chrome passes the resolved directory down to
    every child, so the browser's own network process carries it in argv while another
    Chrome's carries a different one. That is only unambiguous because `ChromeCapture.start`
    refuses to capture a profile something is already running on — the two halves of this
    source hold each other up. `browser_pid` is the fallback for the one case with no mark:
    a built-in profile whose default directory we could not resolve.
    """
    try:
        out = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,command="],
                             capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    flag = f"--user-data-dir={user_data_dir}" if user_data_dir else None
    pids: set[int] = set()
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pid, ppid, command = int(parts[0]), parts[1], parts[2]
        if _NETWORK_SERVICE not in command:
            continue
        if flag and _flag_present(command, flag):
            pids.add(pid)
        elif browser_pid is not None and ppid.isdigit() and int(ppid) == browser_pid:
            pids.add(pid)
    return pids


def filter_expression(proc: str, exclude_pids=()) -> str:
    """The metadata filter: `proc`'s packets, minus the pids listed.

    Name alone matches *every* Chrome-family instance on the machine, so a browser the user
    already had open is captured too — its flows never decrypt (its keys are not in our
    key-log) but its bytes still bloat the pcap, which is the one thing this source exists
    to avoid. Excluding the pids that existed a moment before we launch narrows it to the
    instance we are about to start: ours is the only one whose network process is new.

    Written as a chain of `pid != N` rather than the more natural `not (pid = A or pid =
    B)`, because Apple's filter parser cannot read the latter. `A and not (B or C)` fails
    with *"missing right parenthesis"* — tcpdump then exits before capturing anything, so
    the capture is empty whenever two Chrome-family browsers happen to hold sockets. The
    single-term form `A and not (B)` parses, which is what made this intermittent and hard
    to see: it depended on how many browsers were open. The `!=` form parses at every
    length tested (100 terms, 1.6KB).

    The set is fixed when tcpdump starts, so a browser opened *during* the capture still
    slips past it: its network process has a pid in neither list. That is what this filter
    cannot fix and why it is only half the narrowing — the kernel makes the cheap cut here
    (every non-browser process on the machine, which is most of the traffic), and the
    gateway makes the exact one when the session closes, using the pids
    [network_service_pids][capture_pktap.pktap.network_service_pids] observed while the
    capture ran. Keeping this filter broad is deliberate: a pid-only filter would go blind
    the moment Chrome replaced its network process, and those packets would be gone for
    good rather than merely unclassified."""
    expr = f'proc = "{proc}"'
    if exclude_pids:
        expr += "".join(f" and pid != {p}" for p in sorted(exclude_pids))
    return expr


def capture_command(iface: str, expression: str, *, tcpdump: str | None = None) -> list[str]:
    """tcpdump recording only the packets `expression` selects on `iface`, as pcap-ng on
    stdout.

    `-i pktap,<iface>` creates the tagged pseudo interface over that one NIC, and
    `--apple-md-filter` is the metadata filter (the long form of the overloaded `-Q`, which
    also means direction — spelling it out keeps the two from being confused). `-U` flushes
    each packet so the live view stays live instead of trickling out a buffer at a time.

    The output is pcap-ng and that is not negotiable: tcpdump(1) says the metadata filter
    "is meaningful only with capture files in the Pcap-ng file format or for interfaces
    supporting the PKTAP data link type". Forcing classic pcap with `-y RAW` strips the
    metadata the filter reads, and the filter then silently stops matching outbound packets
    — the capture keeps only one side of every connection, so no handshake is ever seen and
    nothing decodes. The gateway reads pcap-ng with DLT_PKTAP directly instead."""
    return [
        tcpdump or tcpdump_binary(),
        "-i", f"pktap,{iface}",
        "--apple-md-filter", expression,
        "-U",           # packet-buffered: the gateway decodes as packets arrive
        "-n",           # no name resolution — it would generate its own DNS traffic
        "-w", "-",
    ]
