"""Chrome live-capture tool.

Launches Chrome with a dedicated SSLKEYLOGFILE + fresh profile, captures packets
with dumpcap, and streams the pcap + key.log to the gateway over gRPC in
STREAMING_LIVE mode. Decryptable (Chrome-only) flows appear live in the viewer.

Capture is interface-wide; only Chrome's TLS sessions have keys, so the decoded
view is effectively Chrome-only. Linux + macOS.

Run in a terminal with no arguments for the interactive flow: it lists the
discovered Chrome/Chromium binaries to pick from, then the profile to use — one of
the browser's own existing profiles (auto-discovered from its Local State and
launched with --profile-directory), the browser's own default (launched with no
--user-data-dir, so each binary uses its own default path), a fresh temp profile,
or a named persistent profile (pick an existing one or create a new one) under
~/.traffic-deck/chrome-profiles. The pickers default to the previous run's choices
(remembered under ~/.traffic-deck/state). Flags override each step; `--no-prompt`
(or a non-TTY stdin) skips the pickers and uses auto-detected defaults (fresh temp
profile), so it stays scriptable:

    trafficdeck-capture-chrome --no-prompt --label demo --url https://example.com

dumpcap needs capture permission (Linux: the `wireshark` group — the capture-chrome.sh
launcher activates it via `sg`; macOS: Wireshark's ChmodBPF).
"""

from __future__ import annotations

import argparse
import os
import queue
import subprocess
import sys
import tempfile
import threading

import grpc

from capture_chrome import platform
from capture_sdk import paths, prompt
from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip
from capture_sdk.proto import ingest_pb2_grpc as ig
from capture_sdk.state import Store

_SENTINEL = object()

# Returned by the profile picker to mean "launch with no --user-data-dir", so the
# chosen browser uses its own built-in default profile (each binary has its own path).
_BUILTIN_PROFILE = object()

# Named persistent custom profiles live here so a capture's logins/state survive
# across runs; the user picks an existing one or creates a new named one.
_PROFILES_DIR = str(paths.home() / "chrome-profiles")
# Pre-relocation location, migrated into _PROFILES_DIR on first use.
_LEGACY_PROFILES_DIR = os.path.expanduser("~/.capture-chrome/profiles")


def _profiles_dir() -> str:
    """The persistent-profiles dir, creating it and migrating any legacy profiles
    (from ~/.capture-chrome/profiles) into it on first use."""
    os.makedirs(_PROFILES_DIR, exist_ok=True)
    if os.path.isdir(_LEGACY_PROFILES_DIR):
        for name in os.listdir(_LEGACY_PROFILES_DIR):
            src = os.path.join(_LEGACY_PROFILES_DIR, name)
            dst = os.path.join(_PROFILES_DIR, name)
            if not os.path.exists(dst):
                os.rename(src, dst)
    return _PROFILES_DIR


# --- interactive prompts -------------------------------------------------

def _pick_chrome(store: Store) -> str:
    """Step 1: show discovered Chrome/Chromium binaries and pick one."""
    bins = platform.chrome_binaries()
    if not bins:
        print("no Chrome/Chromium found on PATH")
        return store.remember("chrome", prompt.text("Chrome binary path"))
    default = store.get_valid("chrome", bins)
    choice = prompt.select("Chrome to use:", bins + [("custom path…", "__custom__")],
                           default=default)
    chrome = prompt.text("Chrome binary path") if choice == "__custom__" else choice
    return store.remember("chrome", chrome)


def _pick_profile(chrome: str, store: Store):
    """Step 2: pick the profile. Returns one of: a (user_data_dir, profile_directory)
    tuple for an existing profile of this browser; a path string used as --user-data-dir
    (fresh temp or a named persistent profile under ~/.traffic-deck/chrome-profiles); or
    _BUILTIN_PROFILE to launch with no --user-data-dir (the browser's own default)."""
    discovered = platform.chrome_profiles(chrome)
    options = []
    if discovered:
        options.append(("existing profile of this browser", "existing"))
    options += [
        ("browser default profile", "default"),
        ("temporary new empty profile", "temp"),
        ("custom persistent profile (~/.traffic-deck/chrome-profiles)", "custom"),
    ]
    choice = prompt.select("Profile:", options,
                           default=store.get_valid("profile_kind", [v for _, v in options]))
    store.remember("profile_kind", choice)
    if choice == "existing":
        return _pick_existing_profile(chrome, discovered, store)
    if choice == "default":
        print(f"note: uses {os.path.basename(chrome)}'s own default profile — quit any "
              "running instance of it first, or no TLS keys are logged")
        return _BUILTIN_PROFILE
    if choice == "temp":
        return tempfile.mkdtemp(prefix="chrome-capture-")
    return _pick_persistent_profile(store)


def _pick_existing_profile(chrome: str, discovered: list[tuple[str, str, str]], store: Store):
    """Pick one of the browser's own discovered profiles; returns (user_data_dir,
    profile_directory) to launch with --user-data-dir + --profile-directory."""
    choices = [(f"{label}  [{dirn}]", (udd, dirn)) for udd, dirn, label in discovered]
    choice = prompt.select("Existing profile:", choices,
                           default=store.get_valid("existing_profile", [v for _, v in choices]))
    store.remember("existing_profile", choice)
    print(f"note: uses {os.path.basename(chrome)}'s real profile — quit any running "
          "instance of it first, or no TLS keys are logged")
    return choice


def _pick_persistent_profile(store: Store) -> str:
    """Choose one of the saved persistent profiles, or create a new named one."""
    profiles_dir = _profiles_dir()
    existing = sorted(d for d in os.listdir(profiles_dir)
                      if os.path.isdir(os.path.join(profiles_dir, d)))
    choice = prompt.select("Custom persistent profile:", existing + [("＋ create new…", "__new__")],
                           default=store.get_valid("profile_name", existing))
    if choice == "__new__":
        name = prompt.text("New profile name", store.get("profile_name") or "default")
    else:
        name = choice
    store.remember("profile_name", name)
    path = os.path.join(profiles_dir, name)
    os.makedirs(path, exist_ok=True)
    return path


def _reader_thread(stdout, q: queue.Queue, stop: threading.Event) -> None:
    """Stream dumpcap's pcap bytes (stdout) into the queue."""
    try:
        while not stop.is_set():
            b = stdout.read(65536)
            if not b:
                break
            q.put(("pcap", b))
    except Exception:  # noqa: BLE001
        pass


def _keylog_thread(path: str, q: queue.Queue, stop: threading.Event) -> None:
    """Tail the SSLKEYLOGFILE and stream new bytes into the queue."""
    import time

    while not os.path.exists(path) and not stop.is_set():
        time.sleep(0.1)
    if not os.path.exists(path):
        return
    with open(path, "rb") as f:
        while True:
            b = f.read()
            if b:
                q.put(("keylog", b))
            elif stop.is_set():
                break
            else:
                time.sleep(0.1)
        if b := f.read():
            q.put(("keylog", b))


def _chunks(session_id: str, q: queue.Queue, max_chunk: int):
    """Generator of CaptureChunk messages for UploadCapture."""
    yield ip.CaptureChunk(begin=ip.UploadBegin(
        session_id=session_id, upload_id="chrome", mode=ip.CAPTURE_MODE_STREAMING_LIVE))
    offsets = {"pcap": 0, "keylog": 0}
    kinds = {"pcap": cp.FILE_KIND_PCAP, "keylog": cp.FILE_KIND_KEYLOG}
    while True:
        item = q.get()
        if item is _SENTINEL:
            break
        kind, payload = item
        for i in range(0, len(payload), max_chunk):
            part = payload[i : i + max_chunk]
            yield ip.CaptureChunk(data=ip.DataChunk(
                kind=kinds[kind], offset=offsets[kind], payload=part))
            offsets[kind] += len(part)
    yield ip.CaptureChunk(end=ip.UploadEnd(upload_id="chrome"))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Stream a live Chrome capture to the gateway")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"))
    ap.add_argument("--label", default="chrome")
    ap.add_argument("--iface", default=None, help="capture interface (default: auto)")
    ap.add_argument("--filter", default="",
                    help="dumpcap capture filter (BPF). Default empty = capture everything "
                         "(so proxies, non-standard ports, and HTTP/3 are all included; the "
                         "decode only surfaces Chrome-decryptable + plaintext HTTP flows). "
                         "Narrow it (e.g. 'tcp port 443') for smaller captures.")
    ap.add_argument("--url", default=None, help="URL to open")
    ap.add_argument("--chrome", default=None,
                    help="Chrome/Chromium binary (default: auto-detect, or pick when interactive)")
    ap.add_argument("--profile-dir", default=None,
                    help="Chrome user-data-dir (default: a fresh temp profile, or pick when "
                         "interactive). Quit any running Chrome on this profile first, or the "
                         "launch attaches to it and no TLS keys are logged.")
    ap.add_argument("--profile-directory", default=None,
                    help="profile within --user-data-dir to launch (e.g. 'Profile 1'); "
                         "pairs with --profile-dir for a specific discovered profile")
    ap.add_argument("--default-profile", action="store_true",
                    help="use the browser's own default profile (launch with no --user-data-dir)")
    ap.add_argument("--no-prompt", action="store_true",
                    help="skip the interactive Chrome/profile pickers (use defaults)")
    ap.add_argument("--duration", type=float, default=None,
                    help="auto-stop after N seconds (default: run until Chrome is closed)")
    ap.add_argument("chrome_args", nargs=argparse.REMAINDER,
                    help="extra Chrome flags after --")
    args = ap.parse_args(argv)

    # Interactive by default in a terminal: pick the Chrome binary and profile unless
    # they were given as flags (or prompting was disabled / there's no TTY). The pickers
    # default to the previous run's choices, remembered under ~/.traffic-deck/state.
    interactive = not args.no_prompt and sys.stdin.isatty()
    store = Store("chrome")
    chrome = args.chrome or os.environ.get("CHROME_BIN")
    if not chrome:
        chrome = _pick_chrome(store) if interactive else platform.chrome_binary()
    # profile is a path (→ --user-data-dir), a (user_data_dir, profile_directory) tuple
    # for a specific profile, or _BUILTIN_PROFILE (no flag → the browser's own default).
    if args.default_profile:
        profile = _BUILTIN_PROFILE
    elif args.profile_dir:
        profile = (args.profile_dir, args.profile_directory) if args.profile_directory \
            else args.profile_dir
    elif interactive:
        profile = _pick_profile(chrome, store)
    else:
        profile = tempfile.mkdtemp(prefix="chrome-capture-")

    iface = args.iface or platform.default_interface()
    dumpcap = platform.dumpcap_binary()
    # Keep the keylog out of the profile dir so an existing user profile isn't
    # polluted (and stays valid even when --profile-dir points at a real one).
    keylog = os.path.join(tempfile.mkdtemp(prefix="chrome-keylog-"), "key.log")

    chan = grpc.insecure_channel(args.gateway)
    ing = ig.IngestServiceStub(chan)
    handle = ing.OpenSession(ip.OpenSessionRequest(
        label=args.label, source_kind=cp.SOURCE_KIND_CHROME))
    sid = handle.session_id
    max_chunk = handle.max_chunk_bytes or (1 << 20)
    prof_desc = (
        "browser default" if profile is _BUILTIN_PROFILE
        else f"{profile[0]} [{profile[1]}]" if isinstance(profile, tuple)
        else profile)
    print(f"session {sid}  iface={iface}  profile={prof_desc}  keylog={keylog}", flush=True)

    q: queue.Queue = queue.Queue()
    stop = threading.Event()

    dump_cmd = [dumpcap, "-i", iface, "-P", "-w", "-", "-q"]
    if args.filter:
        dump_cmd += ["-f", args.filter]  # no filter = capture everything
    dump = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    rt = threading.Thread(target=_reader_thread, args=(dump.stdout, q, stop), daemon=True)
    kt = threading.Thread(target=_keylog_thread, args=(keylog, q, stop), daemon=True)
    rt.start()
    kt.start()

    ack = {}
    def upload():
        ack["ack"] = ing.UploadCapture(_chunks(sid, q, max_chunk))
    ut = threading.Thread(target=upload, daemon=True)
    ut.start()

    chrome_cmd = [
        chrome,
        f"--ssl-key-log-file={keylog}",
        "--no-first-run",
        "--no-default-browser-check",
        *[a for a in args.chrome_args if a != "--"],
    ]
    # Only pin a user-data-dir for temp/explicit/persistent profiles; for the browser
    # default we pass nothing so each binary uses its own default profile path. A tuple
    # additionally selects a specific profile within that dir via --profile-directory.
    if isinstance(profile, tuple):
        user_data_dir, profile_directory = profile
        chrome_cmd[2:2] = [f"--user-data-dir={user_data_dir}",
                           f"--profile-directory={profile_directory}"]
    elif profile is not _BUILTIN_PROFILE:
        chrome_cmd.insert(2, f"--user-data-dir={profile}")
    if args.url:
        chrome_cmd.append(args.url)

    if args.duration:
        print(f"launching Chrome (auto-stop in {args.duration:g}s) …", flush=True)
    else:
        print("launching Chrome (close it to finish capture) …", flush=True)
    chrome_proc = subprocess.Popen(chrome_cmd)
    try:
        chrome_proc.wait(timeout=args.duration)
    except subprocess.TimeoutExpired:
        pass  # --duration elapsed
    except KeyboardInterrupt:
        pass
    finally:
        if chrome_proc.poll() is None:
            chrome_proc.terminate()
            try:
                chrome_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                chrome_proc.kill()
        # Stop capture: terminate dumpcap, drain producers, end the upload stream.
        stop.set()
        dump.terminate()
        try:
            dump.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dump.kill()
        rt.join(timeout=5)
        kt.join(timeout=5)
        q.put(_SENTINEL)
        ut.join(timeout=30)
        if a := ack.get("ack"):
            print(f"uploaded pcap={a.pcap_received}B keylog={a.keylog_received}B", flush=True)
        summary = ing.CloseSession(ip.CloseSessionRequest(session_id=sid))
        print(f"closed session {sid}: {summary.session.flow_count} flows", flush=True)


if __name__ == "__main__":
    main()
