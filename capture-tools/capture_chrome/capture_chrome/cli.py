"""Chrome live-capture tool (plan §7.2, Phase 2 step 3).

Launches Chrome with a dedicated SSLKEYLOGFILE + fresh profile, captures packets
with dumpcap, and streams the pcap + key.log to the gateway over gRPC in
STREAMING_LIVE mode. Decryptable (Chrome-only) flows appear live in the viewer.

Capture is interface-wide; only Chrome's TLS sessions have keys, so the decoded
view is effectively Chrome-only (see plan discussion). Linux + macOS.

Run in a terminal with no arguments for the interactive flow: it lists the
discovered Chrome/Chromium binaries to pick from, then the profile to use (system
default / a fresh temp / a named persistent profile under ~/.capture-chrome/profiles).
Flags override each step; `--no-prompt` (or a non-TTY stdin) skips the pickers and
uses auto-detected defaults, so it stays scriptable:

    capture-chrome --no-prompt --label demo --url https://example.com

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

from capture_sdk import platform
from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip
from capture_sdk.proto import ingest_pb2_grpc as ig

_SENTINEL = object()

# Persistent custom profiles live here so a capture's logins/state survive across runs.
_PROFILES_DIR = os.path.expanduser("~/.capture-chrome/profiles")


# --- interactive prompts -------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        v = ""
    return v or default


def _choose(title: str, items: list[str]) -> str:
    print(f"\n{title}")
    for i, it in enumerate(items, 1):
        print(f"  {i:2d}. {it}")
    while True:
        raw = _ask("select", "1")
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return items[int(raw) - 1]
        print("  ? enter a number from the list")


def _pick_chrome() -> str:
    """Step 1: show discovered Chrome/Chromium binaries and pick one."""
    bins = platform.chrome_binaries()
    if not bins:
        print("no Chrome/Chromium found on PATH")
        return _ask("Chrome binary path")
    choice = _choose("Chrome to use:", bins + ["custom path…"])
    return _ask("Chrome binary path") if choice == "custom path…" else choice


def _pick_profile(chrome: str) -> str:
    """Step 2: pick the user-data-dir — system default, a fresh temp, or a named
    persistent profile under ~/.capture-chrome/profiles."""
    default_dir = platform.chrome_profile_default(chrome)
    choice = _choose("Profile:", [
        f"system default profile ({default_dir})",
        "temporary new empty profile",
        "custom persistent profile (~/.capture-chrome/profiles)",
    ])
    if choice.startswith("system default"):
        print("note: quit any running Chrome on this profile first, or no TLS keys are logged")
        return default_dir
    if choice.startswith("temporary"):
        return tempfile.mkdtemp(prefix="chrome-capture-")
    os.makedirs(_PROFILES_DIR, exist_ok=True)
    existing = sorted(d for d in os.listdir(_PROFILES_DIR)
                      if os.path.isdir(os.path.join(_PROFILES_DIR, d)))
    if existing:
        print("existing: " + ", ".join(existing))
    name = _ask("profile name", "default")
    path = os.path.join(_PROFILES_DIR, name)
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
    ap.add_argument("--filter", default="tcp port 80 or tcp port 443 or udp port 443",
                    help="dumpcap capture filter (BPF; udp port 443 captures HTTP/3 + QUIC)")
    ap.add_argument("--url", default=None, help="URL to open")
    ap.add_argument("--chrome", default=None,
                    help="Chrome/Chromium binary (default: auto-detect, or pick when interactive)")
    ap.add_argument("--profile-dir", default=None,
                    help="Chrome user-data-dir (default: a fresh temp profile, or pick when "
                         "interactive). Quit any running Chrome on this profile first, or the "
                         "launch attaches to it and no TLS keys are logged.")
    ap.add_argument("--no-prompt", action="store_true",
                    help="skip the interactive Chrome/profile pickers (use defaults)")
    ap.add_argument("--duration", type=float, default=None,
                    help="auto-stop after N seconds (default: run until Chrome is closed)")
    ap.add_argument("chrome_args", nargs=argparse.REMAINDER,
                    help="extra Chrome flags after --")
    args = ap.parse_args(argv)

    # Interactive by default in a terminal: pick the Chrome binary and profile unless
    # they were given as flags (or prompting was disabled / there's no TTY).
    interactive = not args.no_prompt and sys.stdin.isatty()
    chrome = args.chrome or os.environ.get("CHROME_BIN")
    if not chrome:
        chrome = _pick_chrome() if interactive else platform.chrome_binary()
    profile = args.profile_dir
    if not profile:
        profile = _pick_profile(chrome) if interactive else tempfile.mkdtemp(prefix="chrome-capture-")

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
    print(f"session {sid}  iface={iface}  keylog={keylog}", flush=True)

    q: queue.Queue = queue.Queue()
    stop = threading.Event()

    dump = subprocess.Popen(
        [dumpcap, "-i", iface, "-P", "-w", "-", "-q", "-f", args.filter],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        *[a for a in args.chrome_args if a != "--"],
    ]
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
