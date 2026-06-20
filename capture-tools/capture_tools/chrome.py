"""Chrome live-capture tool (plan §7.2, Phase 2 step 3).

Launches Chrome with a dedicated SSLKEYLOGFILE + fresh profile, captures packets
with dumpcap, and streams the pcap + key.log to the gateway over gRPC in
STREAMING_LIVE mode. Decryptable (Chrome-only) flows appear live in the viewer.

Capture is interface-wide; only Chrome's TLS sessions have keys, so the decoded
view is effectively Chrome-only (see plan discussion). Linux + macOS.

Run with capture permission for dumpcap (Linux: be in the `wireshark` group;
macOS: Wireshark's ChmodBPF). Example:

    python -m capture_tools.chrome --gateway 127.0.0.1:8080 --label demo \\
        --url https://example.com
"""

from __future__ import annotations

import argparse
import os
import queue
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

_GEN = Path(__file__).resolve().parent.parent / "gen"
if str(_GEN) not in sys.path:
    sys.path.insert(0, str(_GEN))

import grpc  # noqa: E402
from traffic.v1 import common_pb2 as cp  # noqa: E402
from traffic.v1 import ingest_pb2 as ip  # noqa: E402
from traffic.v1 import ingest_pb2_grpc as ig  # noqa: E402

from capture_tools.common import platform  # noqa: E402

_SENTINEL = object()


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
    ap.add_argument("--filter", default="tcp port 80 or tcp port 443",
                    help="dumpcap capture filter (BPF)")
    ap.add_argument("--url", default=None, help="URL to open")
    ap.add_argument("--profile-dir", default=None,
                    help="Chrome user-data-dir (default: a fresh temp profile). "
                         "Quit any running Chrome on this profile first, or the "
                         "launch attaches to it and no TLS keys are logged.")
    ap.add_argument("--duration", type=float, default=None,
                    help="auto-stop after N seconds (default: run until Chrome is closed)")
    ap.add_argument("chrome_args", nargs=argparse.REMAINDER,
                    help="extra Chrome flags after --")
    args = ap.parse_args(argv)

    iface = args.iface or platform.default_interface()
    chrome = platform.chrome_binary()
    dumpcap = platform.dumpcap_binary()
    profile = args.profile_dir or tempfile.mkdtemp(prefix="chrome-capture-")
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
