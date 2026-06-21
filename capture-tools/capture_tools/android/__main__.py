"""Android capture agent (plan §7, Phase 7).

Per-app capture from a rooted emulator/device:
  * Frida spawns the target app + hooks BoringSSL → NSS key.log (no proxy/CA).
  * iptables tags the app's connections by UID and NFLOGs them; on-device tcpdump
    reads `nflog:<group>` → a pcap of *only that app's* packets.
Both stream to the gateway over UploadCapture (STREAMING_LIVE), decoded by tshark
exactly like the Chrome path.

  uv run --project capture-tools python -m capture_tools.android \\
      --package com.android.chrome --url https://example.com --duration 20
"""

from __future__ import annotations

import argparse
import lzma
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

_GEN = Path(__file__).resolve().parent.parent.parent / "gen"
if str(_GEN) not in sys.path:
    sys.path.insert(0, str(_GEN))

import frida  # noqa: E402
import grpc  # noqa: E402
from traffic.v1 import common_pb2 as cp  # noqa: E402
from traffic.v1 import ingest_pb2 as ip  # noqa: E402
from traffic.v1 import ingest_pb2_grpc as ig  # noqa: E402

from capture_tools.android.adb import AdbClient, frida_arch, nflog_rules  # noqa: E402
from capture_tools.common.upload import SENTINEL, capture_chunks  # noqa: E402

_SCRIPT = Path(__file__).resolve().parent / "frida_sslkeylog.js"
_FRIDA_REMOTE = "/data/local/tmp/frida-server"


def ensure_frida_server(adb: AdbClient, abi: str) -> None:
    """Make frida-server reachable on the device (download+push+start if needed)."""
    try:
        frida.get_usb_device(timeout=2).enumerate_processes()
        return  # already running
    except Exception:  # noqa: BLE001
        pass
    version = frida.__version__
    arch = frida_arch(abi)
    cache = Path(os.path.expanduser("~/.cache/traffic-android"))
    cache.mkdir(parents=True, exist_ok=True)
    local = cache / f"frida-server-{version}-android-{arch}"
    if not local.exists():
        url = (f"https://github.com/frida/frida/releases/download/{version}/"
               f"frida-server-{version}-android-{arch}.xz")
        print(f"downloading {url}", flush=True)
        with urllib.request.urlopen(url) as r:  # noqa: S310
            local.write_bytes(lzma.decompress(r.read()))
    adb.push(str(local), _FRIDA_REMOTE)
    adb.shell("chmod", "755", _FRIDA_REMOTE)
    adb.run("shell", _FRIDA_REMOTE, check=False, capture=False)  # detached by adb
    for _ in range(20):
        try:
            frida.get_usb_device(timeout=1).enumerate_processes()
            return
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    raise RuntimeError("frida-server did not become reachable")


def _tcpdump_reader(stdout, q: "queue.Queue", stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            b = stdout.read(65536)
            if not b:
                break
            q.put(("pcap", b))
    except Exception:  # noqa: BLE001
        pass


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Per-app Android capture → gateway")
    ap.add_argument("--package", required=True, help="target app package name")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"))
    ap.add_argument("--label", default=None, help="session label (default: the package)")
    ap.add_argument("--url", default=None, help="open this URL in the app after launch (am start VIEW)")
    ap.add_argument("--duration", type=float, default=None, help="auto-stop after N seconds")
    ap.add_argument("--serial", default=None, help="adb device serial (default: the only device)")
    ap.add_argument("--nflog-group", type=int, default=30)
    ap.add_argument("--mark", type=lambda s: int(s, 0), default=0x2a)
    ap.add_argument("--attach", action="store_true",
                    help="attach to the already-running app instead of spawning it")
    args = ap.parse_args(argv)
    label = args.label or args.package

    adb = AdbClient(serial=args.serial)
    adb.root()
    abi = adb.abi()
    uid = adb.app_uid(args.package)
    print(f"device abi={abi}  {args.package} uid={uid}", flush=True)
    ensure_frida_server(adb, abi)

    chan = grpc.insecure_channel(args.gateway)
    ing = ig.IngestServiceStub(chan)
    handle = ing.OpenSession(ip.OpenSessionRequest(
        label=label, source_kind=cp.SOURCE_KIND_ANDROID_EMULATOR))
    sid = handle.session_id
    max_chunk = handle.max_chunk_bytes or (1 << 20)
    print(f"session {sid}", flush=True)

    q: "queue.Queue" = queue.Queue()
    stop = threading.Event()

    # NFLOG per-app capture rules (added before tcpdump opens the group).
    add_rules, teardown_rules = nflog_rules(uid, args.mark, args.nflog_group)
    for rule in add_rules:
        adb.shell(*rule)

    # On-device tcpdump reads the app's NFLOG group. exec-out keeps stdout raw; the
    # device-side `2>/dev/null` drops tcpdump's "listening on …" banner so only the
    # pcap stream reaches us (otherwise it corrupts the first record).
    tcpdump = subprocess.Popen(
        adb._base() + ["exec-out", "sh", "-c",
                       f"tcpdump -i nflog:{args.nflog_group} -U -s 0 -w - 2>/dev/null"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    rt = threading.Thread(target=_tcpdump_reader, args=(tcpdump.stdout, q, stop), daemon=True)
    rt.start()

    ack: dict = {}
    def upload():
        ack["ack"] = ing.UploadCapture(capture_chunks(sid, q, max_chunk, upload_id="android"))
    ut = threading.Thread(target=upload, daemon=True)
    ut.start()

    # Frida: spawn (or attach) the app and stream its TLS secrets as key.log lines.
    # Apps are often multi-process (Chrome's network/renderer run in zygote-forked
    # `<pkg>:child` processes), so hook the main process *and* every matching child.
    device = frida.get_usb_device(timeout=5)
    script_src = _SCRIPT.read_text()
    keys = {"n": 0}
    hooked: set[int] = set()
    sessions: list = []

    def on_message(message, _data):
        if message.get("type") == "send":
            p = message.get("payload") or {}
            if p.get("type") == "keylog":
                q.put(("keylog", (p["line"] + "\n").encode()))
                keys["n"] += 1
            elif p.get("type") == "log":
                print(f"[frida] {p.get('message')}", flush=True)
        elif message.get("type") == "error":
            print(f"[frida-error] {message.get('description')}", flush=True)

    def hook(pid: int) -> None:
        if pid in hooked:
            return
        hooked.add(pid)
        s = device.attach(pid)
        sc = s.create_script(script_src)
        sc.on("message", on_message)
        sc.load()
        sessions.append((s, sc))

    def belongs(name: str) -> bool:
        return name == args.package or name.startswith(args.package + ":")

    if args.attach:
        hook(device.get_process(args.package).pid)
    else:
        pid = device.spawn([args.package])
        hook(pid)            # hook the main process before it runs
        device.resume(pid)
    if args.url:
        time.sleep(1.0)
        adb.shell("am", "start", "-a", "android.intent.action.VIEW", "-d", args.url, args.package)

    def watch_children() -> None:
        while not stop.is_set():
            try:
                for p in device.enumerate_processes():
                    if belongs(p.name):
                        hook(p.pid)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.5)
    wt = threading.Thread(target=watch_children, daemon=True)
    wt.start()

    print(f"capturing {args.package} (stop with Ctrl-C"
          + (f", auto-stop in {args.duration:g}s)" if args.duration else ")"), flush=True)
    try:
        if args.duration:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if not args.attach:
                device.kill(pid)
        except Exception:  # noqa: BLE001
            pass
        stop.set()
        tcpdump.terminate()
        adb.run("shell", "pkill", "tcpdump", check=False)
        for rule in teardown_rules:
            adb.run("shell", *rule, check=False)
        try:
            tcpdump.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tcpdump.kill()
        rt.join(timeout=5)
        q.put(SENTINEL)
        ut.join(timeout=30)
        if a := ack.get("ack"):
            print(f"uploaded pcap={a.pcap_received}B keylog={a.keylog_received}B "
                  f"({keys['n']} secrets)", flush=True)
        summary = ing.CloseSession(ip.CloseSessionRequest(session_id=sid))
        print(f"closed session {sid}: {summary.session.flow_count} flows", flush=True)


if __name__ == "__main__":
    main()
