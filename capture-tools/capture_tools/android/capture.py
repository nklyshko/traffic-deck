"""Core per-app Android capture (library) — reusable by both CLIs.

Assumes the target is ready (root + frida-server); call frida_server.ensure_target_ready
first. Captures one app's traffic via UID→NFLOG tcpdump + a Frida TLS keylog and streams
pcap + key.log to the gateway over UploadCapture.
"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

_GEN = Path(__file__).resolve().parent.parent.parent / "gen"
if str(_GEN) not in sys.path:
    sys.path.insert(0, str(_GEN))

import grpc  # noqa: E402
from traffic.v1 import common_pb2 as cp  # noqa: E402
from traffic.v1 import ingest_pb2 as ip  # noqa: E402
from traffic.v1 import ingest_pb2_grpc as ig  # noqa: E402

from capture_tools.android.adb import AdbClient, nflog_rules  # noqa: E402
from capture_tools.android.frida_server import frida_device  # noqa: E402
from capture_tools.common.upload import SENTINEL, capture_chunks  # noqa: E402

_KEYLOG_SCRIPT = Path(__file__).resolve().parent / "frida_sslkeylog.js"


@dataclass
class CaptureResult:
    session_id: str
    flow_count: int
    secrets: int
    pcap_bytes: int


def _tcpdump_reader(stdout, q: "queue.Queue", stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            b = stdout.read(65536)
            if not b:
                break
            q.put(("pcap", b))
    except Exception:  # noqa: BLE001
        pass


def run_capture(
    adb: AdbClient,
    package: str,
    *,
    gateway: str = "127.0.0.1:8080",
    label: str | None = None,
    url: str | None = None,
    duration: float | None = None,
    extra_scripts: Sequence[Path | str] = (),
    nflog_group: int = 30,
    mark: int = 0x2A,
    attach: bool = False,
    stop_event: threading.Event | None = None,
    log: Callable[[str], None] = print,
) -> CaptureResult:
    """Capture `package`'s traffic until `duration` elapses, `stop_event` is set, or
    Ctrl-C. Extra Frida scripts (e.g. SSL-unpinning) load alongside the keylog hook."""
    label = label or package
    uid = adb.app_uid(package)
    scripts = [_KEYLOG_SCRIPT.read_text()] + [Path(s).read_text() for s in extra_scripts]
    log(f"{package} uid={uid}  scripts={1 + len(extra_scripts)}")

    chan = grpc.insecure_channel(gateway)
    ing = ig.IngestServiceStub(chan)
    handle = ing.OpenSession(ip.OpenSessionRequest(
        label=label, source_kind=cp.SOURCE_KIND_ANDROID_EMULATOR))
    sid = handle.session_id
    max_chunk = handle.max_chunk_bytes or (1 << 20)
    log(f"session {sid}")

    q: "queue.Queue" = queue.Queue()
    stop = threading.Event()

    add_rules, teardown_rules = nflog_rules(uid, mark, nflog_group)
    for rule in add_rules:
        adb.shell(*rule)

    # On-device tcpdump on the app's NFLOG group; exec-out keeps stdout raw and the
    # device-side 2>/dev/null drops the "listening on …" banner (it would corrupt the pcap).
    tcpdump = subprocess.Popen(
        adb._base() + ["exec-out", "sh", "-c",
                       f"tcpdump -i nflog:{nflog_group} -U -s 0 -w - 2>/dev/null"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    rt = threading.Thread(target=_tcpdump_reader, args=(tcpdump.stdout, q, stop), daemon=True)
    rt.start()

    ack: dict = {}
    def upload():
        ack["ack"] = ing.UploadCapture(capture_chunks(sid, q, max_chunk, upload_id="android"))
    ut = threading.Thread(target=upload, daemon=True)
    ut.start()

    # Frida: hook the app's (and its <pkg>:child processes') TLS for the key.log.
    device = frida_device(adb.serial)
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
                log(f"[frida] {p.get('message')}")
        elif message.get("type") == "error":
            log(f"[frida-error] {message.get('description')}")

    def hook(pid: int) -> None:
        if pid in hooked:
            return
        hooked.add(pid)
        s = device.attach(pid)
        for src in scripts:
            sc = s.create_script(src)
            sc.on("message", on_message)
            sc.load()
            sessions.append((s, sc))

    def belongs(name: str) -> bool:
        return name == package or name.startswith(package + ":")

    pid = None
    if attach:
        hook(device.get_process(package).pid)
    else:
        pid = device.spawn([package])
        hook(pid)  # hook the main process before it runs
        device.resume(pid)
    if url:
        time.sleep(1.0)
        adb.shell("am", "start", "-a", "android.intent.action.VIEW", "-d", url, package)

    def watch_children() -> None:
        while not stop.is_set():
            try:
                for p in device.enumerate_processes():
                    if belongs(p.name):
                        hook(p.pid)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.5)
    threading.Thread(target=watch_children, daemon=True).start()

    log(f"capturing {package}" + (f" (auto-stop in {duration:g}s)" if duration else " (Ctrl-C to stop)"))
    try:
        deadline = (time.monotonic() + duration) if duration else None
        while True:
            if deadline and time.monotonic() >= deadline:
                break
            if stop_event and stop_event.is_set():
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if pid is not None:
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
        a = ack.get("ack")
        pcap_bytes = a.pcap_received if a else 0
        if a:
            log(f"uploaded pcap={a.pcap_received}B keylog={a.keylog_received}B ({keys['n']} secrets)")
        summary = ing.CloseSession(ip.CloseSessionRequest(session_id=sid))
        log(f"closed session {sid}: {summary.session.flow_count} flows")
        return CaptureResult(sid, summary.session.flow_count, keys["n"], pcap_bytes)
