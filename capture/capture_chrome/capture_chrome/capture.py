"""The Chrome capture runner, shared by the interactive CLI and serve mode.

`ChromeCapture` owns one capture's machinery: open a gateway session, launch dumpcap +
Chrome, stream the pcap + key.log over UploadCapture, and tear it all down on stop. It is
split start / wait / stop so the CLI can block on it (wait until Chrome closes) while the
serve-mode source starts it, returns the session id, and lets it run in the background.
"""

from __future__ import annotations

import os
import queue
import subprocess
import tempfile
import threading
import time

import grpc

from capture_chrome import platform, profiles
from capture_chrome.profiles import BUILTIN_PROFILE
from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip
from capture_sdk.proto import ingest_pb2_grpc as ig
from capture_sdk.viewer import PCAP_VIEWER_COLUMNS, VIEWER_COLUMNS_KEY

_SENTINEL = object()


def wait_for_stop(proc: subprocess.Popen, duration: float | None, stop: threading.Event) -> None:
    """Block until Chrome exits, `duration` elapses, or a stop is requested. Polls so the
    request is seen promptly without a handler having to raise — keeping teardown intact."""
    deadline = (time.monotonic() + duration) if duration else None
    while proc.poll() is None:
        if stop.is_set() or (deadline and time.monotonic() >= deadline):
            break
        time.sleep(0.2)


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


def profile_desc(profile) -> str:
    """Human description of a resolved profile, for logging."""
    if profile is BUILTIN_PROFILE:
        return "browser default"
    if isinstance(profile, tuple):
        return f"{profile[0]} [{profile[1]}]"
    return str(profile)


class ChromeCapture:
    """One live Chrome capture. `start` opens the session and launches everything (returns
    the session id, non-blocking); `wait` blocks until Chrome closes / duration elapses /
    stop is requested; `stop` tears down and closes the session (idempotent)."""

    def __init__(self, *, gateway: str, label: str, chrome: str, profile,
                 iface: str | None = None, dumpcap: str | None = None,
                 capture_filter: str = "", url: str | None = None,
                 duration: float | None = None, extra_args=()) -> None:
        self.gateway = gateway
        self.label = label
        self.chrome = chrome
        self.profile = profile
        self.iface = iface
        self.dumpcap = dumpcap
        self.capture_filter = capture_filter
        self.url = url
        self.duration = duration
        self.extra_args = list(extra_args)

        self.session_id: str | None = None
        self.keylog: str | None = None
        self._stop = threading.Event()
        self._q: queue.Queue = queue.Queue()
        self._ack: dict = {}
        self._stopped = False
        self._teardown_lock = threading.Lock()

    def start(self) -> str:
        """Open the session, spawn dumpcap + upload threads, launch Chrome. Returns the
        session id while capture continues."""
        chrome = self.chrome
        iface = self.iface or platform.default_interface()
        dumpcap = self.dumpcap or platform.dumpcap_binary()
        self.keylog = os.path.join(
            tempfile.mkdtemp(prefix="chrome-keylog-", dir=profiles.snap_writable_base(chrome)),
            "key.log")

        self._chan = grpc.insecure_channel(self.gateway)
        self._ing = ig.IngestServiceStub(self._chan)
        handle = self._ing.OpenSession(ip.OpenSessionRequest(
            label=self.label, source_kind=cp.SOURCE_KIND_CHROME,
            metadata={VIEWER_COLUMNS_KEY: PCAP_VIEWER_COLUMNS}))
        self.session_id = handle.session_id
        max_chunk = handle.max_chunk_bytes or (1 << 20)

        dump_cmd = [dumpcap, "-i", iface, "-P", "-w", "-", "-q"]
        if self.capture_filter:
            dump_cmd += ["-f", self.capture_filter]  # no filter = capture everything
        self._dump = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self._rt = threading.Thread(target=_reader_thread, args=(self._dump.stdout, self._q, self._stop), daemon=True)
        self._kt = threading.Thread(target=_keylog_thread, args=(self.keylog, self._q, self._stop), daemon=True)
        self._rt.start()
        self._kt.start()

        def upload():
            self._ack["ack"] = self._ing.UploadCapture(_chunks(self.session_id, self._q, max_chunk))
        self._ut = threading.Thread(target=upload, daemon=True)
        self._ut.start()

        chrome_cmd = [
            chrome,
            f"--ssl-key-log-file={self.keylog}",
            "--no-first-run",
            "--no-default-browser-check",
            *[a for a in self.extra_args if a != "--"],
        ]
        # Pin a user-data-dir only for temp/explicit/persistent profiles; for the browser
        # default we pass nothing so each binary uses its own path. A tuple additionally
        # selects a specific profile within that dir via --profile-directory.
        if isinstance(self.profile, tuple):
            udd, profile_directory = self.profile
            chrome_cmd[2:2] = [f"--user-data-dir={udd}", f"--profile-directory={profile_directory}"]
        elif self.profile is not BUILTIN_PROFILE:
            chrome_cmd.insert(2, f"--user-data-dir={self.profile}")
        if self.url:
            chrome_cmd.append(self.url)
        self._chrome_proc = subprocess.Popen(chrome_cmd)
        return self.session_id

    def wait(self, stop_event: threading.Event | None = None) -> None:
        """Block until Chrome closes, the duration elapses, or `stop_event` (or an internal
        request_stop) is set."""
        wait_for_stop(self._chrome_proc, self.duration, stop_event or self._stop)

    def request_stop(self) -> None:
        """Ask a `wait` in progress to return (without tearing down)."""
        self._stop.set()

    def stop(self) -> tuple:
        """Stop Chrome + dumpcap first (so nothing keeps recording), then drain the upload
        and close the session. Idempotent — safe to call from both the stop path and a
        watcher that saw Chrome exit. Returns (ack, summary), each possibly None."""
        with self._teardown_lock:
            if self._stopped:
                return self._ack.get("ack"), getattr(self, "_summary", None)
            self._stopped = True

        if self._chrome_proc.poll() is None:
            self._chrome_proc.terminate()
            try:
                self._chrome_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._chrome_proc.kill()
        self._stop.set()
        self._dump.terminate()
        try:
            self._dump.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._dump.kill()
        self._rt.join(timeout=5)
        self._kt.join(timeout=5)
        self._q.put(_SENTINEL)
        self._ut.join(timeout=30)
        ack = self._ack.get("ack")
        try:
            self._summary = self._ing.CloseSession(ip.CloseSessionRequest(session_id=self.session_id))
        finally:
            self._chan.close()
        return ack, self._summary
