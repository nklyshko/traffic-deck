"""The dumpcap + `SSLKEYLOGFILE` capture engine, shared by the tools that launch a
TLS-key-logging program and record the interface it talks on.

[KeylogCapture][capture_sdk.livecapture.KeylogCapture] owns one capture's machinery: open
a gateway session, start dumpcap, launch the program, stream the pcap + key.log over
`UploadCapture`, and tear it all down on stop. A tool subclasses it and implements
[launch][capture_sdk.livecapture.KeylogCapture.launch] — the only genuinely
program-specific step (Chrome takes a `--ssl-key-log-file` flag, Firefox reads the
`SSLKEYLOGFILE` environment variable, and each has its own profile flags).

It is split start / wait / stop so a CLI can block on it (until the program exits) while
a serve-mode source starts it, returns the session id, and lets it run in the background.
"""

from __future__ import annotations

import abc
import os
import queue
import subprocess
import tempfile
import threading
import time

import grpc

from capture_sdk import dumpcap as dumpcap_mod
from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip
from capture_sdk.proto import ingest_pb2_grpc as ig
from capture_sdk.upload import SENTINEL, capture_chunks
from capture_sdk.viewer import PCAP_VIEWER_COLUMNS, VIEWER_COLUMNS_KEY


def wait_for_stop(proc: subprocess.Popen, duration: float | None, stop: threading.Event) -> None:
    """Block until `proc` exits, `duration` elapses, or a stop is requested. Polls so the
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


class KeylogCapture(abc.ABC):
    """One live pcap + key.log capture. `start` opens the session and launches everything
    (returns the session id, non-blocking); `wait` blocks until the launched program exits /
    the duration elapses / stop is requested; `stop` tears down and closes the session
    (idempotent).

    Every capture of this kind is `SOURCE_SHAPE_PCAP` by construction — it streams packets
    for the gateway to decode — so subclasses declare only their `name`."""

    #: The tool's own name, recorded as the session's provenance and used to name this
    #: capture's upload stream and its keylog tempdir.
    name: str = "capture"

    #: (uid, gid) to run the launched program as, when the capture itself needs privilege
    #: the program must not inherit — macOS pktap needs root, but a browser launched as
    #: root would use root's home and profile. None (the default) launches as we are.
    run_as: tuple[int, int] | None = None

    def __init__(self, *, gateway: str, label: str, iface: str | None = None,
                 dumpcap: str | None = None, capture_filter: str = "",
                 duration: float | None = None, keylog_dir: str | None = None) -> None:
        self.gateway = gateway
        self.label = label
        self.iface = iface
        self.dumpcap = dumpcap
        self.capture_filter = capture_filter
        self.duration = duration
        self.keylog_dir = keylog_dir

        self.session_id: str | None = None
        self.keylog: str | None = None
        self._stop = threading.Event()
        self._q: queue.Queue = queue.Queue()
        self._ack: dict = {}
        self._stopped = False
        self._teardown_lock = threading.Lock()

    # --- implement this ------------------------------------------------------

    @abc.abstractmethod
    def launch(self, keylog: str) -> subprocess.Popen:
        """Start the program under capture, making it write its TLS secrets to `keylog`.
        Called once the capture is recording, so nothing is missed."""

    def capture_command(self, iface: str) -> list[str]:
        """The packet-capture command, streaming a pcap to stdout. The default records the
        whole interface with dumpcap; a source that captures more narrowly (macOS pktap,
        which filters by process) overrides this."""
        cmd = [self.dumpcap or dumpcap_mod.binary(), "-i", iface, "-P", "-w", "-", "-q"]
        if self.capture_filter:
            cmd += ["-f", self.capture_filter]  # no filter = capture everything
        return cmd

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> str:
        """Open the session, spawn dumpcap + upload threads, launch the program. Returns
        the session id while capture continues."""
        iface = self.iface or dumpcap_mod.default_interface()
        keydir = tempfile.mkdtemp(prefix=f"{self.name}-keylog-", dir=self.keylog_dir)
        if self.run_as:
            # The program writes the keylog as that user; we tail it as ourselves. mkdtemp
            # made it 0700 and ours, so hand it over or the secrets never get written.
            os.chown(keydir, *self.run_as)
        self.keylog = os.path.join(keydir, "key.log")

        self._chan = grpc.insecure_channel(self.gateway)
        self._ing = ig.IngestServiceStub(self._chan)
        handle = self._ing.OpenSession(ip.OpenSessionRequest(
            label=self.label, source=self.name, shape=cp.SOURCE_SHAPE_PCAP,
            metadata={VIEWER_COLUMNS_KEY: PCAP_VIEWER_COLUMNS}))
        self.session_id = handle.session_id
        max_chunk = handle.max_chunk_bytes or (1 << 20)

        dump_cmd = self.capture_command(iface)
        # stderr is inherited, not discarded: it is the only place a capture backend
        # reports why it produced nothing (a bad filter, a device it cannot open, an
        # unsupported link type). Swallowing it turns every such failure into a silent
        # zero-byte capture. It lands in this source's own log when supervised.
        self._dump = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE)
        self._rt = threading.Thread(target=_reader_thread, args=(self._dump.stdout, self._q, self._stop), daemon=True)
        self._kt = threading.Thread(target=_keylog_thread, args=(self.keylog, self._q, self._stop), daemon=True)
        self._rt.start()
        self._kt.start()

        def upload():
            self._ack["ack"] = self._ing.UploadCapture(
                capture_chunks(self.session_id, self._q, max_chunk, upload_id=self.name))
        self._ut = threading.Thread(target=upload, daemon=True)
        self._ut.start()

        self._proc = self.launch(self.keylog)
        return self.session_id

    def wait(self, stop_event: threading.Event | None = None) -> None:
        """Block until the program exits, the duration elapses, or `stop_event` (or an
        internal request_stop) is set."""
        wait_for_stop(self._proc, self.duration, stop_event or self._stop)

    def request_stop(self) -> None:
        """Ask a `wait` in progress to return (without tearing down)."""
        self._stop.set()

    def stop(self) -> tuple:
        """Stop the program + dumpcap first (so nothing keeps recording), then drain the
        upload and close the session. Idempotent — safe to call from both the stop path and
        a watcher that saw the program exit. Returns (ack, summary), each possibly None."""
        with self._teardown_lock:
            if self._stopped:
                return self._ack.get("ack"), getattr(self, "_summary", None)
            self._stopped = True

        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._stop.set()
        self._dump.terminate()
        try:
            self._dump.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._dump.kill()
        self._rt.join(timeout=5)
        self._kt.join(timeout=5)
        self._q.put(SENTINEL)
        self._ut.join(timeout=30)
        ack = self._ack.get("ack")
        try:
            self._summary = self._ing.CloseSession(ip.CloseSessionRequest(session_id=self.session_id))
        finally:
            self._chan.close()
        return ack, self._summary
