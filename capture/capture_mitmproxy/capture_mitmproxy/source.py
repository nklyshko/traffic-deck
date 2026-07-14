"""mitmproxy as a CaptureSourceService the gateway dials (ADR-0010).

Unlike the packet sources, mitmproxy is a *flow* source: it terminates TLS and its addon
pushes already-decoded flows (IngestService.PushFlows). Each capture is one `mitmdump` run
— the proxy is up while capturing and stops when the capture stops — so the source is
transient (keep_warm stays False), like Chrome. There is no device to provision; Describe
just offers the proxy options (mode, port, bind host).
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from pathlib import Path
from typing import Mapping

from capture_sdk import source
from capture_sdk.proto import control_pb2 as ctl

_ADDON = str(Path(__file__).resolve().parent / "addon.py")


class MitmproxySource(source.CaptureSource):
    """A transient mitmproxy source: each StartCapture runs one mitmdump; StopCapture stops
    it (its addon closes the session)."""

    def __init__(self, gateway: str) -> None:
        super().__init__()
        self._gateway = gateway
        self._caps: dict[str, subprocess.Popen] = {}  # session id -> mitmdump process
        self._lock = threading.Lock()

    def describe(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        return source.descriptor([
            source.param("mode", "Proxy mode", source.CHOICE, default=params.get("mode") or "regular",
                         choices=[source.choice("regular", "Regular HTTP proxy"),
                                  source.choice("wireguard", "WireGuard server"),
                                  source.choice("transparent", "Transparent"),
                                  source.choice("local", "Local (this host's traffic)")]),
            source.param("listen_port", "Listen port", source.INT, default="8888"),
            source.param("listen_host", "Bind / endpoint host (for WireGuard)", source.STRING),
        ], message="Point the device's proxy (or WireGuard) at this host; trust mitmproxy's CA.")

    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        mode = params.get("mode") or "regular"
        cmd = ["mitmdump", "-s", _ADDON, "--mode", mode,
               "--listen-port", params.get("listen_port") or "8888"]
        if params.get("listen_host"):
            cmd += ["--listen-host", params["listen_host"]]
        env = dict(os.environ, GATEWAY_ADDR=self._gateway,
                   CAPTURE_LABEL=label or "mitmproxy", PYTHONUNBUFFERED="1")

        proc = self._spawn(cmd, env)
        sid = self._read_session(proc)
        with self._lock:
            self._caps[sid] = proc
        threading.Thread(target=self._watch, args=(sid, proc), daemon=True).start()
        return sid

    def _spawn(self, cmd, env) -> subprocess.Popen:
        # own process group so a stop (SIGINT) reaches mitmdump for a graceful close.
        return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, start_new_session=True)

    def _read_session(self, proc: subprocess.Popen) -> str:
        """Read mitmdump's output until the addon prints its session id (SESSION <id>)."""
        for line in proc.stdout:
            if line.startswith("SESSION "):
                return line[len("SESSION "):].strip()
        raise RuntimeError("mitmdump exited before opening a session (port in use? bad mode?)")

    def _watch(self, sid: str, proc: subprocess.Popen) -> None:
        # Drain output so the pipe never fills; when mitmdump exits, drop the session.
        for _ in proc.stdout:
            pass
        with self._lock:
            self._caps.pop(sid, None)
        self.session_ended(sid)

    def stop_capture(self, session_id: str) -> None:
        with self._lock:
            proc = self._caps.pop(session_id, None)
        if proc is None or proc.poll() is not None:
            return
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGINT)  # graceful: addon closes the session
        except ProcessLookupError:
            return
        # Wait for mitmdump to actually exit before returning, so its proxy port is free for
        # the next capture — otherwise a start-right-after-stop races the port and fails to
        # bind. Escalate to SIGKILL if the graceful shutdown hangs.
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
