"""Launcher for the mitmproxy capture agent.

Runs `mitmdump` with the gateway-push addon loaded. mitmproxy terminates TLS and the
addon streams decoded flows to the gateway (IngestService.PushFlows) — no pcap/keylog.

  # regular HTTP proxy on :8888 (set device/app proxy to this host:8888)
  trafficdeck-capture-mitmproxy --label "api poke"

  # WireGuard server — any device that can be a WireGuard client routes through it
  trafficdeck-capture-mitmproxy --mode wireguard --label phone

mitmproxy prints its own setup hints (proxy address / WireGuard peer config). The
device must trust mitmproxy's CA to decrypt HTTPS (mitm.it once connected, or install
~/.mitmproxy/mitmproxy-ca-cert.*). Extra mitmdump args pass through after `--`.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path

from capture_sdk import prompt
from capture_sdk.state import Store

# The two modes offered by the interactive selector (label shown, value passed to mitmdump).
# --mode still accepts any mitmproxy mode (transparent, local, ...) for power users.
_MODE_CHOICES = [
    ("Regular — set the device/app HTTP(S) proxy to this host", "regular"),
    ("WireGuard — device connects as a WireGuard peer (no proxy config)", "wireguard"),
]


def _choose_mode(store: Store) -> str:
    """Return the mitmproxy mode: the last-used one is the default. Interactive arrow-key
    selector when attached to a terminal; otherwise fall back to the remembered value."""
    remembered = store.get("mode", "regular")
    if sys.stdin.isatty() and sys.stdout.isatty():
        return prompt.select("mitmproxy capture mode", _MODE_CHOICES, default=remembered)
    return remembered


def _lan_candidates() -> list[tuple[str, str]]:
    """Local IPv4 (ip, iface) pairs, physical LAN interfaces first — auto-detection is
    unreliable when a VPN/Docker owns the default route, so we let the user pick."""
    import socket

    import psutil

    cands = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                cands.append((a.address, name))
    cands.sort(key=_iface_rank)
    return cands


def _iface_rank(item: tuple[str, str]):
    """Sort key placing physical LAN interfaces first, virtual (docker/bridge/vmnet/VPN)
    last — so the default endpoint is the address a device on the LAN can reach."""
    ip, name = item
    virtual = name.startswith(("docker", "br-", "veth", "vmnet")) or "tun" in name or "tap" in name
    lan = ip.startswith("192.168.") or ip.startswith("10.")
    return (virtual, not lan, name)


def _choose_host(store: Store, override: str | None) -> str | None:
    """The address the device connects to (WireGuard Endpoint / bind host). An explicit
    --listen-host wins; otherwise pick interactively from the local interfaces (default:
    the last-used address, else the best-guess physical LAN interface)."""
    if override:
        return override
    cands = _lan_candidates()
    if not cands:
        return None
    values = [ip for ip, _ in cands]
    remembered = store.get("listen_host", "")
    default = remembered if remembered in values else values[0]
    if len(values) == 1 or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return default
    choices = [(f"{ip}  ({iface})", ip) for ip, iface in cands]
    return prompt.select(
        "WireGuard endpoint — the address your device connects to", choices, default=default)


def main() -> None:
    # serve mode: run as a CaptureSourceService the gateway dials (ADR-0010).
    argv = sys.argv[1:]
    if argv and argv[0] == "serve":
        return _serve(argv[1:])
    return _interactive()


def _serve(argv) -> None:
    from capture_mitmproxy.source import MitmproxySource
    from capture_sdk import source as harness

    ap = argparse.ArgumentParser(prog="capture-mitmproxy serve",
                                 description="Serve mitmproxy as a CaptureSourceService")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--control", default=os.environ.get("TRAFFICDECK_CONTROL_ADDR", "127.0.0.1:0"),
                    help="address to serve CaptureSourceService on (host:port; :0 auto-assigns)")
    args = ap.parse_args(argv)
    harness.serve_forever(MitmproxySource(args.gateway), args.control)


def _interactive() -> None:
    # Proxy settings default to the previous run's, remembered under
    # ~/.traffic-deck/state/mitmproxy.json; passing a flag updates the remembered value.
    store = Store("mitmproxy")
    ap = argparse.ArgumentParser(prog="trafficdeck-capture-mitmproxy")
    ap.add_argument("--mode", default=None,
                    help="mitmproxy mode: regular | wireguard | transparent | local | ...; "
                         "omit to choose regular/wireguard interactively")
    ap.add_argument("--label", default="mitmproxy", help="session label shown in the viewer")
    ap.add_argument("--listen-port", type=int, default=store.get("listen_port", 8888),
                    help="proxy/server listen port (default 8888)")
    ap.add_argument("--listen-host", default=None,
                    help="bind/endpoint address; in wireguard mode this is what the device "
                         "connects to (omit to choose interactively from local interfaces)")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"),
                    help="gateway address (default 127.0.0.1:7331)")
    ap.add_argument("passthrough", nargs="*",
                    help="extra args forwarded to mitmdump (use `--` to separate)")
    args = ap.parse_args()

    # --mode given → use it verbatim; otherwise pick interactively (or the remembered value).
    args.mode = args.mode or _choose_mode(store)
    store.remember("mode", args.mode)
    store.remember("listen_port", args.listen_port)

    addon = Path(__file__).resolve().parent / "addon.py"
    cmd = ["mitmdump", "-s", str(addon), "--mode", args.mode,
           "--listen-port", str(args.listen_port)]
    if args.mode == "wireguard":
        # Auto-detection picks the wrong interface when a VPN/Docker owns the default route,
        # so choose the endpoint address (and bind the WireGuard server to it).
        host = _choose_host(store, args.listen_host)
        if host:
            store.remember("listen_host", host)
            cmd += ["--listen-host", host]
    elif args.listen_host:
        cmd += ["--listen-host", args.listen_host]
    cmd += args.passthrough

    env = dict(os.environ, GATEWAY_ADDR=args.gateway, CAPTURE_LABEL=args.label)

    if args.mode == "wireguard":
        # mitmproxy logs the WireGuard client config on startup; run it as a child so we can
        # tee that output and also render it as a scannable QR code.
        sys.exit(_run_with_qr(cmd, env))
    os.execvpe(cmd[0], cmd, env)


def _run_with_qr(cmd: list[str], env: dict) -> int:
    """Run mitmdump, streaming its output, and render the WireGuard client config it prints
    as a QR code. The child runs in its own session so a terminal Ctrl-C reaches only us; we
    forward one SIGINT for a graceful shutdown."""
    # PYTHONUNBUFFERED so mitmdump flushes to the pipe live (not only on exit).
    proc = subprocess.Popen(
        cmd, env={**env, "PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)

    def forward(_sig, _frame):
        try:
            proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGTERM, forward)

    scanner = _WGConfigScanner()
    assert proc.stdout is not None
    # readline (not `for line in proc.stdout`) — the iterator's read-ahead buffer would
    # hold lines back until it fills, so nothing would appear until the child exits.
    for line in iter(proc.stdout.readline, ""):
        sys.stdout.write(line)
        sys.stdout.flush()
        if scanner.config is None and scanner.feed(line):
            _print_qr(scanner.config)
    return proc.wait()


class _WGConfigScanner:
    """Extracts the WireGuard client config block ([Interface]…Endpoint) from mitmproxy's
    streamed log output, tolerating any log prefix on the delimiter/first line."""

    def __init__(self) -> None:
        self._lines: list[str] = []
        self._capturing = False
        self.config: str | None = None

    def feed(self, line: str) -> bool:
        """Feed one output line; returns True on the line that completes the config."""
        if self.config is not None:
            return False
        if "[Interface]" in line:
            self._capturing = True
            self._lines = [line[line.index("[Interface]"):].rstrip("\n")]
        elif self._capturing:
            self._lines.append(line.rstrip("\n"))
            if line.lstrip().startswith("Endpoint"):  # last line of the config
                self.config = "\n".join(self._lines)
                return True
        return False


def _print_qr(config: str) -> None:
    """Render a WireGuard client config as a terminal QR code (scannable by the WireGuard
    mobile app). Best-effort: on any failure the config text (already printed) is enough."""
    try:
        import segno
        print("\nScan with the WireGuard app to add this tunnel:\n", flush=True)
        segno.make(config, error="l").terminal(compact=True)
        print(flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"(QR render failed: {exc}; use the config text above)", flush=True)


if __name__ == "__main__":
    main()
