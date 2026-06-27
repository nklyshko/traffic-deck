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
from pathlib import Path

from capture_sdk.state import Store


def main() -> None:
    # Proxy settings default to the previous run's, remembered under
    # ~/.traffic-deck/state/mitmproxy.json; passing a flag updates the remembered value.
    store = Store("mitmproxy")
    ap = argparse.ArgumentParser(prog="trafficdeck-capture-mitmproxy")
    ap.add_argument("--mode", default=store.get("mode", "regular"),
                    help="mitmproxy mode: regular | wireguard | transparent | local | ... (default regular)")
    ap.add_argument("--label", default="mitmproxy", help="session label shown in the viewer")
    ap.add_argument("--listen-port", type=int, default=store.get("listen_port", 8888),
                    help="proxy/server listen port (default 8888)")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"),
                    help="gateway address (default 127.0.0.1:8080)")
    ap.add_argument("passthrough", nargs="*",
                    help="extra args forwarded to mitmdump (use `--` to separate)")
    args = ap.parse_args()
    store.remember("mode", args.mode)
    store.remember("listen_port", args.listen_port)

    addon = Path(__file__).resolve().parent / "addon.py"
    cmd = ["mitmdump", "-s", str(addon), "--mode", args.mode,
           "--listen-port", str(args.listen_port)]
    cmd += args.passthrough

    env = dict(os.environ, GATEWAY_ADDR=args.gateway, CAPTURE_LABEL=args.label)
    os.execvpe(cmd[0], cmd, env)


if __name__ == "__main__":
    main()
