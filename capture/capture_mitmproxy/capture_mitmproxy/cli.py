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


def main() -> None:
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
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"),
                    help="gateway address (default 127.0.0.1:8080)")
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
    cmd += args.passthrough

    env = dict(os.environ, GATEWAY_ADDR=args.gateway, CAPTURE_LABEL=args.label)
    os.execvpe(cmd[0], cmd, env)


if __name__ == "__main__":
    main()
