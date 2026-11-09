"""Non-interactive Android capture.

Thin flag-based entry over the library (adb + frida_server + capture). For a guided
flow (pick target / emulator setup / app / scripts) run `trafficdeck-capture-android` instead.

  uv run --project capture/capture_android python -m capture_android.headless \\
      --package com.example.app --url https://example.com --duration 20 \\
      --script unpinning.js
"""

from __future__ import annotations

import argparse
import os
import sys

from capture_android.adb import AdbClient
from capture_android.chromeproxy import run_proxy_capture


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Per-app Android capture → gateway")
    ap.add_argument("--package", required=True, help="target app package name")
    ap.add_argument("--method", choices=("frida", "proxy"), default="frida",
                    help="frida: per-app pcap + TLS keylog (needs root). "
                         "proxy: route a Chromium browser through mitmproxy (no root, "
                         "no keylog — the only way to decrypt Chrome)")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--label", default=None, help="session label (default: the package)")
    ap.add_argument("--url", default=None, help="open this URL in the app after launch")
    ap.add_argument("--duration", type=float, default=None, help="auto-stop after N seconds")
    ap.add_argument("--serial", default=None, help="adb device serial (default: the only device)")
    ap.add_argument("--script", action="append", default=[], metavar="FILE",
                    help="extra Frida script to load (repeatable; e.g. SSL-unpinning)")
    ap.add_argument("--nflog-group", type=int, default=30)
    ap.add_argument("--mark", type=lambda s: int(s, 0), default=0x2A)
    ap.add_argument("--attach", action="store_true",
                    help="attach to the running app instead of spawning it")
    args = ap.parse_args(argv)

    adb = AdbClient(serial=args.serial)
    # A supervisor (the serve-mode source) parses this line to learn the session id while
    # the capture runs; harmless noise for a human.
    on_session = lambda sid: print(f"SESSION {sid}", flush=True)
    try:
        if args.method == "proxy":
            # No root, no frida-server: the browser connects out through mitmproxy, so
            # ensure_target_ready's elevation is not needed (and not wanted — this path is
            # the one that works on a stock device).
            run_proxy_capture(adb, args.package, gateway=args.gateway, label=args.label,
                              url=args.url, duration=args.duration, on_session=on_session)
            return
        # Imported here because both import frida, which the proxy method runs without.
        from capture_android.capture import run_capture
        from capture_android.frida_server import ensure_target_ready

        ensure_target_ready(adb)
        run_capture(adb, args.package, gateway=args.gateway, label=args.label, url=args.url,
                    duration=args.duration, extra_scripts=args.script,
                    nflog_group=args.nflog_group, mark=args.mark, attach=args.attach,
                    on_session=on_session)
    except KeyboardInterrupt:  # second Ctrl-C — abort without a traceback
        sys.exit(130)


if __name__ == "__main__":
    main()
