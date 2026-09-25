"""Chrome per-process live-capture tool for macOS (PKTAP).

Records only the browser's own packets instead of the whole interface, so a short Chrome
session produces a bundle sized like the session rather than like the machine's traffic.
Needs root — PKTAP creates its interface with a privileged ioctl — so run it under `sudo`;
it launches the browser as *you*, never as root.

Two ways to run it:

`serve` is the one to use. Start it once and leave it up; it speaks CaptureSourceService,
and a `[control]`-only manifest in ~/.traffic-deck/plugins/ makes the gateway dial it, so
captures start and stop from the TUI or a web UI with no further prompting:

    sudo trafficdeck-capture-pktap serve --control 127.0.0.1:7071

With no arguments it runs one capture directly, with the same interactive Chrome/profile
pickers as `trafficdeck-capture-chrome`:

    sudo trafficdeck-capture-pktap --label demo --url https://example.com

Enable Touch ID for sudo (uncomment `pam_tid.so` in /etc/pam.d/sudo_local, from the
template beside it) and the one prompt becomes one fingerprint.
"""

from __future__ import annotations

import argparse
import os
import sys

from capture_chrome import platform, profiles
from capture_chrome.capture import AlreadyRunning, profile_desc
# The pickers are capture-chrome's, reused as-is: same browsers, same profiles, same
# remembered defaults, so the two tools can't drift on what they offer.
from capture_chrome.cli import _pick_chrome, _pick_profile
from capture_sdk import dumpcap, terminal
from capture_sdk.shutdown import GracefulInterrupt
from capture_sdk.state import Store

from capture_pktap import pktap, privdrop
from capture_pktap.capture import PktapCapture


def _require_macos() -> None:
    if sys.platform != "darwin":
        sys.exit("error: PKTAP is macOS-only — use trafficdeck-capture-chrome, or the "
                 "android source's nflog capture for per-app capture on Linux")


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    _require_macos()
    if argv and argv[0] == "serve":
        return _serve(argv[1:])
    return _capture(argv)


def _serve(argv) -> None:
    from capture_sdk import source as harness

    from capture_pktap.source import PktapSource

    ap = argparse.ArgumentParser(prog="capture-pktap serve",
                                 description="Serve macOS per-process capture as a CaptureSourceService")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--control", default=os.environ.get("TRAFFICDECK_CONTROL_ADDR", "127.0.0.1:7071"),
                    help="address to serve CaptureSourceService on; must match the addr in "
                         "the module manifest the gateway dials (host:port)")
    ap.add_argument("--tcpdump", default=None, help="tcpdump binary (default: /usr/sbin/tcpdump)")
    args = ap.parse_args(argv)

    run_as = privdrop.invoking_user()
    privdrop.adopt_user_home(run_as)
    if run_as is None:
        print("warning: not running as root — pktap capture will fail; re-run under sudo",
              file=sys.stderr, flush=True)
    harness.serve_forever(PktapSource(args.gateway, run_as, args.tcpdump), args.control)


def _capture(argv) -> None:
    ap = argparse.ArgumentParser(
        description="Stream a live Chrome capture to the gateway, recording only Chrome's packets")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--label", default="chrome-pktap")
    ap.add_argument("--iface", default=None, help="capture interface (default: auto)")
    ap.add_argument("--url", default=None, help="URL to open")
    ap.add_argument("--chrome", default=None,
                    help="Chrome/Chromium binary (default: auto-detect, or pick when interactive)")
    ap.add_argument("--profile-dir", default=None, help="Chrome user-data-dir")
    ap.add_argument("--profile-directory", default=None,
                    help="profile within --profile-dir to launch (e.g. 'Profile 1')")
    ap.add_argument("--default-profile", action="store_true",
                    help="use the browser's own default profile")
    ap.add_argument("--no-prompt", action="store_true",
                    help="skip the interactive Chrome/profile pickers (use defaults)")
    ap.add_argument("--duration", type=float, default=None,
                    help="auto-stop after N seconds (default: run until Chrome is closed)")
    ap.add_argument("--tcpdump", default=None, help="tcpdump binary (default: /usr/sbin/tcpdump)")
    ap.add_argument("chrome_args", nargs=argparse.REMAINDER, help="extra Chrome flags after --")
    args = ap.parse_args(argv)

    run_as = privdrop.invoking_user()
    privdrop.adopt_user_home(run_as)
    if run_as is None:
        sys.exit("error: PKTAP needs root to create its capture interface — re-run under sudo")

    # Everything below resolves paths in the user's home and may create dirs there, so it
    # runs as them; only the capture itself needs the privilege we're holding.
    with privdrop.as_user(run_as):
        interactive = not args.no_prompt and sys.stdin.isatty()
        store = Store("chrome")  # shared with capture-chrome: same browser, same choices
        chrome = args.chrome or os.environ.get("CHROME_BIN")
        if not chrome:
            chrome = _pick_chrome(store) if interactive else platform.chrome_binary()
        if args.default_profile:
            profile = profiles.BUILTIN_PROFILE
        elif args.profile_dir:
            profile = (args.profile_dir, args.profile_directory) if args.profile_directory \
                else args.profile_dir
        elif interactive:
            profile = _pick_profile(chrome, store)
        else:
            profile = profiles.temp_profile(chrome)

    iface = args.iface or dumpcap.default_interface()
    cap = PktapCapture(gateway=args.gateway, label=args.label, chrome=chrome, profile=profile,
                       iface=iface, url=args.url, duration=args.duration,
                       run_as=run_as, tcpdump=args.tcpdump, extra_args=args.chrome_args)
    try:
        sid = cap.start()
    except AlreadyRunning as e:
        sys.exit(f"error: {e}")
    print(f"session {sid}  iface={iface}  profile={profile_desc(profile)}  "
          f"proc={cap.proc_name!r}  keylog={cap.keylog}", flush=True)

    terminal.restore()
    if args.duration:
        print(f"launching Chrome (auto-stop in {args.duration:g}s; Ctrl-C to stop early) …",
              flush=True)
    else:
        print("launching Chrome (close it or press Ctrl-C to finish capture) …", flush=True)
    try:
        with GracefulInterrupt() as interrupt:
            try:
                cap.wait(interrupt.event)
            finally:
                try:
                    ack, summary = cap.stop()
                    if ack:
                        print(f"uploaded pcap={ack.pcap_received}B keylog={ack.keylog_received}B",
                              flush=True)
                    if summary:
                        print(f"closed session {sid}: {summary.session.flow_count} flows", flush=True)
                except KeyboardInterrupt:
                    print("aborted — session left open (gateway closes it on timeout)", flush=True)
                    raise
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
