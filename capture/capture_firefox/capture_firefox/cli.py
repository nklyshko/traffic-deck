"""Firefox live-capture tool.

Launches Firefox with a dedicated `SSLKEYLOGFILE` + fresh profile, captures packets
with dumpcap, and streams the pcap + key.log to the gateway over gRPC in
STREAMING_LIVE mode. Decryptable (Firefox-only) flows appear live in the viewer.

Capture is interface-wide; only Firefox's TLS sessions have keys, so the decoded
view is effectively Firefox-only. Linux + macOS.

Run in a terminal with no arguments for the interactive flow: it lists the
discovered Firefox-family binaries to pick from (Firefox and its channels, LibreWolf,
Waterfox, Zen), then the profile to use — one of the browser's own registered profiles
(auto-discovered from its `profiles.ini` and launched with `-P`), the browser's own
default (launched with no profile flag), a fresh temp profile, or a named persistent
profile (pick an existing one or create a new one) under ~/.traffic-deck/firefox-profiles.
The pickers default to the previous run's choices (remembered under ~/.traffic-deck/state).
Flags override each step; `--no-prompt` (or a non-TTY stdin) skips the pickers and uses
auto-detected defaults (fresh temp profile), so it stays scriptable:

    trafficdeck-capture-firefox --no-prompt --label demo --url https://example.com

dumpcap needs capture permission (Linux: the `wireshark` group — the capture-firefox.sh
launcher activates it via `sg`; macOS: Wireshark's ChmodBPF).
"""

from __future__ import annotations

import argparse
import os
import sys

from capture_firefox import platform, profiles
from capture_firefox.capture import FirefoxCapture, profile_desc
from capture_firefox.profiles import BUILTIN_PROFILE
from capture_sdk import dumpcap, prompt, snap, terminal
from capture_sdk.shutdown import GracefulInterrupt
from capture_sdk.state import Store


# --- interactive prompts -------------------------------------------------

def _pick_firefox(store: Store) -> str:
    """Step 1: show discovered Firefox-family binaries and pick one."""
    bins = platform.firefox_binaries()
    if not bins:
        print("no Firefox found on PATH")
        return store.remember("firefox", prompt.text("Firefox binary path"))
    default = store.get_valid("firefox", bins)
    choice = prompt.select("Firefox to use:", bins + [("custom path…", "__custom__")],
                           default=default)
    firefox = prompt.text("Firefox binary path") if choice == "__custom__" else choice
    return store.remember("firefox", firefox)


def _pick_profile(firefox: str, store: Store):
    """Step 2: pick the profile. Returns one of: a (root, name) tuple for one of the
    browser's own registered profiles; a path string used as --profile (fresh temp or a
    named persistent profile under ~/.traffic-deck/firefox-profiles); or BUILTIN_PROFILE
    to launch with no profile flag (the browser's own default)."""
    discovered = platform.firefox_profiles(firefox)
    options = []
    if discovered:
        options.append(("existing profile of this browser", "existing"))
    options += [
        ("browser default profile", "default"),
        ("temporary new empty profile", "temp"),
        ("custom persistent profile (~/.traffic-deck/firefox-profiles)", "custom"),
    ]
    choice = prompt.select("Profile:", options,
                           default=store.get_valid("profile_kind", [v for _, v in options]))
    store.remember("profile_kind", choice)
    if choice == "existing":
        return _pick_existing_profile(firefox, discovered, store)
    if choice == "default":
        print(f"note: uses {os.path.basename(firefox)}'s own default profile — quit any "
              "running instance of it first, or no TLS keys are logged")
        return BUILTIN_PROFILE
    if choice == "temp":
        return profiles.temp_profile(firefox)
    return _pick_persistent_profile(firefox, store)


def _pick_existing_profile(firefox: str, discovered: list[tuple[str, str, str]], store: Store):
    """Pick one of the browser's own registered profiles; returns (root, name) to launch
    with -P."""
    choices = [(f"{name}  [{path}]", (root, name)) for root, name, path in discovered]
    choice = prompt.select("Existing profile:", choices,
                           default=store.get_valid("existing_profile", [v for _, v in choices]))
    store.remember("existing_profile", choice)
    print(f"note: uses {os.path.basename(firefox)}'s real profile — quit any running "
          "instance of it first, or no TLS keys are logged")
    return choice


def _pick_persistent_profile(firefox: str, store: Store) -> str:
    """Choose one of the saved persistent profiles, or create a new named one."""
    existing = profiles.saved_profiles(firefox)
    choice = prompt.select("Custom persistent profile:", existing + [("＋ create new…", "__new__")],
                           default=store.get_valid("profile_name", existing))
    if choice == "__new__":
        name = prompt.text("New profile name", store.get("profile_name") or "default")
    else:
        name = choice
    store.remember("profile_name", name)
    return profiles.persistent_path(firefox, name)


def main(argv=None) -> None:
    # serve mode: run as a CaptureSourceService the gateway dials (ADR-0010). Split off
    # before argparse so the capture flags don't apply.
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "serve":
        return _serve(argv[1:])
    return _capture(argv)


def _serve(argv) -> None:
    from capture_firefox.source import FirefoxSource
    from capture_sdk import source as harness

    ap = argparse.ArgumentParser(prog="capture-firefox serve",
                                 description="Serve Firefox as a CaptureSourceService")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--control", default=os.environ.get("TRAFFICDECK_CONTROL_ADDR", "127.0.0.1:0"),
                    help="address to serve CaptureSourceService on (host:port; :0 auto-assigns)")
    args = ap.parse_args(argv)
    harness.serve_forever(FirefoxSource(args.gateway), args.control)


def _capture(argv) -> None:
    ap = argparse.ArgumentParser(description="Stream a live Firefox capture to the gateway")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--label", default="firefox")
    ap.add_argument("--iface", default=None, help="capture interface (default: auto)")
    ap.add_argument("--filter", default="",
                    help="dumpcap capture filter (BPF). Default empty = capture everything "
                         "(so proxies, non-standard ports, and HTTP/3 are all included; the "
                         "decode only surfaces Firefox-decryptable + plaintext HTTP flows). "
                         "Narrow it (e.g. 'tcp port 443') for smaller captures.")
    ap.add_argument("--url", default=None, help="URL to open")
    ap.add_argument("--firefox", default=None,
                    help="Firefox binary (default: auto-detect, or pick when interactive)")
    ap.add_argument("--profile-dir", default=None,
                    help="profile directory to launch (--profile; default: a fresh temp "
                         "profile, or pick when interactive). Quit any running Firefox on "
                         "this profile first, or it refuses to start.")
    ap.add_argument("--profile-name", default=None,
                    help="one of the browser's own registered profiles, by name (-P), as "
                         "listed in its profiles.ini")
    ap.add_argument("--default-profile", action="store_true",
                    help="use the browser's own default profile (launch with no profile flag)")
    ap.add_argument("--no-prompt", action="store_true",
                    help="skip the interactive Firefox/profile pickers (use defaults)")
    ap.add_argument("--duration", type=float, default=None,
                    help="auto-stop after N seconds (default: run until Firefox is closed)")
    ap.add_argument("firefox_args", nargs=argparse.REMAINDER,
                    help="extra Firefox flags after --")
    args = ap.parse_args(argv)

    # Interactive by default in a terminal: pick the Firefox binary and profile unless
    # they were given as flags (or prompting was disabled / there's no TTY). The pickers
    # default to the previous run's choices, remembered under ~/.traffic-deck/state.
    interactive = not args.no_prompt and sys.stdin.isatty()
    store = Store("firefox")
    firefox = args.firefox or os.environ.get("FIREFOX_BIN")
    if not firefox:
        firefox = _pick_firefox(store) if interactive else platform.firefox_binary()
    # profile is a path (→ --profile), a (root, name) tuple for one of the browser's own
    # registered profiles (→ -P), or BUILTIN_PROFILE (no flag → the browser's own default).
    if args.default_profile:
        profile = BUILTIN_PROFILE
    elif args.profile_name:
        profile = profiles.resolve_existing(firefox, args.profile_name)
    elif args.profile_dir:
        profile = args.profile_dir
    elif interactive:
        profile = _pick_profile(firefox, store)
    else:
        profile = profiles.temp_profile(firefox)

    iface = args.iface or dumpcap.default_interface()
    # A snap-confined browser has a private /tmp and can't write outside its own writable
    # area, so the keylog (and any tool-managed profile) must go under ~/snap/<name>/common
    # or the TLS keys never reach us and nothing decodes.
    if snap_name := snap.name(firefox):
        print(f"note: {os.path.basename(firefox)} is the '{snap_name}' snap — keeping keylog/profile "
              f"under ~/snap/{snap_name}/common so confinement doesn't swallow the TLS keys",
              flush=True)

    cap = FirefoxCapture(
        gateway=args.gateway, label=args.label, firefox=firefox, profile=profile,
        iface=iface, capture_filter=args.filter, url=args.url, duration=args.duration,
        extra_args=args.firefox_args)
    sid = cap.start()
    print(f"session {sid}  iface={iface}  profile={profile_desc(profile)}  keylog={cap.keylog}",
          flush=True)

    # A preceding questionary picker may have left the tty raw on a CPR-less terminal,
    # where ^C is a literal byte not SIGINT — restore it so Ctrl-C reaches the capture.
    terminal.restore()
    if args.duration:
        print(f"launching Firefox (auto-stop in {args.duration:g}s; Ctrl-C to stop early) …",
              flush=True)
    else:
        print("launching Firefox (close it or press Ctrl-C to finish capture) …", flush=True)
    # First Ctrl-C stops the capture and closes the session; a second aborts the upload
    # drain (Firefox + dumpcap are already stopped by then, so nothing keeps recording).
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
