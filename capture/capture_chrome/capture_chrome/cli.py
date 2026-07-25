"""Chrome live-capture tool.

Launches Chrome with a dedicated SSLKEYLOGFILE + fresh profile, captures packets
with dumpcap, and streams the pcap + key.log to the gateway over gRPC in
STREAMING_LIVE mode. Decryptable (Chrome-only) flows appear live in the viewer.

Capture is interface-wide; only Chrome's TLS sessions have keys, so the decoded
view is effectively Chrome-only. Linux + macOS.

Run in a terminal with no arguments for the interactive flow: it lists the
discovered Chrome/Chromium binaries to pick from, then the profile to use — one of
the browser's own existing profiles (auto-discovered from its Local State and
launched with --profile-directory), the browser's own default (launched with no
--user-data-dir, so each binary uses its own default path), a fresh temp profile,
or a named persistent profile (pick an existing one or create a new one) under
~/.traffic-deck/chrome-profiles. The pickers default to the previous run's choices
(remembered under ~/.traffic-deck/state). Flags override each step; `--no-prompt`
(or a non-TTY stdin) skips the pickers and uses auto-detected defaults (fresh temp
profile), so it stays scriptable:

    trafficdeck-capture-chrome --no-prompt --label demo --url https://example.com

dumpcap needs capture permission (Linux: the `wireshark` group — the capture-chrome.sh
launcher activates it via `sg`; macOS: Wireshark's ChmodBPF).
"""

from __future__ import annotations

import argparse
import os
import sys

from capture_chrome import platform, profiles
from capture_chrome.capture import ChromeCapture, profile_desc
from capture_chrome.profiles import BUILTIN_PROFILE
from capture_sdk import prompt, terminal
from capture_sdk.shutdown import GracefulInterrupt
from capture_sdk.state import Store


# --- interactive prompts -------------------------------------------------

def _pick_chrome(store: Store) -> str:
    """Step 1: show discovered Chrome/Chromium binaries and pick one."""
    bins = platform.chrome_binaries()
    if not bins:
        print("no Chrome/Chromium found on PATH")
        return store.remember("chrome", prompt.text("Chrome binary path"))
    default = store.get_valid("chrome", bins)
    choice = prompt.select("Chrome to use:", bins + [("custom path…", "__custom__")],
                           default=default)
    chrome = prompt.text("Chrome binary path") if choice == "__custom__" else choice
    return store.remember("chrome", chrome)


def _pick_profile(chrome: str, store: Store):
    """Step 2: pick the profile. Returns one of: a (user_data_dir, profile_directory)
    tuple for an existing profile of this browser; a path string used as --user-data-dir
    (fresh temp or a named persistent profile under ~/.traffic-deck/chrome-profiles); or
    BUILTIN_PROFILE to launch with no --user-data-dir (the browser's own default)."""
    discovered = platform.chrome_profiles(chrome)
    options = []
    if discovered:
        options.append(("existing profile of this browser", "existing"))
    options += [
        ("browser default profile", "default"),
        ("temporary new empty profile", "temp"),
        ("custom persistent profile (~/.traffic-deck/chrome-profiles)", "custom"),
    ]
    choice = prompt.select("Profile:", options,
                           default=store.get_valid("profile_kind", [v for _, v in options]))
    store.remember("profile_kind", choice)
    if choice == "existing":
        return _pick_existing_profile(chrome, discovered, store)
    if choice == "default":
        print(f"note: uses {os.path.basename(chrome)}'s own default profile — quit any "
              "running instance of it first, or no TLS keys are logged")
        return BUILTIN_PROFILE
    if choice == "temp":
        return profiles.temp_profile(chrome)
    return _pick_persistent_profile(chrome, store)


def _pick_existing_profile(chrome: str, discovered: list[tuple[str, str, str]], store: Store):
    """Pick one of the browser's own discovered profiles; returns (user_data_dir,
    profile_directory) to launch with --user-data-dir + --profile-directory."""
    choices = [(f"{label}  [{dirn}]", (udd, dirn)) for udd, dirn, label in discovered]
    choice = prompt.select("Existing profile:", choices,
                           default=store.get_valid("existing_profile", [v for _, v in choices]))
    store.remember("existing_profile", choice)
    print(f"note: uses {os.path.basename(chrome)}'s real profile — quit any running "
          "instance of it first, or no TLS keys are logged")
    return choice


def _pick_persistent_profile(chrome: str, store: Store) -> str:
    """Choose one of the saved persistent profiles, or create a new named one."""
    profiles_dir = profiles.profiles_dir(chrome)
    existing = sorted(d for d in os.listdir(profiles_dir)
                      if os.path.isdir(os.path.join(profiles_dir, d)))
    choice = prompt.select("Custom persistent profile:", existing + [("＋ create new…", "__new__")],
                           default=store.get_valid("profile_name", existing))
    if choice == "__new__":
        name = prompt.text("New profile name", store.get("profile_name") or "default")
    else:
        name = choice
    store.remember("profile_name", name)
    path = os.path.join(profiles_dir, name)
    os.makedirs(path, exist_ok=True)
    return path


def main(argv=None) -> None:
    # serve mode: run as a CaptureSourceService the gateway dials (ADR-0010). Split off
    # before argparse so the capture flags don't apply.
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "serve":
        return _serve(argv[1:])
    return _capture(argv)


def _serve(argv) -> None:
    from capture_chrome.source import ChromeSource
    from capture_sdk import source as harness

    ap = argparse.ArgumentParser(prog="capture-chrome serve",
                                 description="Serve Chrome as a CaptureSourceService")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--control", default=os.environ.get("TRAFFICDECK_CONTROL_ADDR", "127.0.0.1:0"),
                    help="address to serve CaptureSourceService on (host:port; :0 auto-assigns)")
    args = ap.parse_args(argv)
    harness.serve_forever(ChromeSource(args.gateway), args.control)


def _capture(argv) -> None:
    ap = argparse.ArgumentParser(description="Stream a live Chrome capture to the gateway")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    ap.add_argument("--label", default="chrome")
    ap.add_argument("--iface", default=None, help="capture interface (default: auto)")
    ap.add_argument("--filter", default="",
                    help="dumpcap capture filter (BPF). Default empty = capture everything "
                         "(so proxies, non-standard ports, and HTTP/3 are all included; the "
                         "decode only surfaces Chrome-decryptable + plaintext HTTP flows). "
                         "Narrow it (e.g. 'tcp port 443') for smaller captures.")
    ap.add_argument("--url", default=None, help="URL to open")
    ap.add_argument("--chrome", default=None,
                    help="Chrome/Chromium binary (default: auto-detect, or pick when interactive)")
    ap.add_argument("--profile-dir", default=None,
                    help="Chrome user-data-dir (default: a fresh temp profile, or pick when "
                         "interactive). Quit any running Chrome on this profile first, or the "
                         "launch attaches to it and no TLS keys are logged.")
    ap.add_argument("--profile-directory", default=None,
                    help="profile within --user-data-dir to launch (e.g. 'Profile 1'); "
                         "pairs with --profile-dir for a specific discovered profile")
    ap.add_argument("--default-profile", action="store_true",
                    help="use the browser's own default profile (launch with no --user-data-dir)")
    ap.add_argument("--no-prompt", action="store_true",
                    help="skip the interactive Chrome/profile pickers (use defaults)")
    ap.add_argument("--duration", type=float, default=None,
                    help="auto-stop after N seconds (default: run until Chrome is closed)")
    ap.add_argument("chrome_args", nargs=argparse.REMAINDER,
                    help="extra Chrome flags after --")
    args = ap.parse_args(argv)

    # Interactive by default in a terminal: pick the Chrome binary and profile unless
    # they were given as flags (or prompting was disabled / there's no TTY). The pickers
    # default to the previous run's choices, remembered under ~/.traffic-deck/state.
    interactive = not args.no_prompt and sys.stdin.isatty()
    store = Store("chrome")
    chrome = args.chrome or os.environ.get("CHROME_BIN")
    if not chrome:
        chrome = _pick_chrome(store) if interactive else platform.chrome_binary()
    # profile is a path (→ --user-data-dir), a (user_data_dir, profile_directory) tuple
    # for a specific profile, or BUILTIN_PROFILE (no flag → the browser's own default).
    if args.default_profile:
        profile = BUILTIN_PROFILE
    elif args.profile_dir:
        profile = (args.profile_dir, args.profile_directory) if args.profile_directory \
            else args.profile_dir
    elif interactive:
        profile = _pick_profile(chrome, store)
    else:
        profile = profiles.temp_profile(chrome)

    iface = args.iface or platform.default_interface()
    # A snap-confined browser has a private /tmp and can't write outside its own writable
    # area, so the keylog (and any tool-managed profile) must go under ~/snap/<name>/common
    # or the TLS keys never reach us and nothing decodes.
    snap = platform.snap_name(chrome)
    if snap:
        print(f"note: {os.path.basename(chrome)} is the '{snap}' snap — keeping keylog/profile "
              f"under ~/snap/{snap}/common so confinement doesn't swallow the TLS keys",
              flush=True)

    cap = ChromeCapture(
        gateway=args.gateway, label=args.label, chrome=chrome, profile=profile,
        iface=iface, capture_filter=args.filter, url=args.url, duration=args.duration,
        extra_args=args.chrome_args)
    sid = cap.start()
    print(f"session {sid}  iface={iface}  profile={profile_desc(profile)}  keylog={cap.keylog}",
          flush=True)

    # A preceding questionary picker may have left the tty raw on a CPR-less terminal,
    # where ^C is a literal byte not SIGINT — restore it so Ctrl-C reaches the capture.
    terminal.restore()
    if args.duration:
        print(f"launching Chrome (auto-stop in {args.duration:g}s; Ctrl-C to stop early) …",
              flush=True)
    else:
        print("launching Chrome (close it or press Ctrl-C to finish capture) …", flush=True)
    # First Ctrl-C stops the capture and closes the session; a second aborts the upload
    # drain (Chrome + dumpcap are already stopped by then, so nothing keeps recording).
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
