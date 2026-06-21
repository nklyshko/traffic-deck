"""Interactive Android capture CLI (plan §7).

A thin front-end over the capture library (adb / emulator / frida_server / capture).
Guided flow:
  1. pick a target — emulator or a connected real device
  2. for an emulator: use a running one, boot an existing AVD, or create one (installing
     a rootable system image if needed)
  3. ensure the target has root + frida-server
  4. pick the app to capture from the installed list
  5. optionally add Frida scripts (SSL-unpinning / bypass) to load alongside the keylog

  uv run --project capture-tools python -m capture_tools.android.cli
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from capture_tools.android.adb import AdbClient
from capture_tools.android.capture import run_capture
from capture_tools.android.emulator import DEFAULT_AVD, DEFAULT_IMAGE, Sdk
from capture_tools.android.frida_server import ensure_target_ready

_DEFAULT_SCRIPTS_DIR = os.path.expanduser("~/.config/traffic/frida-scripts")


# --- prompt helpers ------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        v = ""
    return v or default


def _choose(title: str, items: list[str], render=lambda x: x) -> str:
    print(f"\n{title}")
    for i, it in enumerate(items, 1):
        print(f"  {i:2d}. {render(it)}")
    while True:
        raw = _ask("select", "1")
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return items[int(raw) - 1]
        print("  ? enter a number from the list")


def _multi_choose(title: str, items: list[str]) -> list[str]:
    """Pick zero or more by comma-separated indices ('' = none)."""
    if not items:
        return []
    print(f"\n{title}")
    for i, it in enumerate(items, 1):
        print(f"  {i:2d}. {it}")
    raw = _ask("select (comma-separated, empty = none)", "")
    picked = []
    for tok in raw.replace(" ", "").split(","):
        if tok.isdigit() and 1 <= int(tok) <= len(items):
            picked.append(items[int(tok) - 1])
    return picked


# --- steps ---------------------------------------------------------------

def pick_emulator(sdk: Sdk) -> str:
    """Step 2: choose/boot/create an emulator; returns its adb serial."""
    running = [d.serial for d in sdk.connected_devices() if d.emulator and d.state == "device"]
    avds = sdk.list_avds()
    options = ([f"use running {s}" for s in running]
               + [f"boot AVD {a}" for a in avds]
               + ["create a new AVD"])
    choice = _choose("Emulator:", options)

    if choice.startswith("use running "):
        return choice.removeprefix("use running ")
    if choice.startswith("boot AVD "):
        name = choice.removeprefix("boot AVD ")
    else:
        name = _ask("new AVD name", DEFAULT_AVD)
        if not sdk.system_image_installed(DEFAULT_IMAGE):
            if _ask(f"install {DEFAULT_IMAGE}? (y/n)", "y").lower().startswith("y"):
                sdk.install_system_image(DEFAULT_IMAGE)
            else:
                raise SystemExit("a system image is required")
        sdk.create_avd(name, DEFAULT_IMAGE)
    print(f"booting {name} …")
    sdk.boot(name)
    serial = sdk.wait_for_boot()
    print(f"booted {serial}")
    return serial


def pick_device(sdk: Sdk) -> str:
    """Step 1 (device branch): choose a connected, authorized real device."""
    devs = [d for d in sdk.connected_devices() if not d.emulator]
    ready = [d for d in devs if d.state == "device"]
    if not ready:
        if any(d.state == "unauthorized" for d in devs):
            raise SystemExit("device is unauthorized — accept the USB-debugging prompt and retry")
        raise SystemExit("no connected device (enable USB debugging and plug it in)")
    return _choose("Device:", [d.serial for d in ready])


def pick_scripts(scripts_dir: str) -> list[Path]:
    """Step 5: pick extra Frida scripts from a directory and/or a custom path."""
    d = Path(scripts_dir)
    found = sorted(str(p) for p in d.glob("*.js")) if d.is_dir() else []
    chosen = _multi_choose(f"Extra Frida scripts (from {scripts_dir}):", found) if found else []
    if not found:
        print(f"\n(no scripts in {scripts_dir})")
    custom = _ask("extra script path (optional)", "")
    if custom:
        chosen.append(custom)
    return [Path(c) for c in chosen]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Interactive Android capture")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"))
    ap.add_argument("--duration", type=float, default=None, help="auto-stop after N seconds")
    ap.add_argument("--sdk", default=None, help="Android SDK root (default: $ANDROID_HOME / ~/Android/Sdk)")
    ap.add_argument("--scripts-dir", default=_DEFAULT_SCRIPTS_DIR)
    ap.add_argument("--all-apps", action="store_true", help="list all packages, not just third-party")
    args = ap.parse_args(argv)

    sdk = Sdk(args.sdk)

    # Step 1: target.
    target = _choose("Capture target:", ["emulator", "device"])
    serial = pick_emulator(sdk) if target == "emulator" else pick_device(sdk)
    adb = AdbClient(serial=serial, adb=sdk.adb)

    # Step 3: root + frida-server.
    ensure_target_ready(adb)

    # Step 4: pick the app.
    pkgs = adb.list_packages(third_party=not args.all_apps)
    if not pkgs:
        pkgs = adb.list_packages(third_party=False)
    package = _choose(f"App to capture ({len(pkgs)} installed):", pkgs)

    # Step 5: extra scripts + optional URL.
    scripts = pick_scripts(args.scripts_dir)
    url = _ask("URL to open in the app (optional)", "") or None

    run_capture(adb, package, gateway=args.gateway, url=url,
                duration=args.duration, extra_scripts=scripts)


if __name__ == "__main__":
    main()
