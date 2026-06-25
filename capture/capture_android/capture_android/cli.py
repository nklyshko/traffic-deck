"""Interactive Android capture CLI.

A frida-free front-end over the capture library. Guided flow:
  1. pick a target — emulator or a connected real device
  2. for an emulator: use a running one, boot an existing AVD, or create one (installing
     a rootable system image if needed)
  3. ensure the target is rooted
  4. pick the frida version — recommended for the device's Android release, picked from
     the latest available (auto-checked on GitHub); v16 and v17 are always offered
  5. pick the app to capture from the installed list, shown as "App Name (package)" —
     names are read from the device via Frida (run under the version from step 4), which
     also starts frida-server so the capture reuses it (--no-app-names lists packages only)
  6. optionally add Frida scripts (SSL-unpinning / bypass) to load alongside the keylog

It then launches the capture under the chosen frida via `uv run --with frida==<ver>`
(client and server must match), so the CLI itself never imports frida.

  trafficdeck-capture-android
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from capture_android import frida_versions
from capture_android.adb import AdbClient
from capture_android.emulator import DEFAULT_AVD, DEFAULT_IMAGE, Sdk
from capture_sdk import prompt

_DEFAULT_SCRIPTS_DIR = os.path.expanduser("~/.config/traffic/frida-scripts")
_PROJECT = str(Path(__file__).resolve().parents[1])  # the capture_android project dir


# --- steps ---------------------------------------------------------------

def pick_emulator(sdk: Sdk) -> str:
    """Step 2: choose/boot/create an emulator; returns its adb serial."""
    running = [d.serial for d in sdk.connected_devices() if d.emulator and d.state == "device"]
    avds = sdk.list_avds()
    options = ([(f"use running {s}", ("use", s)) for s in running]
               + [(f"boot AVD {a}", ("boot", a)) for a in avds]
               + [("create a new AVD", ("new", ""))])
    action, value = prompt.select("Emulator:", options)

    if action == "use":
        return value
    if action == "boot":
        name = value
    else:
        name = prompt.text("New AVD name", DEFAULT_AVD)
        if not sdk.system_image_installed(DEFAULT_IMAGE):
            if prompt.confirm(f"Install system image {DEFAULT_IMAGE}?", default=True):
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
    return prompt.select("Device:", [d.serial for d in ready])


def pick_frida_version(adb: AdbClient) -> str:
    """Step 4: pick a frida version compatible with the device's Android release."""
    release = adb.shell("getprop", "ro.build.version.release").strip()
    rec = frida_versions.recommended(release)
    print(f"Android {release or '?'} detected — recommended frida {rec}"
          " (frida 17 can't spawn on Android ≤ 11)")
    opts = [(v + "  (recommended)" if v == rec else v, v) for v in frida_versions.choices(rec)]
    return prompt.select("frida version (client + server must match):", opts, default=rec)


def pick_scripts(scripts_dir: str) -> list[str]:
    """Step 6: pick extra Frida scripts from a directory and/or a custom path."""
    d = Path(scripts_dir)
    found = sorted(str(p) for p in d.glob("*.js")) if d.is_dir() else []
    if found:
        chosen = prompt.checkbox(f"Extra Frida scripts (from {scripts_dir}):", found)
    else:
        print(f"(no scripts in {scripts_dir})")
        chosen = []
    custom = prompt.text("Extra script path (optional)", "")
    if custom:
        chosen.append(custom)
    return chosen


def parse_app_names(stdout: str) -> dict[str, str]:
    """Parse `list_apps` output (`<identifier>\\t<name>` per line) into {package: label}."""
    names: dict[str, str] = {}
    for line in stdout.splitlines():
        ident, sep, name = line.partition("\t")
        if sep and ident:
            names[ident] = name
    return names


def enumerate_app_names(serial: str, fver: str) -> dict[str, str]:
    """Resolve {package: label} via Frida, run under the chosen frida version.

    Spawns `capture_android.list_apps` through `uv run --with frida==<fver>` (the same
    way the capture is launched, so this CLI stays frida-free) and reads its labels
    from the device's PackageManager — no APK downloads. Returns {} on any failure, so
    the picker falls back to bare package names.
    """
    cmd = ["uv", "run", "--project", _PROJECT, "--with", f"frida=={fver}",
           "python", "-m", "capture_android.list_apps", "--serial", serial]
    try:
        out = subprocess.run(cmd, text=True, capture_output=True, timeout=180, check=True).stdout
    except (subprocess.SubprocessError, OSError):
        return {}
    return parse_app_names(out)


def app_choices(packages: list[str], labels: dict[str, str]) -> list[tuple[str, str]]:
    """Build (display, value) selector choices: `Label  (com.pkg)` when the label is
    known, otherwise just the package. The chosen value is always the package."""
    return [(f"{labels[p]}  ({p})" if p in labels else p, p) for p in packages]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Interactive Android capture")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"))
    ap.add_argument("--duration", type=float, default=None, help="auto-stop after N seconds")
    ap.add_argument("--sdk", default=None, help="Android SDK root (default: $ANDROID_HOME / ~/Android/Sdk)")
    ap.add_argument("--scripts-dir", default=_DEFAULT_SCRIPTS_DIR)
    ap.add_argument("--all-apps", action="store_true", help="list all packages, not just third-party")
    ap.add_argument("--no-app-names", action="store_true",
                    help="skip resolving app names via Frida (lists package names only)")
    args = ap.parse_args(argv)

    sdk = Sdk(args.sdk)

    # Step 1–2: target.
    target = prompt.select("Capture target:", ["emulator", "device"])
    serial = pick_emulator(sdk) if target == "emulator" else pick_device(sdk)
    adb = AdbClient(serial=serial, adb=sdk.adb)

    # Step 3: ensure rooted (fail fast; the capture re-checks too).
    try:
        adb.root()
    except RuntimeError as e:
        raise SystemExit(str(e))

    # Step 4: frida version (Android-compat recommendation + manual override).
    fver = pick_frida_version(adb)

    # Step 5: pick the app, shown as "App Name  (com.pkg)" when resolvable. Names come
    # from Frida, which also starts frida-server for the capture to reuse.
    tp = not args.all_apps
    pkgs = adb.list_packages(third_party=tp)
    if not pkgs:
        tp = False
        pkgs = adb.list_packages(third_party=tp)
    names: dict[str, str] = {}
    if not args.no_app_names:
        print(f"resolving app names ({len(pkgs)} apps)…")
        names = enumerate_app_names(serial, fver)
    package = prompt.select(f"App to capture ({len(pkgs)} installed):",
                            app_choices(pkgs, names))

    # Step 6: extra scripts + optional URL.
    scripts = pick_scripts(args.scripts_dir)
    url = prompt.text("URL to open in the app (optional)", "")

    # Launch the capture under the chosen frida (client+server must match).
    cmd = ["uv", "run", "--project", _PROJECT, "--with", f"frida=={fver}",
           "python", "-m", "capture_android.headless",
           "--serial", serial, "--package", package, "--gateway", args.gateway]
    if url:
        cmd += ["--url", url]
    if args.duration is not None:
        cmd += ["--duration", str(args.duration)]
    for s in scripts:
        cmd += ["--script", s]
    print(f"\nlaunching capture: {package} under frida {fver}\n")
    os.execvp("uv", cmd)


if __name__ == "__main__":
    main()
