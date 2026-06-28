"""Interactive Android capture CLI.

A frida-free front-end over the capture library. Guided flow:
  1. pick a target — emulator or a connected real device
  2. for an emulator: use a running one, boot an existing AVD, or create one (installing
     a rootable system image if needed)
  3. ensure the target is rooted
  4. pick the frida version — recommended for the device's Android release, picked from
     the latest available (auto-checked on GitHub); v16 and v17 are always offered

Then a main menu loops:
  * Start a capture — pick the app (installed list, shown as "App Name (package)";
    names come from Frida, which also starts frida-server for the capture to reuse —
    --no-app-names lists packages only) + optional unpinning scripts + URL, then run it.
    Ctrl-C stops that capture (graceful, then force on a second Ctrl-C) and returns here.
  * Stop / Delete emulator — shut it down, or delete the AVD.
  * Exit — and offer to stop an emulator we booted.

Each capture runs under the chosen frida via `uv run --with frida==<ver>` (client and
server must match), so the CLI itself never imports frida.

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
from capture_sdk import paths, prompt, terminal
from capture_sdk.state import Store

_DEFAULT_SCRIPTS_DIR = str(paths.home() / "frida-scripts")
_PROJECT = str(Path(__file__).resolve().parents[1])  # the capture_android project dir


# --- steps ---------------------------------------------------------------

def pick_emulator(sdk: Sdk, store: Store, headless: bool = False) -> tuple[str, str | None]:
    """Step 2: choose/boot/create an emulator. Returns (serial, booted_avd) where
    booted_avd is the AVD name iff this call booted/created it (so we own it and can
    offer to stop it on exit), else None. Boots with a window unless `headless`."""
    running = [d.serial for d in sdk.connected_devices() if d.emulator and d.state == "device"]
    avds = sdk.list_avds()
    options = ([(f"use running {s}", ("use", s)) for s in running]
               + [(f"boot AVD {a}", ("boot", a)) for a in avds]
               + [("create a new AVD", ("new", ""))])
    action, value = store.remember("emulator", prompt.select(
        "Emulator:", options, default=store.get_valid("emulator", [v for _, v in options])))

    if action == "use":
        return value, None
    if action == "boot":
        name = value
    else:
        name = store.remember("avd_name", prompt.text(
            "New AVD name", store.get("avd_name", DEFAULT_AVD)))
        if not sdk.system_image_installed(DEFAULT_IMAGE):
            if prompt.confirm(f"Install system image {DEFAULT_IMAGE}?", default=True):
                sdk.install_system_image(DEFAULT_IMAGE)
            else:
                raise SystemExit("a system image is required")
        sdk.create_avd(name, DEFAULT_IMAGE)
    print(f"booting {name} …")
    sdk.boot(name, headless=headless)
    serial = sdk.wait_for_boot()
    print(f"booted {serial}")
    return serial, name


def pick_device(sdk: Sdk, store: Store) -> str:
    """Step 1 (device branch): choose a connected, authorized real device."""
    devs = [d for d in sdk.connected_devices() if not d.emulator]
    ready = [d for d in devs if d.state == "device"]
    if not ready:
        if any(d.state == "unauthorized" for d in devs):
            raise SystemExit("device is unauthorized — accept the USB-debugging prompt and retry")
        raise SystemExit("no connected device (enable USB debugging and plug it in)")
    serials = [d.serial for d in ready]
    return store.remember("device", prompt.select(
        "Device:", serials, default=store.get_valid("device", serials)))


def pick_frida_version(adb: AdbClient, store: Store) -> str:
    """Step 4: pick a frida version compatible with the device's Android release."""
    release = adb.shell("getprop", "ro.build.version.release").strip()
    rec = frida_versions.recommended(release)
    print(f"Android {release or '?'} detected — recommended frida {rec}"
          " (frida 17 can't spawn on Android ≤ 11)")
    choices = frida_versions.choices(rec)
    opts = [(v + "  (recommended)" if v == rec else v, v) for v in choices]
    default = store.get_valid("frida_version", choices, rec)
    return store.remember(
        "frida_version",
        prompt.select("frida version (client + server must match):", opts, default=default))


def pick_scripts(scripts_dir: str, store: Store) -> list[str]:
    """Step 6: pick extra Frida scripts from a directory and/or a custom path.
    Scripts chosen last run are pre-checked when they're still present."""
    last = store.get("scripts", [])
    d = Path(scripts_dir)
    found = sorted(str(p) for p in d.glob("*.js")) if d.is_dir() else []
    if found:
        chosen = prompt.checkbox(f"Extra Frida scripts (from {scripts_dir}):", found,
                                 checked=[s for s in last if s in found])
    else:
        print(f"(no scripts in {scripts_dir})")
        chosen = []
    custom = prompt.text("Extra script path (optional)", "")
    if custom:
        chosen.append(custom)
    store.remember("scripts", chosen)
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
        # stdin=DEVNULL: this subprocess's adb/frida calls would otherwise inherit the
        # controlling tty and leave it in a broken input state, wedging the next prompt.
        out = subprocess.run(cmd, text=True, capture_output=True, timeout=180,
                             check=True, stdin=subprocess.DEVNULL).stdout
    except (subprocess.SubprocessError, OSError):
        return {}
    return parse_app_names(out)


def app_choices(packages: list[str], labels: dict[str, str]) -> list[tuple[str, str]]:
    """Build (display, value) selector choices: `Label  (com.pkg)` when the label is
    known, otherwise just the package. The chosen value is always the package."""
    return [(f"{labels[p]}  ({p})" if p in labels else p, p) for p in packages]


def _run_capture(sdk: Sdk, adb: AdbClient, store: Store, serial: str, fver: str, args) -> None:
    """One capture: pick app + scripts + URL, then run the capture as a subprocess and
    wait. Ctrl-C is owned by the capture (its two-stage stop), so we keep waiting and
    return to the main menu once it stops, rather than exec'ing and never coming back."""
    tp = not args.all_apps
    pkgs = adb.list_packages(third_party=tp)
    if not pkgs:
        tp = False
        pkgs = adb.list_packages(third_party=tp)
    names: dict[str, str] = {}
    if not args.no_app_names:
        print(f"resolving app names ({len(pkgs)} apps)…")
        names = enumerate_app_names(serial, fver)
        terminal.restore()  # heal the tty if the frida subprocess disturbed it
    package = store.remember("package", prompt.select(
        f"App to capture ({len(pkgs)} installed):", app_choices(pkgs, names),
        default=store.get_valid("package", pkgs)))
    scripts = pick_scripts(args.scripts_dir, store)
    url = store.remember("url", prompt.text(
        "URL to open in the app (optional)", store.get("url", "")))

    cmd = ["uv", "run", "--project", _PROJECT, "--with", f"frida=={fver}",
           "python", "-m", "capture_android.headless",
           "--serial", serial, "--package", package, "--gateway", args.gateway]
    if url:
        cmd += ["--url", url]
    if args.duration is not None:
        cmd += ["--duration", str(args.duration)]
    for s in scripts:
        cmd += ["--script", s]
    print(f"\nlaunching capture: {package} under frida {fver}  (Ctrl-C to stop)\n")
    proc = subprocess.Popen(cmd)
    while True:
        try:
            proc.wait()
            break
        except KeyboardInterrupt:
            continue  # the capture handles Ctrl-C itself; keep waiting for it to stop
    terminal.restore()  # the capture may have left the tty raw
    print()


def _maybe_stop_emulator(sdk: Sdk, serial: str) -> None:
    """On exit, offer to stop an emulator we booted ourselves (best-effort)."""
    if not sdk.is_running(serial):
        return
    try:
        if prompt.confirm(f"Stop emulator {serial}?", default=True):
            print(f"stopping {serial} …")
            sdk.stop_emulator(serial)
    except SystemExit:
        pass  # Ctrl-C at the prompt → leave it running


def _menu_loop(sdk: Sdk, adb: AdbClient, store: Store, serial: str, fver: str, args,
               is_emulator: bool) -> None:
    """Main menu: start captures repeatedly, and (for an emulator) stop/delete it."""
    while True:
        options = [("Start a capture", "capture")]
        if is_emulator:
            options += [("Stop emulator", "stop"), ("Delete emulator (AVD)", "delete")]
        options.append(("Exit", "exit"))
        try:
            choice = prompt.select("Main menu:", options)
        except SystemExit:
            return  # Ctrl-C / Esc at the menu → exit
        if choice == "capture":
            _run_capture(sdk, adb, store, serial, fver, args)
        elif choice == "stop":
            print(f"stopping {serial} …")
            sdk.stop_emulator(serial)
            return
        elif choice == "delete":
            name = sdk.avd_name(serial)
            if name and prompt.confirm(f"Delete AVD '{name}'? This erases it.", default=False):
                print(f"stopping and deleting {name} …")
                sdk.stop_emulator(serial)
                sdk.delete_avd(name)
                return
        else:  # exit
            return


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Interactive Android capture")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"))
    ap.add_argument("--duration", type=float, default=None, help="auto-stop after N seconds")
    ap.add_argument("--sdk", default=None, help="Android SDK root (default: $ANDROID_HOME / ~/Android/Sdk)")
    ap.add_argument("--scripts-dir", default=_DEFAULT_SCRIPTS_DIR)
    ap.add_argument("--all-apps", action="store_true", help="list all packages, not just third-party")
    ap.add_argument("--no-app-names", action="store_true",
                    help="skip resolving app names via Frida (lists package names only)")
    ap.add_argument("--headless", action="store_true",
                    help="boot the emulator without a window (default: show it)")
    args = ap.parse_args(argv)

    sdk = Sdk(args.sdk)
    # Each picker defaults to the previous run's choice, remembered under
    # ~/.traffic-deck/state/android.json.
    store = Store("android")

    # Pick the target + frida once; then loop in the main menu (capture repeatedly,
    # stop/delete the emulator, exit). Each capture runs as a subprocess so Ctrl-C
    # stops just that capture and drops back to the menu.
    target = store.remember("target", prompt.select(
        "Capture target:", ["emulator", "device"],
        default=store.get_valid("target", ["emulator", "device"])))
    if target == "emulator":
        serial, booted_avd = pick_emulator(sdk, store, headless=args.headless)
    else:
        serial, booted_avd = pick_device(sdk, store), None

    adb = AdbClient(serial=serial, adb=sdk.adb)
    try:
        adb.root()  # fail fast; the capture re-checks too
    except RuntimeError as e:
        raise SystemExit(str(e))
    fver = pick_frida_version(adb, store)

    try:
        _menu_loop(sdk, adb, store, serial, fver, args, is_emulator=target == "emulator")
    finally:
        # Offer to stop an emulator we booted ourselves (leave pre-existing ones alone).
        if booted_avd:
            _maybe_stop_emulator(sdk, serial)


if __name__ == "__main__":
    main()
