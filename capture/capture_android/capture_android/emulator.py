"""Emulator + SDK provisioning for the Android agent (library, no prompts).

Wraps sdkmanager/avdmanager/emulator so a CLI can: list connected devices, list/create
AVDs, install a (rootable) system image, and boot one. The interactive CLI drives the
choices; these functions stay headless.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# A rootable default (google_apis, not _playstore — only google_apis allows `adb root`).
DEFAULT_IMAGE = "system-images;android-34;google_apis;x86_64"
DEFAULT_AVD = "retools"


@dataclass
class Device:
    serial: str
    state: str          # "device", "unauthorized", "offline", …
    emulator: bool


def parse_devices(adb_devices_l: str) -> list[Device]:
    """Parse `adb devices -l` output into Device records."""
    out = []
    for line in adb_devices_l.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        is_emu = serial.startswith("emulator-") or "transport_id" in line and "usb:" not in line
        out.append(Device(serial=serial, state=state, emulator=serial.startswith("emulator-")))
    return out


def _sdk_root() -> Path:
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if v := os.environ.get(env):
            return Path(v)
    for cand in (Path.home() / "Android/Sdk", Path.home() / "Library/Android/sdk",
                 Path("/opt/android-sdk")):
        if cand.is_dir():
            return cand
    raise RuntimeError("Android SDK not found; set ANDROID_HOME")


class Sdk:
    """Locates SDK command-line tools and runs sdkmanager/avdmanager/emulator."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else _sdk_root()

    def _tool(self, *candidates: str) -> str:
        for rel in candidates:
            p = self.root / rel
            if p.exists():
                return str(p)
        raise RuntimeError(f"SDK tool not found under {self.root}: {candidates[0]}")

    @property
    def adb(self) -> str:
        return self._tool("platform-tools/adb")

    @property
    def emulator(self) -> str:
        return self._tool("emulator/emulator")

    @property
    def sdkmanager(self) -> str:
        return self._tool("cmdline-tools/latest/bin/sdkmanager", "cmdline-tools/bin/sdkmanager")

    @property
    def avdmanager(self) -> str:
        return self._tool("cmdline-tools/latest/bin/avdmanager", "cmdline-tools/bin/avdmanager")

    def list_avds(self) -> list[str]:
        out = subprocess.run([self.emulator, "-list-avds"], text=True, capture_output=True).stdout
        return [l.strip() for l in out.splitlines() if l.strip()]

    def connected_devices(self) -> list[Device]:
        out = subprocess.run([self.adb, "devices", "-l"], text=True, capture_output=True).stdout
        return parse_devices(out)

    def system_image_installed(self, image: str = DEFAULT_IMAGE) -> bool:
        out = subprocess.run([self.sdkmanager, f"--sdk_root={self.root}", "--list_installed"],
                             text=True, capture_output=True).stdout
        return image in out

    def install_system_image(self, image: str = DEFAULT_IMAGE, log: Callable[[str], None] = print) -> None:
        log(f"installing {image} (this can be ~1GB on first use) …")
        subprocess.run([self.sdkmanager, f"--sdk_root={self.root}", image],
                       input="y\n" * 10, text=True, check=True)

    def create_avd(self, name: str = DEFAULT_AVD, image: str = DEFAULT_IMAGE,
                   device: str = "pixel_6", log: Callable[[str], None] = print) -> None:
        log(f"creating AVD {name} from {image}")
        subprocess.run([self.avdmanager, "create", "avd", "-n", name, "-k", image,
                        "-d", device, "--force"], input="no\n", text=True, check=True)

    def boot(self, name: str = DEFAULT_AVD, headless: bool = True) -> subprocess.Popen:
        """Start the emulator (detached). Returns the Popen; pair with wait_for_boot."""
        args = [self.emulator, "-avd", name, "-no-audio", "-no-snapshot", "-no-boot-anim",
                "-netdelay", "none", "-netspeed", "full", "-gpu", "swiftshader_indirect"]
        if headless:
            args.append("-no-window")
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def wait_for_boot(self, serial: str | None = None, timeout: float = 240) -> str:
        """Wait for an emulator to come online and finish booting, then return its serial.

        Polls until the device is in `device` state and both `sys.boot_completed` and a
        responsive package manager report ready — boot_completed flips to 1 before pm is
        serving requests, so a `pm` query immediately after otherwise races and fails.
        Everything targets a resolved serial (no bare `adb wait-for-device`/`shell`), so
        it's unaffected by another attached device — those fail with 'more than one
        device'."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            target = serial or self._emulator_serial()
            if target and self._system_ready(target):
                return target
            time.sleep(2)
        raise RuntimeError("emulator did not finish booting in time")

    def _emulator_serial(self) -> str | None:
        devs = [d for d in self.connected_devices() if d.emulator and d.state == "device"]
        return devs[0].serial if devs else None

    def is_running(self, serial: str) -> bool:
        """Whether `serial` is currently a connected, ready device."""
        return any(d.serial == serial and d.state == "device"
                   for d in self.connected_devices())

    def stop_emulator(self, serial: str) -> None:
        """Shut a running emulator down (`adb emu kill`)."""
        subprocess.run([self.adb, "-s", serial, "emu", "kill"],
                       text=True, capture_output=True, check=False)

    def avd_name(self, serial: str) -> str | None:
        """The AVD backing a running emulator (`adb emu avd name`), or None."""
        out = subprocess.run([self.adb, "-s", serial, "emu", "avd", "name"],
                             text=True, capture_output=True, check=False).stdout
        for line in out.splitlines():
            line = line.strip()
            if line and line != "OK":
                return line
        return None

    def delete_avd(self, name: str) -> None:
        """Delete an AVD definition (`avdmanager delete avd`); stop it first."""
        subprocess.run([self.avdmanager, "delete", "avd", "-n", name],
                       text=True, capture_output=True, check=False)

    def _system_ready(self, serial: str) -> bool:
        """Whether the device has booted and its package manager is serving requests."""
        base = [self.adb, "-s", serial, "shell"]
        booted = subprocess.run(base + ["getprop", "sys.boot_completed"],
                                text=True, capture_output=True).stdout.strip()
        if booted != "1":
            return False
        # `pm path android` is a cheap probe that fails until pm is up (the framework
        # 'android' package always exists once it is).
        pm = subprocess.run(base + ["pm", "path", "android"], text=True, capture_output=True)
        return pm.returncode == 0 and pm.stdout.startswith("package:")
