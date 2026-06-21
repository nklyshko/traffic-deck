"""frida-server provisioning + target readiness for the Android agent (library).

No interactive prompts — callers (the flag CLI and the interactive CLI) drive these.
"""

from __future__ import annotations

import lzma
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Callable

import frida

from capture_tools.android.adb import AdbClient, frida_arch

REMOTE = "/data/local/tmp/frida-server"
_CACHE = Path(os.path.expanduser("~/.cache/traffic-android"))
_servers: list[subprocess.Popen] = []  # keep started frida-servers alive (avoid GC)


def frida_device(serial: str | None = None, timeout: int = 5):
    """The Frida device for an adb serial (or the only USB/emulator device)."""
    if serial:
        return frida.get_device(serial, timeout=timeout)
    return frida.get_usb_device(timeout=timeout)


def server_reachable(serial: str | None = None, timeout: int = 2) -> bool:
    try:
        frida_device(serial, timeout).enumerate_processes()
        return True
    except Exception:  # noqa: BLE001
        return False


def fetch_frida_server(version: str, arch: str, log: Callable[[str], None] = print) -> Path:
    """Download (and cache) the frida-server binary for version+arch from GitHub."""
    _CACHE.mkdir(parents=True, exist_ok=True)
    local = _CACHE / f"frida-server-{version}-android-{arch}"
    if not local.exists():
        url = (f"https://github.com/frida/frida/releases/download/{version}/"
               f"frida-server-{version}-android-{arch}.xz")
        log(f"downloading {url}")
        with urllib.request.urlopen(url) as r:  # noqa: S310
            local.write_bytes(lzma.decompress(r.read()))
    return local


def ensure_frida_server(adb: AdbClient, abi: str, log: Callable[[str], None] = print) -> None:
    """Make frida-server reachable on the device (fetch+push+start if needed)."""
    if server_reachable(adb.serial):
        return
    # A stale/mismatched frida-server (e.g. a v16 from another setup) would hold the
    # port and fail our client's version check, so clear any existing one first.
    adb.sh_root("pkill -f frida-server", check=False)
    time.sleep(0.5)
    local = fetch_frida_server(frida.__version__, frida_arch(abi), log)
    adb.push(str(local), REMOTE)
    adb.shell("chmod", "755", REMOTE)
    # Start it as root, detached: keep the Popen alive so the adb session (and thus
    # the foreground frida-server) persists for the life of the agent.
    _servers.append(subprocess.Popen(
        adb.root_persistent_argv(REMOTE), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for _ in range(20):
        if server_reachable(adb.serial, timeout=1):
            return
        time.sleep(0.5)
    raise RuntimeError("frida-server did not become reachable")


def ensure_target_ready(adb: AdbClient, log: Callable[[str], None] = print) -> str:
    """Gain root and ensure frida-server is running. Returns the device ABI."""
    adb.root()
    abi = adb.abi()
    log(f"target {adb.serial or '(only device)'} abi={abi}")
    ensure_frida_server(adb, abi, log)
    return abi
