"""frida-server provisioning + target readiness for the Android agent (library).

No interactive prompts — callers (the flag CLI and the interactive CLI) drive these.
"""

from __future__ import annotations

import lzma
import os
import time
import urllib.request
from pathlib import Path
from typing import Callable

import frida

from capture_android.adb import AdbClient, frida_arch

REMOTE = "/data/local/tmp/frida-server"
_CACHE = Path(os.path.expanduser("~/.cache/traffic-android"))
# Hold started frida-servers' adb clients alive for the process lifetime: a server
# whose `su` session exits is orphaned and Frida treats it as "jailed".
_servers: list = []


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


def _device_server_running(adb: AdbClient) -> bool:
    return bool(adb.sh_root("pgrep -x frida-server", check=False).strip())


def ensure_frida_server(adb: AdbClient, abi: str, log: Callable[[str], None] = print) -> None:
    """Ensure frida-server is running on the device (fetch+push+start if needed).

    IMPORTANT: this uses only device-side checks (adb/su), never a Frida connection.
    Connecting Frida to a not-yet-ready server latches frida-python into "jailed" mode
    for the whole process, so the *first* Frida op must be the real spawn (in capture).
    """
    if _device_server_running(adb):
        return  # reuse a server that's already up (assume usable)
    local = fetch_frida_server(frida.__version__, frida_arch(abi), log)
    adb.push(str(local), REMOTE)
    adb.shell("chmod", "755", REMOTE)
    # Start as root and KEEP the adb client alive (see start_root_held): setsid + a
    # live su session are both needed or Frida reports "jailed".
    _servers.append(adb.start_root_held(REMOTE))
    for _ in range(20):
        if _device_server_running(adb):
            break
        time.sleep(0.3)
    else:
        raise RuntimeError("frida-server did not start")
    time.sleep(3.0)  # let it finish initializing as root before the first Frida op


def ensure_target_ready(adb: AdbClient, log: Callable[[str], None] = print) -> str:
    """Gain root and ensure frida-server is running. Returns the device ABI."""
    adb.root()
    abi = adb.abi()
    log(f"target {adb.serial or '(only device)'} abi={abi}")
    ensure_frida_server(adb, abi, log)
    return abi
