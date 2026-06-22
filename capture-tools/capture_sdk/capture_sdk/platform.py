"""Cross-platform (Linux + macOS) discovery of Chrome, the capture interface,
and dumpcap. Each can be overridden by an env var.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

_MAC_CHROME = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]
_MAC_DUMPCAP = ["/Applications/Wireshark.app/Contents/MacOS/dumpcap"]
_LINUX_DUMPCAP = ["/usr/bin/dumpcap", "/usr/sbin/dumpcap", "/usr/local/bin/dumpcap", "/sbin/dumpcap"]
_CHROME_NAMES = (
    "google-chrome", "google-chrome-stable", "google-chrome-beta", "google-chrome-canary",
    "chromium", "chromium-browser", "chrome", "brave-browser", "microsoft-edge",
)


def chrome_binaries() -> list[str]:
    """All discovered Chrome/Chromium-family binaries, in preference order
    (CHROME_BIN first), de-duplicated. Used by the interactive picker."""
    found: list[str] = []

    def add(p: str | None) -> None:
        if p and p not in found and os.path.exists(p):
            found.append(p)

    add(os.environ.get("CHROME_BIN"))
    if sys.platform == "darwin":
        for p in _MAC_CHROME:
            add(p)
    for name in _CHROME_NAMES:
        add(shutil.which(name))
    return found


def chrome_binary() -> str:
    if bins := chrome_binaries():
        return bins[0]
    raise RuntimeError("Chrome/Chromium not found; set CHROME_BIN")


def chrome_profile_default(chrome_path: str | None = None) -> str:
    """The browser's standard user-data-dir, picked from the binary name
    (Chromium vs Chrome). Capturing on it requires the browser to be closed first."""
    chromium = "chromium" in (chrome_path or "").lower()
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
        return os.path.join(base, "Chromium" if chromium else "Google/Chrome")
    return os.path.expanduser("~/.config/" + ("chromium" if chromium else "google-chrome"))


def dumpcap_binary() -> str:
    if env := os.environ.get("DUMPCAP_BIN"):
        return env
    if p := shutil.which("dumpcap"):
        return p
    # shutil.which() only returns paths the caller can execute; dumpcap is commonly
    # root:wireshark mode 0750, so it's skipped when the `wireshark` group isn't active
    # in this process. Fall back to known install paths by existence — the launcher
    # re-execs under `sg wireshark` so the binary is runnable by the time it spawns.
    paths = _MAC_DUMPCAP if sys.platform == "darwin" else _LINUX_DUMPCAP
    for p in paths:
        if os.path.exists(p):
            return p
    raise RuntimeError("dumpcap not found (install Wireshark); set DUMPCAP_BIN")


def default_interface() -> str:
    if env := os.environ.get("CAPTURE_IFACE"):
        return env
    if sys.platform == "darwin":
        out = subprocess.run(
            ["route", "-n", "get", "default"], capture_output=True, text=True
        ).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                return line.split(":", 1)[1].strip()
    else:
        out = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        ).stdout
        parts = out.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("could not detect default interface; set CAPTURE_IFACE")
