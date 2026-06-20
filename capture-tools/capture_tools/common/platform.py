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


def chrome_binary() -> str:
    if env := os.environ.get("CHROME_BIN"):
        return env
    if sys.platform == "darwin":
        for p in _MAC_CHROME:
            if os.path.exists(p):
                return p
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        if p := shutil.which(name):
            return p
    raise RuntimeError("Chrome/Chromium not found; set CHROME_BIN")


def dumpcap_binary() -> str:
    if env := os.environ.get("DUMPCAP_BIN"):
        return env
    if p := shutil.which("dumpcap"):
        return p
    if sys.platform == "darwin":
        for p in _MAC_DUMPCAP:
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
