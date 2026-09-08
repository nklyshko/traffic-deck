"""Locating dumpcap and the interface to capture on (Linux + macOS).

Every packet-capturing tool needs the same two answers and honours the same overrides
(``DUMPCAP_BIN``, ``CAPTURE_IFACE``), so they live here rather than in any one tool.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

_MAC_APP_DIRS = ["/Applications", os.path.expanduser("~/Applications")]
_MAC_DUMPCAP = [d + "/Wireshark.app/Contents/MacOS/dumpcap" for d in _MAC_APP_DIRS]
_LINUX_DUMPCAP = ["/usr/bin/dumpcap", "/usr/sbin/dumpcap", "/usr/local/bin/dumpcap", "/sbin/dumpcap"]


def binary() -> str:
    """The dumpcap to run, from ``DUMPCAP_BIN``, PATH, or a known install path."""
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
    """The interface the default route goes out of, or ``CAPTURE_IFACE`` if set."""
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
