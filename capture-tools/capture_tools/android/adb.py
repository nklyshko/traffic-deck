"""adb plumbing for the Android capture agent.

The pure helpers (frida_arch, parse_app_uid, nflog_rules) are unit-tested without a
device; AdbClient is the thin runtime wrapper over the `adb` binary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess


def find_adb() -> str:
    """Resolve the adb binary: $ADB, then $ANDROID_HOME/$ANDROID_SDK_ROOT, then PATH."""
    if env := os.environ.get("ADB"):
        return env
    for root in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")):
        if root:
            cand = os.path.join(root, "platform-tools", "adb")
            if os.path.exists(cand):
                return cand
    if p := shutil.which("adb"):
        return p
    raise RuntimeError("adb not found; set ADB or ANDROID_HOME, or add adb to PATH")


# Android ABI (ro.product.cpu.abi) -> frida-server release arch suffix.
_FRIDA_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}


def frida_arch(abi: str) -> str:
    """Map an Android ABI to frida-server's arch suffix."""
    try:
        return _FRIDA_ARCH[abi.strip()]
    except KeyError:
        raise RuntimeError(f"unsupported ABI {abi!r} (known: {', '.join(_FRIDA_ARCH)})")


def parse_app_uid(pm_list_u: str, package: str) -> int:
    """Extract an app's Linux UID from `pm list packages -U` output.

    Lines look like `package:com.android.chrome uid:10150`. Matching the exact
    package avoids substring collisions (…chrome vs …chrome.beta).
    """
    for line in pm_list_u.splitlines():
        m = re.match(r"package:(\S+)\s+uid:(\d+)", line.strip())
        if m and m.group(1) == package:
            return int(m.group(2))
    raise RuntimeError(f"uid for {package!r} not found (is it installed?)")


def nflog_rules(uid: int, mark: int, group: int) -> tuple[list[list[str]], list[list[str]]]:
    """iptables rules for per-app capture by UID via NFLOG (returns add, teardown).

    Tag the app's connections by owner UID (CONNMARK), then NFLOG every packet of a
    tagged connection in both directions — so inbound packets (which have no owner)
    are matched by their connection mark. tcpdump reads `nflog:<group>`.
    """
    m, g = hex(mark), str(group)
    specs = [
        # mangle OUTPUT: mark new connections owned by the app UID
        ["mangle", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "CONNMARK", "--set-mark", m],
        # NFLOG both directions for packets belonging to a marked connection
        ["mangle", "OUTPUT", "-m", "connmark", "--mark", m, "-j", "NFLOG", "--nflog-group", g],
        ["mangle", "INPUT", "-m", "connmark", "--mark", m, "-j", "NFLOG", "--nflog-group", g],
    ]
    add = [["iptables", "-t", s[0], "-A", *s[1:]] for s in specs]
    teardown = [["iptables", "-t", s[0], "-D", *s[1:]] for s in specs]
    return add, teardown


class AdbClient:
    """Thin wrapper over `adb [-s serial] …` for one device."""

    def __init__(self, serial: str | None = None, adb: str | None = None) -> None:
        self.adb = adb or find_adb()
        self.serial = serial

    def _base(self) -> list[str]:
        return [self.adb] + (["-s", self.serial] if self.serial else [])

    def run(self, *args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(self._base() + list(args), text=True,
                              capture_output=capture, check=check)

    def shell(self, *args: str, check: bool = True) -> str:
        return self.run("shell", *args, check=check).stdout

    def su(self, cmd: str, check: bool = True) -> str:
        """Run a shell command as root (adb root has been gained, so shell is root)."""
        return self.run("shell", cmd, check=check).stdout

    def wait_for_device(self) -> None:
        self.run("wait-for-device", capture=False)

    def root(self) -> None:
        self.run("root", check=False)
        self.wait_for_device()

    def abi(self) -> str:
        return self.shell("getprop", "ro.product.cpu.abi").strip()

    def app_uid(self, package: str) -> int:
        return parse_app_uid(self.shell("pm", "list", "packages", "-U"), package)

    def list_packages(self, third_party: bool = True) -> list[str]:
        """Installed package names (third-party only by default), sorted."""
        args = ["pm", "list", "packages"] + (["-3"] if third_party else [])
        pkgs = [l.strip()[8:] for l in self.shell(*args).splitlines()
                if l.strip().startswith("package:")]
        return sorted(pkgs)

    def push(self, local: str, remote: str) -> None:
        self.run("push", local, remote, capture=False)
