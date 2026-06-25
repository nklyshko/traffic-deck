"""Enumerate installed apps (package + human-readable label) via Frida.

Prints one ``<identifier>\\t<name>`` line per app to stdout; diagnostics go to stderr
so the interactive CLI can parse stdout cleanly. Frida reads the labels straight from
the device's PackageManager — no APK transfers.

Run under the frida version the user picked, mirroring the capture launch, so the
interactive CLI itself never imports frida:

  uv run --project capture/capture_android --with frida==<ver> \\
      python -m capture_android.list_apps --serial <serial>

Starts frida-server if it isn't already up; the subsequent capture reuses it.
"""

from __future__ import annotations

import argparse
import sys

from capture_android.adb import AdbClient
from capture_android.frida_server import ensure_target_ready, frida_device


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="List installed apps (package + label) via Frida")
    ap.add_argument("--serial", default=None, help="adb device serial (default: the only device)")
    args = ap.parse_args(argv)

    adb = AdbClient(serial=args.serial)
    ensure_target_ready(adb, log=lambda m: print(m, file=sys.stderr))  # root + frida-server
    device = frida_device(args.serial)
    for app in sorted(device.enumerate_applications(), key=lambda a: (a.name or "").lower()):
        print(f"{app.identifier}\t{app.name}")


if __name__ == "__main__":
    main()
