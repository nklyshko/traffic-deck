"""Snap confinement, as it affects a capture tool's files.

A snap-published browser runs with a private ``/tmp`` mount namespace and can't write
outside a small allowed set — so an ``SSLKEYLOGFILE`` (or a tool-managed profile) placed
in the host's ``/tmp`` is either denied or written to the snap's *private* ``/tmp``,
invisible to us, and the capture decodes nothing. Tools must place such files under the
snap's own writable area instead ([writable_base][capture_sdk.snap.writable_base]).

Shared because it is a property of the host, not of any one browser: Ubuntu ships both
Chromium and Firefox as snaps.
"""

from __future__ import annotations

import os
import re
import sys


def name(binary: str) -> str | None:
    """The snap name if `binary` is a snap-published program, else None.

    Detected three ways: the ``/snap/bin/<name>`` launcher (a symlink to ``/usr/bin/snap``),
    a path inside a mounted snap (``/snap/<name>/…``), and a transitional shim script (e.g.
    Ubuntu's ``/usr/bin/chromium-browser``) ending in ``exec /snap/bin/<name>``. Always None
    on macOS (no snaps)."""
    if sys.platform == "darwin":
        return None
    real = os.path.realpath(binary)
    if real == "/usr/bin/snap":
        # /snap/bin/<name> is a symlink to the snap launcher; the launcher name is the snap.
        return os.path.basename(binary)
    if real.startswith("/snap/"):
        # A path inside a mounted snap, e.g. /snap/<name>/current/… — the 2nd part names it.
        parts = real.split("/")
        return parts[2] if len(parts) > 2 else os.path.basename(binary)
    try:
        with open(binary, encoding="utf-8", errors="replace") as f:
            head = f.read(8192)
    except OSError:
        return None
    m = re.search(r"/snap/bin/(\S+)", head)
    return m.group(1) if m else None


def user_common(snap: str) -> str:
    """A snap's writable, non-namespaced ``$SNAP_USER_COMMON`` dir (``~/snap/<name>/common``).

    Unlike /tmp (which confinement replaces with a private mount) this is the same real
    path both inside the sandbox and on the host, so a keylog written here by the confined
    program is visible to the capture tool. It also survives snap refreshes (``common`` is
    not tied to a revision, unlike ``current``)."""
    return os.path.expanduser(os.path.join("~", "snap", snap, "common"))


def writable_base(binary: str) -> str | None:
    """The dir a tool's files for `binary` must live in for confinement not to swallow
    them, or None when `binary` is unconfined (the ordinary tempdir/home then applies).
    Created on demand."""
    snap = name(binary)
    if not snap:
        return None
    base = user_common(snap)
    os.makedirs(base, exist_ok=True)
    return base
