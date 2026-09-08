"""Discovery and profile-storage helpers shared by the browser capture tools.

A browser capture tool (`capture_chrome`, `capture_firefox`) has the same three jobs
regardless of engine: find the installed browsers, decide which profile to launch, and
keep tool-managed profiles somewhere the browser can actually write. The *how* differs
per engine (bundle names, profile registries, launch flags) and stays in the owning app;
the shape lives here.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

from capture_sdk import snap

# Returned by a tool's profile resolution to mean "launch with no profile flag", so the
# chosen browser uses its own built-in default profile (each binary has its own path).
BUILTIN_PROFILE = object()

# macOS browsers are .app bundles, not on PATH, and are installed system-wide or per-user.
APP_DIRS = ["/Applications", os.path.expanduser("~/Applications")]


def discover(*, env_var: str, mac_bundles, unix_names) -> list[str]:
    """All installed browser binaries of one family, in preference order, de-duplicated.

    `$<env_var>` wins when set, then (on macOS) the executable inside each of `mac_bundles`
    — paths relative to an [APP_DIRS][capture_sdk.browser.APP_DIRS] entry — else the
    `unix_names` looked up on PATH. Only paths that exist are returned, so the result is
    directly offerable as a picker's choices."""
    found: list[str] = []

    def add(p: str | None) -> None:
        if p and p not in found and os.path.exists(p):
            found.append(p)

    add(os.environ.get(env_var))
    if sys.platform == "darwin":
        for base in APP_DIRS:
            for rel in mac_bundles:
                add(os.path.join(base, rel))
    else:
        for name in unix_names:
            add(shutil.which(name))
    return found


def temp_profile(binary: str, prefix: str) -> str:
    """A fresh throwaway profile dir: under the snap's writable area for a snap browser
    (confinement blocks /tmp), an ordinary tempdir otherwise."""
    return tempfile.mkdtemp(prefix=prefix, dir=snap.writable_base(binary))


def profiles_root(binary: str, *, unconfined: str, snap_dir: str) -> str:
    """The dir holding a tool's named persistent profiles for `binary`, created on demand.

    For a snap browser this is `snap_dir` under the snap's own writable area — the hidden
    ~/.traffic-deck home is blocked by confinement — so persistent profiles are separate
    per snap; otherwise it is `unconfined`."""
    if base := snap.writable_base(binary):
        path = os.path.join(base, snap_dir)
    else:
        path = unconfined
    os.makedirs(path, exist_ok=True)
    return path


def saved_profiles(root: str) -> list[str]:
    """Names of the saved persistent profiles under `root` (its subdirectories)."""
    return sorted(n for n in os.listdir(root) if os.path.isdir(os.path.join(root, n)))


def persistent_path(root: str, name: str) -> str:
    """The profile dir for a saved persistent profile `name` under `root`, created on
    demand. An empty name falls back to "default"."""
    path = os.path.join(root, name or "default")
    os.makedirs(path, exist_ok=True)
    return path


def profile_desc(profile) -> str:
    """Human description of a resolved profile, for logging. Handles all three forms a
    tool resolves to: the built-in sentinel, an (identifier, selection) pair, or a path."""
    if profile is BUILTIN_PROFILE:
        return "browser default"
    if isinstance(profile, tuple):
        return f"{profile[0]} [{profile[1]}]"
    return str(profile)
