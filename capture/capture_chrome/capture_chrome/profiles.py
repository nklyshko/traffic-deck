"""Chrome profile discovery + resolution, shared between the interactive picker and the
serve-mode `Describe`.

Both surfaces present the same tree — pick a kind (an existing browser profile, the
browser default, a fresh temp, or a saved persistent one), then which one within it — the
picker by prompting, `Describe` by re-describing as fields fill. This module holds the
discovery (which profiles exist, which are saved) and the resolution (a chosen kind +
selection → the launch form), so the two can't disagree about what exists — the
precondition ADR-0010 calls out.
"""

from __future__ import annotations

import os
import tempfile

from capture_chrome import platform
from capture_sdk import paths

# Returned to mean "launch with no --user-data-dir", so the chosen browser uses its own
# built-in default profile (each binary has its own path).
BUILTIN_PROFILE = object()

# Named persistent custom profiles live here so a capture's logins/state survive across
# runs; the user picks an existing one or creates a new named one.
_PROFILES_DIR = str(paths.home() / "chrome-profiles")
# Pre-relocation location, migrated into _PROFILES_DIR on first use.
_LEGACY_PROFILES_DIR = os.path.expanduser("~/.capture-chrome/profiles")


def snap_writable_base(chrome: str) -> str | None:
    """The snap-writable dir tool-managed files (keylog, throwaway/persistent profiles)
    must live in for a snap-confined browser — snap's private /tmp and hidden-file rules
    otherwise swallow them so nothing decodes. None for an unconfined browser. Created on
    demand."""
    snap = platform.snap_name(chrome)
    if not snap:
        return None
    base = platform.snap_user_common(snap)
    os.makedirs(base, exist_ok=True)
    return base


def temp_profile(chrome: str) -> str:
    """A fresh throwaway --user-data-dir: under the snap's writable area for a snap browser
    (confinement blocks /tmp), an ordinary tempdir otherwise."""
    return tempfile.mkdtemp(prefix="chrome-capture-", dir=snap_writable_base(chrome))


def profiles_dir(chrome: str) -> str:
    """The persistent-profiles dir, creating it and migrating any legacy profiles (from
    ~/.capture-chrome/profiles) into it on first use. For a snap browser this lives under
    the snap's own writable area instead of the hidden ~/.traffic-deck (which confinement
    blocks), so persistent profiles are separate per snap and not migrated."""
    if base := snap_writable_base(chrome):
        path = os.path.join(base, "td-chrome-profiles")
        os.makedirs(path, exist_ok=True)
        return path
    os.makedirs(_PROFILES_DIR, exist_ok=True)
    if os.path.isdir(_LEGACY_PROFILES_DIR):
        for name in os.listdir(_LEGACY_PROFILES_DIR):
            src = os.path.join(_LEGACY_PROFILES_DIR, name)
            dst = os.path.join(_PROFILES_DIR, name)
            if not os.path.exists(dst):
                os.rename(src, dst)
    return _PROFILES_DIR


def saved_profiles(chrome: str) -> list[str]:
    """Names of the saved persistent profiles for a binary (subdirs of profiles_dir)."""
    d = profiles_dir(chrome)
    return sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))


def persistent_path(chrome: str, name: str) -> str:
    """The --user-data-dir for a saved persistent profile `name`, created on demand."""
    path = os.path.join(profiles_dir(chrome), name or "default")
    os.makedirs(path, exist_ok=True)
    return path


def resolve_existing(chrome: str, dir_name: str) -> tuple[str, str]:
    """Map a discovered profile's directory name back to its (user_data_dir, dir_name) for
    launch, looking it up in the same discovery the choice came from."""
    for udd, dirn, _label in platform.chrome_profiles(chrome):
        if dirn == dir_name:
            return (udd, dirn)
    return (platform.chrome_user_data_dir(chrome) or "", dir_name)
