"""Chrome profile handling, shared between the interactive picker and the serve-mode
`Describe`.

The CLI picker is a tree (pick a kind, then which one within it); a viewer form can't
cascade like that, so `profile_choices` flattens the tree's leaves into one list of
(value, label) pairs and `resolve_profile` decodes a chosen value back into the launch
form. Both sides read the same discovery (`platform.chrome_profiles`) and the same
persistent-profiles directory, so they can't disagree about what exists — the precondition
ADR-0010 calls out.
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

# Separator packed into an "existing:<udd>\x1f<dir>" choice value (a control char can't
# occur in a path), so a discovered profile round-trips through the flat value string.
_SEP = "\x1f"


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


def _saved_profiles(chrome: str) -> list[str]:
    d = profiles_dir(chrome)
    return sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))


def profile_choices(chrome: str) -> list[tuple[str, str]]:
    """The flattened profile options for a binary as (value, label). The value encodes the
    outcome so `resolve_profile` can decode it: "default", "temp", "existing:<udd>|<dir>",
    "saved:<name>", or "new" (which then reads the new_profile_name param)."""
    out = [
        ("default", "Browser's own default profile"),
        ("temp", "Fresh temporary profile"),
    ]
    for udd, dirn, label in platform.chrome_profiles(chrome):
        out.append((f"existing:{udd}{_SEP}{dirn}", f"{label} [{dirn}]"))
    for name in _saved_profiles(chrome):
        out.append((f"saved:{name}", f"Saved profile: {name}"))
    out.append(("new", "New saved profile…"))
    return out


def resolve_profile(chrome: str, value: str, new_name: str = ""):
    """Decode a `profile_choices` value into the launch form the runner takes: BUILTIN_PROFILE
    (no --user-data-dir), a (user_data_dir, profile_directory) tuple for a specific profile,
    or a path string used as --user-data-dir. A bare path is passed through (the CLI's
    --profile-dir). Creates the directory for saved/new profiles."""
    if not value or value == "temp":
        return temp_profile(chrome)
    if value == "default":
        return BUILTIN_PROFILE
    if value.startswith("existing:"):
        udd, _, dirn = value[len("existing:"):].partition(_SEP)
        return (udd, dirn)
    if value.startswith("saved:"):
        name = value[len("saved:"):]
    elif value == "new":
        name = new_name or "default"
    else:
        return value  # a raw --user-data-dir path
    path = os.path.join(profiles_dir(chrome), name)
    os.makedirs(path, exist_ok=True)
    return path
