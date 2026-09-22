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

from capture_chrome import platform
from capture_sdk import browser, paths
from capture_sdk.browser import BUILTIN_PROFILE  # noqa: F401 — re-exported for this tool

# Named persistent custom profiles live here so a capture's logins/state survive across
# runs; the user picks an existing one or creates a new named one.
_PROFILES_DIR = str(paths.home() / "chrome-profiles")
# Pre-relocation location, migrated into _PROFILES_DIR on first use.
_LEGACY_PROFILES_DIR = os.path.expanduser("~/.capture-chrome/profiles")


def temp_profile(chrome: str) -> str:
    """A fresh throwaway --user-data-dir: under the snap's writable area for a snap browser
    (confinement blocks /tmp), an ordinary tempdir otherwise."""
    return browser.temp_profile(chrome, "chrome-capture-")


def profiles_dir(chrome: str) -> str:
    """The persistent-profiles dir, creating it and migrating any legacy profiles (from
    ~/.capture-chrome/profiles) into it on first use. For a snap browser this lives under
    the snap's own writable area instead of the hidden ~/.traffic-deck (which confinement
    blocks), so persistent profiles are separate per snap and not migrated."""
    path = browser.profiles_root(chrome, unconfined=_PROFILES_DIR, snap_dir="td-chrome-profiles")
    if path != _PROFILES_DIR:  # a snap's own area — nothing to migrate into it
        return path
    if os.path.isdir(_LEGACY_PROFILES_DIR):
        for name in os.listdir(_LEGACY_PROFILES_DIR):
            src = os.path.join(_LEGACY_PROFILES_DIR, name)
            dst = os.path.join(_PROFILES_DIR, name)
            if not os.path.exists(dst):
                os.rename(src, dst)
    return path


def saved_profiles(chrome: str) -> list[str]:
    """Names of the saved persistent profiles for a binary (subdirs of profiles_dir)."""
    return browser.saved_profiles(profiles_dir(chrome))


def persistent_path(chrome: str, name: str) -> str:
    """The --user-data-dir for a saved persistent profile `name`, created on demand."""
    return browser.persistent_path(profiles_dir(chrome), name)


def resolve_existing(chrome: str, dir_name: str) -> tuple[str, str]:
    """Map a discovered profile's directory name back to its (user_data_dir, dir_name) for
    launch, looking it up in the same discovery the choice came from."""
    for udd, dirn, _label in platform.chrome_profiles(chrome):
        if dirn == dir_name:
            return (udd, dirn)
    return (platform.chrome_user_data_dir(chrome) or "", dir_name)


def user_data_dir(chrome: str, profile) -> str | None:
    """The --user-data-dir a resolved profile launches against — the dir Chrome's singleton
    is keyed on. Handles all three launch forms: the built-in sentinel (the binary's own
    default dir), an (user_data_dir, profile_directory) pair, or a path. None when the
    binary's default dir isn't known."""
    if profile is BUILTIN_PROFILE:
        return platform.chrome_user_data_dir(chrome)
    if isinstance(profile, tuple):
        return profile[0]
    return profile
