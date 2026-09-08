"""Firefox profile discovery + resolution, shared between the interactive picker and the
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

from capture_firefox import platform
from capture_sdk import browser, paths
from capture_sdk.browser import BUILTIN_PROFILE  # noqa: F401 — re-exported for this tool

# Named persistent custom profiles live here so a capture's logins/state survive across
# runs; the user picks an existing one or creates a new named one.
_PROFILES_DIR = str(paths.home() / "firefox-profiles")

# Seeded into a *tool-managed* profile only (never the user's own), so a capture doesn't
# open onto the first-run tour and Firefox doesn't ask to be the default browser — the
# equivalent of the --no-first-run/--no-default-browser-check Chrome takes as flags.
_USER_JS = """// Written by TrafficDeck on first use of this capture profile. Edit freely:
// it is only created when absent, never rewritten.
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
"""


def seed_prefs(path: str) -> str:
    """Give a tool-managed profile dir its `user.js`, unless it already has one. Returns
    the dir, so it can wrap a profile-producing call inline."""
    userjs = os.path.join(path, "user.js")
    if not os.path.exists(userjs):
        with open(userjs, "w", encoding="utf-8") as f:
            f.write(_USER_JS)
    return path


def temp_profile(firefox: str) -> str:
    """A fresh throwaway profile dir (launched with --profile): under the snap's writable
    area for a snap browser (confinement blocks /tmp), an ordinary tempdir otherwise."""
    return seed_prefs(browser.temp_profile(firefox, "firefox-capture-"))


def profiles_dir(firefox: str) -> str:
    """The persistent-profiles dir, created on first use. For a snap browser this lives
    under the snap's own writable area instead of the hidden ~/.traffic-deck (which
    confinement blocks), so persistent profiles are separate per snap."""
    return browser.profiles_root(firefox, unconfined=_PROFILES_DIR, snap_dir="td-firefox-profiles")


def saved_profiles(firefox: str) -> list[str]:
    """Names of the saved persistent profiles for a binary (subdirs of profiles_dir)."""
    return browser.saved_profiles(profiles_dir(firefox))


def persistent_path(firefox: str, name: str) -> str:
    """The profile dir for a saved persistent profile `name`, created on demand."""
    return seed_prefs(browser.persistent_path(profiles_dir(firefox), name))


def resolve_existing(firefox: str, profile_name: str) -> tuple[str, str]:
    """Map a discovered profile's name back to its (root, name) for launch, looking it up
    in the same discovery the choice came from."""
    for root, name, _path in platform.firefox_profiles(firefox):
        if name == profile_name:
            return (root, name)
    return (platform.firefox_root(firefox) or "", profile_name)
