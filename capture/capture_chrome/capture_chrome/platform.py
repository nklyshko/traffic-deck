"""Cross-platform (Linux + macOS) discovery of the Chrome binaries on this host and the
profiles each of them stores. The generic parts — browser discovery mechanics, snap
confinement, dumpcap and the capture interface — live in `capture_sdk`.
"""

from __future__ import annotations

import json
import os
import sys

from capture_sdk import browser, snap

# macOS browsers are .app bundles, not on PATH — each entry is the executable path
# inside the bundle, searched under every dir in browser.APP_DIRS.
_MAC_CHROME_BUNDLES = [
    "Google Chrome.app/Contents/MacOS/Google Chrome",
    "Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta",
    "Google Chrome Dev.app/Contents/MacOS/Google Chrome Dev",
    "Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "Chromium.app/Contents/MacOS/Chromium",
    "Brave Browser.app/Contents/MacOS/Brave Browser",
    "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "Vivaldi.app/Contents/MacOS/Vivaldi",
    "Arc.app/Contents/MacOS/Arc",
]
_CHROME_NAMES = (
    "google-chrome", "google-chrome-stable", "google-chrome-beta", "google-chrome-canary",
    "chromium", "chromium-browser", "chrome", "brave-browser", "microsoft-edge",
)


def chrome_binaries() -> list[str]:
    """All discovered Chrome/Chromium-family binaries, in preference order
    (CHROME_BIN first), de-duplicated. Used by the interactive picker.

    On macOS this scans the common .app bundles (Chrome + channels, Chromium, Brave,
    Edge, Vivaldi, Arc) under /Applications and ~/Applications; elsewhere it looks up
    the known binary names on PATH."""
    return browser.discover(env_var="CHROME_BIN", mac_bundles=_MAC_CHROME_BUNDLES,
                            unix_names=_CHROME_NAMES)


def chrome_binary() -> str:
    if bins := chrome_binaries():
        return bins[0]
    raise RuntimeError("Chrome/Chromium not found; set CHROME_BIN")


# A Chrome binary keeps all its profiles under one user-data-dir, named by channel.
# basename(binary) -> path relative to the platform's config root.
_LINUX_USER_DATA = {
    "google-chrome": "google-chrome",
    "google-chrome-stable": "google-chrome",
    "chrome": "google-chrome",
    "google-chrome-beta": "google-chrome-beta",
    "google-chrome-unstable": "google-chrome-unstable",
    "google-chrome-canary": "google-chrome-canary",
    "chromium": "chromium",
    "chromium-browser": "chromium",
    "brave-browser": "BraveSoftware/Brave-Browser",
    "microsoft-edge": "microsoft-edge",
}
_MAC_USER_DATA = {
    "Google Chrome": "Google/Chrome",
    "Google Chrome Beta": "Google/Chrome Beta",
    "Google Chrome Dev": "Google/Chrome Dev",
    "Google Chrome Canary": "Google/Chrome Canary",
    "Chromium": "Chromium",
    "Brave Browser": "BraveSoftware/Brave-Browser",
    "Microsoft Edge": "Microsoft Edge",
    "Vivaldi": "Vivaldi",
}


def chrome_user_data_dir(binary: str) -> str | None:
    """The user-data-dir a Chrome binary stores its profiles in, or None if the binary
    isn't a known channel or the directory doesn't exist."""
    # A snap browser ignores ~/.config and keeps its profiles under its own writable
    # $SNAP_USER_COMMON (e.g. ~/snap/chromium/common/chromium), so look there instead.
    if snap_name := snap.name(binary):
        path = os.path.join(snap.user_common(snap_name), snap_name)
        return path if os.path.isdir(path) else None
    name = os.path.basename(binary)
    if sys.platform == "darwin":
        rel = _MAC_USER_DATA.get(name)
        root = os.path.expanduser("~/Library/Application Support")
    else:
        rel = _LINUX_USER_DATA.get(name)
        root = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    if not rel:
        return None
    path = os.path.join(root, rel)
    return path if os.path.isdir(path) else None


def parse_chrome_profiles(local_state: dict) -> list[tuple[str, str]]:
    """Profiles from a parsed `Local State`, as (dir_name, label) in Chrome's UI order.

    label is the profile's display name, with the signed-in account appended when it
    differs (e.g. ``Work (me@corp.com)``)."""
    prof = local_state.get("profile", {})
    cache = prof.get("info_cache", {})
    order = prof.get("profiles_order") or []
    # Honour profiles_order, then append any cache entries it omits (sorted, stable).
    ordered = [d for d in order if d in cache] + [d for d in sorted(cache) if d not in order]
    out = []
    for dirn in ordered:
        info = cache.get(dirn, {})
        name = info.get("name") or dirn
        email = info.get("user_name") or ""
        label = f"{name} ({email})" if email and email != name else name
        out.append((dirn, label))
    return out


def chrome_profiles(binary: str) -> list[tuple[str, str, str]]:
    """Discover existing profiles for a Chrome binary as (user_data_dir, dir_name, label).

    Empty if the binary maps to no known user-data-dir, or its `Local State` is missing
    or unreadable — so callers can simply hide the option when nothing turns up."""
    udd = chrome_user_data_dir(binary)
    if not udd:
        return []
    try:
        with open(os.path.join(udd, "Local State"), encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        return []
    return [(udd, dirn, label) for dirn, label in parse_chrome_profiles(state)]
