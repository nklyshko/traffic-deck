"""Cross-platform (Linux + macOS) discovery of the Firefox-family browsers on this host
and the profiles each of them registers. The generic parts — browser discovery mechanics,
snap confinement, dumpcap and the capture interface — live in `capture_sdk`.

Firefox differs from Chrome in two ways that shape this module. Every channel of the same
fork shares one profile root (there is no per-channel directory), so the root is keyed by
*fork* — Firefox, LibreWolf, Waterfox, Zen — not by binary name. And profiles are listed
in an INI registry (`profiles.ini`) naming them, rather than a JSON blob keyed by
directory.
"""

from __future__ import annotations

import configparser
import os
import sys

from capture_sdk import browser, snap

# macOS browsers are .app bundles, not on PATH — each entry is the executable path
# inside the bundle, searched under every dir in browser.APP_DIRS. Every Firefox channel
# ships the same executable name (`firefox`); the bundle it sits in is what differs.
_MAC_FIREFOX_BUNDLES = [
    "Firefox.app/Contents/MacOS/firefox",
    "Firefox Developer Edition.app/Contents/MacOS/firefox",
    "Firefox Nightly.app/Contents/MacOS/firefox",
    "Firefox ESR.app/Contents/MacOS/firefox",
    "LibreWolf.app/Contents/MacOS/librewolf",
    "Waterfox.app/Contents/MacOS/waterfox",
    "Zen Browser.app/Contents/MacOS/zen",
]
_FIREFOX_NAMES = (
    "firefox", "firefox-esr", "firefox-developer-edition", "firefox-nightly",
    "librewolf", "waterfox", "zen-browser", "zen",
)

# Forks keep their profiles apart from Mozilla's, under their own root. Keyed by the
# executable's basename, which is distinct per fork on both platforms (unlike per channel).
# value: (path under $HOME on Linux, path under ~/Library/Application Support on macOS)
_FORK_ROOTS = {
    "librewolf": (".librewolf", "LibreWolf"),
    "waterfox": (".waterfox", "Waterfox"),
    "zen": (".zen", "zen"),
    "zen-browser": (".zen", "zen"),
}
_MOZILLA_ROOT = (".mozilla/firefox", "Firefox")


def firefox_binaries() -> list[str]:
    """All discovered Firefox-family binaries, in preference order (FIREFOX_BIN first),
    de-duplicated. Used by the interactive picker.

    On macOS this scans the common .app bundles (Firefox + channels, LibreWolf, Waterfox,
    Zen) under /Applications and ~/Applications; elsewhere it looks up the known binary
    names on PATH."""
    return browser.discover(env_var="FIREFOX_BIN", mac_bundles=_MAC_FIREFOX_BUNDLES,
                            unix_names=_FIREFOX_NAMES)


def firefox_binary() -> str:
    if bins := firefox_binaries():
        return bins[0]
    raise RuntimeError("Firefox not found; set FIREFOX_BIN")


def firefox_root(binary: str) -> str | None:
    """The directory a Firefox binary registers its profiles in (the one holding
    `profiles.ini`), or None if it doesn't exist.

    All channels of one fork share this root — a Developer Edition install lists its
    profiles in the same `profiles.ini` as the release channel — so this is keyed by fork,
    not by binary."""
    # A snap browser can't see ~/.mozilla and keeps its profiles inside its own writable
    # $SNAP_USER_COMMON instead (~/snap/firefox/common/.mozilla/firefox).
    if snap_name := snap.name(binary):
        path = os.path.join(snap.user_common(snap_name), _MOZILLA_ROOT[0])
        return path if os.path.isdir(path) else None
    linux_rel, mac_rel = _FORK_ROOTS.get(os.path.basename(binary).lower(), _MOZILLA_ROOT)
    if sys.platform == "darwin":
        path = os.path.join(os.path.expanduser("~/Library/Application Support"), mac_rel)
    else:
        path = os.path.expanduser(os.path.join("~", linux_rel))
    return path if os.path.isdir(path) else None


def parse_profiles_ini(text: str) -> list[tuple[str, str]]:
    """Profiles from a `profiles.ini`, as (name, path) with the default profile first.

    "Default" is the one the browser itself would launch: the `Default=` of an `[InstallXXX]`
    section (how modern Firefox pins a profile per install), falling back to the legacy
    `Default=1` inside a `[ProfileN]` section. The rest follow in file order.

    Tolerant by design — a registry we can't make sense of yields fewer profiles, never an
    error, so the caller just offers less."""
    ini = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        ini.read_string(text)
    except configparser.Error:
        return []

    found: list[tuple[str, str]] = []
    install_default = legacy_default = ""
    for section in ini.sections():
        entry = ini[section]
        low = section.lower()
        if low.startswith("install"):
            # Several installs can be listed (release + nightly); the first names our best
            # guess at the default, and a wrong guess only reorders the picker.
            install_default = install_default or entry.get("default", "")
        elif low.startswith("profile"):
            path = entry.get("path", "")
            if not path:
                continue  # a registry entry with no directory can't be launched
            found.append((entry.get("name") or path, path))
            if entry.get("default", "0") == "1":
                legacy_default = legacy_default or path
    default = install_default or legacy_default
    return sorted(found, key=lambda np: np[1] != default)  # stable: default first


def firefox_profiles(binary: str) -> list[tuple[str, str, str]]:
    """Discover the registered profiles of a Firefox binary as (root, name, path).

    `name` is what launches the profile (`-P <name>`); `path` is its directory as
    `profiles.ini` records it, shown to disambiguate same-named profiles. Empty if the
    binary has no root yet or its `profiles.ini` is missing or unreadable — so callers can
    simply hide the option when nothing turns up."""
    root = firefox_root(binary)
    if not root:
        return []
    try:
        with open(os.path.join(root, "profiles.ini"), encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    return [(root, name, path) for name, path in parse_profiles_ini(text)]
