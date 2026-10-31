"""Discovery and profile-storage helpers shared by the browser capture tools.

A browser capture tool (`capture_chrome`, `capture_firefox`) has the same three jobs
regardless of engine: find the installed browsers, decide which profile to launch, and
keep tool-managed profiles somewhere the browser can actually write. The *how* differs
per engine (bundle names, profile registries, launch flags) and stays in the owning app;
the shape lives here.
"""

from __future__ import annotations

import os
import re
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
    """The dir holding a tool's named persistent profiles for `binary`, created on demand,
    with any profile an older build saved nested moved out (flatten_nested_profiles).

    For a snap browser this is `snap_dir` under the snap's own writable area — the hidden
    ~/.traffic-deck home is blocked by confinement — so persistent profiles are separate
    per snap; otherwise it is `unconfined`."""
    if base := snap.writable_base(binary):
        path = os.path.join(base, snap_dir)
    else:
        path = unconfined
    os.makedirs(path, exist_ok=True)
    flatten_nested_profiles(path)
    return path


_PATH_CHARS = re.compile(r"[/\\\0]")


def profile_folder(name: str) -> str:
    """The folder a saved profile called `name` lives in: the name with every character
    that would make it a path ("/", "\\", NUL) replaced by "-", and "." / ".." spelled as
    dashes. Always a single path component under the profiles root.

    Lossy on purpose, so folders stay readable: "client/acme" and "client-acme" are the
    same profile, and the picker lists it under its folder name. A plain name is its own
    folder, so every profile saved before is still found."""
    if name in (".", ".."):
        return "-" * len(name)
    return _PATH_CHARS.sub("-", name)


def saved_profiles(root: str) -> list[str]:
    """Names of the saved persistent profiles under `root` (its subdirectories)."""
    return sorted(n for n in os.listdir(root) if os.path.isdir(os.path.join(root, n)))


def flatten_nested_profiles(root: str) -> None:
    """Move profiles that older builds saved under a name with a "/" in it — `a/b` became
    the folders root/a/b — to the folder profile_folder gives that name now (`a-b`).
    Otherwise the picker lists only `a`, and choosing it hands the browser the parent.

    Such a parent holds only folders, and the profile inside carries the file a browser
    writes at a profile's top (_PROFILE_MARKERS). Both are required: a Chrome killed before
    writing Local State leaves a real profile holding only Default/, which must stay put.
    Nothing is moved over a folder that already exists. A deeper `a/b/c` becomes `a-b/c`
    on one pass and `a-b-c` on the next."""
    moved = True
    while moved:
        moved = False
        for name in os.listdir(root):
            parent = os.path.join(root, name)
            if not _is_nested_parent(parent):
                continue
            for child in os.listdir(parent):
                target = os.path.join(root, profile_folder(f"{name}/{child}"))
                if not os.path.exists(target):
                    os.rename(os.path.join(parent, child), target)
                    moved = True
            try:
                os.rmdir(parent)
            except OSError:
                pass  # a name clash kept something behind; leave it for the user


# Chrome's user-data dir has Local State at its top; a Firefox profile has prefs.js and
# times.json.
_PROFILE_MARKERS = ("Local State", "prefs.js", "times.json")


def _is_nested_parent(path: str) -> bool:
    if not os.path.isdir(path) or os.path.islink(path):
        return False
    entries = [os.path.join(path, e) for e in os.listdir(path)]
    return (bool(entries) and all(os.path.isdir(e) for e in entries)
            and any(_holds_profile(e) for e in entries))


def _holds_profile(path: str) -> bool:
    return (any(os.path.isfile(os.path.join(path, m)) for m in _PROFILE_MARKERS)
            or _is_nested_parent(path))


def persistent_path(root: str, name: str) -> str:
    """The profile dir for a saved persistent profile `name` under `root`, created on
    demand. An empty name falls back to "default".

    `name` arrives from a capture request (new_profile_name / saved_profile) and may hold
    anything, so it goes through profile_folder: "../x" or "/etc" (which os.path.join would
    honour outright) names a profile, never a directory outside `root`."""
    path = os.path.join(root, profile_folder(name or "default"))
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


def launch_metadata(binary: str, profile, url: str | None = None, extra_args=()) -> dict[str, str]:
    """Session metadata describing how a browser was launched, for `open_metadata`.

    Shared by the browser runners rather than written per tool: what a person wants when
    reading a session back ("which browser, which profile, which page") is the same whether
    it was Chrome or Firefox, and the keys should be too — a comparison across two sessions
    from different browsers is the case that breaks when they drift. Hence `browser.*` and
    not `chrome.*`.

    Only `url` is omitted when unset; the rest are always stated, because a missing key
    reads as "unknown" rather than as a default."""
    md = {
        "browser.binary": binary,
        "browser.profile": profile_desc(profile),
    }
    if url:
        md["browser.url"] = url
    if args := [a for a in extra_args if a != "--"]:
        md["browser.extra_args"] = " ".join(args)
    return md
