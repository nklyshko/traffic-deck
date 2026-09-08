"""Tests for the Firefox profile-path handling (no browser/gateway). The logic lives in
capture_firefox.profiles, shared by the interactive picker and serve-mode Describe."""

from __future__ import annotations

import tempfile

from capture_firefox import profiles


def snap_as(monkeypatch, name, common=None):
    """Make every binary look like (or not like) a snap, as capture_sdk.snap sees it."""
    monkeypatch.setattr(profiles.browser.snap, "name", lambda _b: name)
    if common is not None:
        monkeypatch.setattr(profiles.browser.snap, "user_common", lambda _n: common)


def test_temp_profile_is_seeded_with_prefs(monkeypatch):
    # Firefox has no --no-first-run/--no-default-browser-check flags; the equivalent is
    # a user.js in the profile, or every capture opens onto the first-run tour.
    snap_as(monkeypatch, None)
    prof = profiles.temp_profile("/usr/bin/firefox")
    userjs = (profiles.os.path.join(prof, "user.js"))
    assert profiles.os.path.exists(userjs)
    assert "browser.shell.checkDefaultBrowser" in open(userjs).read()


def test_temp_profile_unconfined_uses_tmp(monkeypatch):
    snap_as(monkeypatch, None)
    assert profiles.temp_profile("/usr/bin/firefox").startswith(tempfile.gettempdir())


def test_temp_profile_snap_under_common(monkeypatch, tmp_path):
    snap_as(monkeypatch, "firefox", str(tmp_path / "common"))
    assert profiles.temp_profile("/snap/bin/firefox").startswith(str(tmp_path / "common"))


def test_profiles_dir_snap_uses_snap_common(monkeypatch, tmp_path):
    snap_as(monkeypatch, "firefox", str(tmp_path / "common"))
    assert profiles.profiles_dir("/snap/bin/firefox") == str(
        tmp_path / "common" / "td-firefox-profiles")


def test_persistent_path_creates_and_seeds(monkeypatch, tmp_path):
    monkeypatch.setattr(profiles, "profiles_dir", lambda _f: str(tmp_path))
    p = profiles.persistent_path("/usr/bin/firefox", "work")
    assert p == str(tmp_path / "work") and (tmp_path / "work").is_dir()
    assert (tmp_path / "work" / "user.js").exists()
    # No name falls back to "default".
    assert profiles.persistent_path("/usr/bin/firefox", "") == str(tmp_path / "default")


def test_seed_prefs_never_overwrites(monkeypatch, tmp_path):
    # A persistent profile is reused across captures; user edits must survive.
    (tmp_path / "user.js").write_text("user_pref(\"mine\", true);\n")
    profiles.seed_prefs(str(tmp_path))
    assert (tmp_path / "user.js").read_text() == "user_pref(\"mine\", true);\n"


def test_saved_profiles_lists_subdirs(monkeypatch, tmp_path):
    (tmp_path / "work").mkdir()
    (tmp_path / "research").mkdir()
    (tmp_path / "notes.txt").write_text("x")  # files are ignored
    monkeypatch.setattr(profiles, "profiles_dir", lambda _f: str(tmp_path))
    assert profiles.saved_profiles("firefox") == ["research", "work"]


def test_resolve_existing_maps_name_to_root(monkeypatch):
    monkeypatch.setattr(profiles.platform, "firefox_profiles",
                        lambda _f: [("/u/.mozilla/firefox", "default", "a.default"),
                                    ("/u/.mozilla/firefox", "work", "b.work")])
    assert profiles.resolve_existing("firefox", "work") == ("/u/.mozilla/firefox", "work")
    # Unknown name falls back to the binary's root.
    monkeypatch.setattr(profiles.platform, "firefox_root", lambda _f: "/u/.mozilla/firefox")
    assert profiles.resolve_existing("firefox", "ghost") == ("/u/.mozilla/firefox", "ghost")
