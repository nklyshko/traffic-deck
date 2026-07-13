"""Tests for the Chrome profile-path handling (no browser/gateway). The logic lives in
capture_chrome.profiles, shared by the interactive picker and serve-mode Describe."""

from __future__ import annotations

from capture_chrome import profiles


def test_profiles_dir_migrates_legacy(monkeypatch, tmp_path):
    legacy = tmp_path / "legacy"
    dest = tmp_path / "chrome-profiles"
    (legacy / "work").mkdir(parents=True)
    (legacy / "work" / "marker").write_text("x")
    monkeypatch.setattr(profiles, "_PROFILES_DIR", str(dest))
    monkeypatch.setattr(profiles, "_LEGACY_PROFILES_DIR", str(legacy))

    # An unconfined browser uses the ~/.traffic-deck home and runs the legacy migration.
    assert profiles.profiles_dir("google-chrome") == str(dest)
    # Legacy profile is moved (not copied) into the new home.
    assert (dest / "work" / "marker").read_text() == "x"
    assert not (legacy / "work").exists()


def test_profiles_dir_keeps_existing_over_legacy(monkeypatch, tmp_path):
    legacy = tmp_path / "legacy"
    dest = tmp_path / "chrome-profiles"
    (legacy / "work").mkdir(parents=True)
    (legacy / "work" / "marker").write_text("old")
    (dest / "work").mkdir(parents=True)
    (dest / "work" / "marker").write_text("new")
    monkeypatch.setattr(profiles, "_PROFILES_DIR", str(dest))
    monkeypatch.setattr(profiles, "_LEGACY_PROFILES_DIR", str(legacy))

    profiles.profiles_dir("google-chrome")
    # An already-relocated profile of the same name is not clobbered by the legacy copy.
    assert (dest / "work" / "marker").read_text() == "new"


def test_profiles_dir_snap_uses_snap_common(monkeypatch, tmp_path):
    # A snap browser keeps persistent profiles under its own writable area (confinement
    # blocks the hidden ~/.traffic-deck) and skips the legacy migration entirely.
    legacy = tmp_path / "legacy"
    (legacy / "work").mkdir(parents=True)
    monkeypatch.setattr(profiles, "_LEGACY_PROFILES_DIR", str(legacy))
    monkeypatch.setattr(profiles.platform, "snap_name", lambda _b: "chromium")
    monkeypatch.setattr(profiles.platform, "snap_user_common", lambda _n: str(tmp_path / "common"))

    got = profiles.profiles_dir("/snap/bin/chromium")
    assert got == str(tmp_path / "common" / "td-chrome-profiles")
    # Legacy dir is left untouched (no migration into a snap area).
    assert (legacy / "work").exists()


def test_temp_profile_snap_under_common(monkeypatch, tmp_path):
    monkeypatch.setattr(profiles.platform, "snap_name", lambda _b: "chromium")
    monkeypatch.setattr(profiles.platform, "snap_user_common", lambda _n: str(tmp_path / "common"))
    prof = profiles.temp_profile("/snap/bin/chromium")
    assert prof.startswith(str(tmp_path / "common"))


def test_temp_profile_unconfined_uses_tmp(monkeypatch):
    monkeypatch.setattr(profiles.platform, "snap_name", lambda _b: None)
    prof = profiles.temp_profile("/usr/bin/google-chrome")
    assert prof.startswith(profiles.tempfile.gettempdir())


def test_saved_profiles_lists_subdirs(monkeypatch, tmp_path):
    (tmp_path / "work").mkdir()
    (tmp_path / "research").mkdir()
    (tmp_path / "notes.txt").write_text("x")  # files are ignored
    monkeypatch.setattr(profiles, "profiles_dir", lambda _b: str(tmp_path))
    assert profiles.saved_profiles("chrome") == ["research", "work"]


def test_persistent_path_creates_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(profiles, "profiles_dir", lambda _b: str(tmp_path))
    p = profiles.persistent_path("chrome", "work")
    assert p == str(tmp_path / "work") and (tmp_path / "work").is_dir()
    # No name falls back to "default".
    assert profiles.persistent_path("chrome", "") == str(tmp_path / "default")


def test_resolve_existing_maps_dir_to_udd(monkeypatch):
    monkeypatch.setattr(profiles.platform, "chrome_profiles",
                        lambda _b: [("/u/.config/chrome", "Default", "Personal"),
                                    ("/u/.config/chrome", "Profile 2", "Work")])
    assert profiles.resolve_existing("chrome", "Profile 2") == ("/u/.config/chrome", "Profile 2")
    # Unknown dir falls back to the binary's user-data-dir.
    monkeypatch.setattr(profiles.platform, "chrome_user_data_dir", lambda _b: "/u/.config/chrome")
    assert profiles.resolve_existing("chrome", "Ghost") == ("/u/.config/chrome", "Ghost")
