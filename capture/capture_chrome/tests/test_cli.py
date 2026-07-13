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


def test_profile_choices_flattens_the_picker_tree(monkeypatch):
    # The cascade's leaves as one flat list: fixed kinds + each discovered profile + each
    # saved one + "new" — what a viewer form renders instead of the CLI's tree.
    monkeypatch.setattr(profiles.platform, "chrome_profiles",
                        lambda _b: [("/u/.config/chrome", "Default", "Personal")])
    monkeypatch.setattr(profiles, "_saved_profiles", lambda _b: ["research"])

    values = [v for v, _ in profiles.profile_choices("chrome")]
    assert values == ["default", "temp",
                      "existing:/u/.config/chrome\x1fDefault", "saved:research", "new"]


def test_resolve_profile_round_trips_each_value(monkeypatch, tmp_path):
    monkeypatch.setattr(profiles, "temp_profile", lambda _b: "/tmp/x")
    monkeypatch.setattr(profiles, "profiles_dir", lambda _b: str(tmp_path))

    assert profiles.resolve_profile("chrome", "default") is profiles.BUILTIN_PROFILE
    assert profiles.resolve_profile("chrome", "temp") == "/tmp/x"
    assert profiles.resolve_profile("chrome", "") == "/tmp/x"  # empty => temp
    assert profiles.resolve_profile("chrome", "existing:/u/dd\x1fProfile 2") == ("/u/dd", "Profile 2")
    # saved/new create the directory under profiles_dir.
    assert profiles.resolve_profile("chrome", "saved:work") == str(tmp_path / "work")
    assert (tmp_path / "work").is_dir()
    assert profiles.resolve_profile("chrome", "new", new_name="fresh") == str(tmp_path / "fresh")
    # A bare path passes through (the CLI's --profile-dir).
    assert profiles.resolve_profile("chrome", "/explicit/dir") == "/explicit/dir"
