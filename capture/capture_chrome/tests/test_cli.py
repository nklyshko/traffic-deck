"""Tests for the Chrome CLI's persistent-profile relocation (no browser/gateway)."""

from __future__ import annotations

from capture_chrome import cli


def test_profiles_dir_migrates_legacy(monkeypatch, tmp_path):
    legacy = tmp_path / "legacy"
    dest = tmp_path / "chrome-profiles"
    (legacy / "work").mkdir(parents=True)
    (legacy / "work" / "marker").write_text("x")
    monkeypatch.setattr(cli, "_PROFILES_DIR", str(dest))
    monkeypatch.setattr(cli, "_LEGACY_PROFILES_DIR", str(legacy))

    # An unconfined browser uses the ~/.traffic-deck home and runs the legacy migration.
    assert cli._profiles_dir("google-chrome") == str(dest)
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
    monkeypatch.setattr(cli, "_PROFILES_DIR", str(dest))
    monkeypatch.setattr(cli, "_LEGACY_PROFILES_DIR", str(legacy))

    cli._profiles_dir("google-chrome")
    # An already-relocated profile of the same name is not clobbered by the legacy copy.
    assert (dest / "work" / "marker").read_text() == "new"


def test_profiles_dir_snap_uses_snap_common(monkeypatch, tmp_path):
    # A snap browser keeps persistent profiles under its own writable area (confinement
    # blocks the hidden ~/.traffic-deck) and skips the legacy migration entirely.
    legacy = tmp_path / "legacy"
    (legacy / "work").mkdir(parents=True)
    monkeypatch.setattr(cli, "_LEGACY_PROFILES_DIR", str(legacy))
    monkeypatch.setattr(cli.platform, "snap_name", lambda _b: "chromium")
    monkeypatch.setattr(cli.platform, "snap_user_common", lambda _n: str(tmp_path / "common"))

    got = cli._profiles_dir("/snap/bin/chromium")
    assert got == str(tmp_path / "common" / "td-chrome-profiles")
    # Legacy dir is left untouched (no migration into a snap area).
    assert (legacy / "work").exists()


def test_temp_profile_snap_under_common(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.platform, "snap_name", lambda _b: "chromium")
    monkeypatch.setattr(cli.platform, "snap_user_common", lambda _n: str(tmp_path / "common"))
    prof = cli._temp_profile("/snap/bin/chromium")
    assert prof.startswith(str(tmp_path / "common"))


def test_temp_profile_unconfined_uses_tmp(monkeypatch):
    monkeypatch.setattr(cli.platform, "snap_name", lambda _b: None)
    prof = cli._temp_profile("/usr/bin/google-chrome")
    assert prof.startswith(cli.tempfile.gettempdir())
