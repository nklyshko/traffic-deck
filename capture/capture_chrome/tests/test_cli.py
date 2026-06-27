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

    assert cli._profiles_dir() == str(dest)
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

    cli._profiles_dir()
    # An already-relocated profile of the same name is not clobbered by the legacy copy.
    assert (dest / "work" / "marker").read_text() == "new"
