"""Unit tests for the host-independent Firefox discovery helpers (no browser needed)."""
from __future__ import annotations

from capture_firefox import platform


def test_parse_profiles_ini_install_default_first():
    # Modern Firefox pins the profile an install opens via [InstallXXX] Default=<path>.
    # That profile leads, whatever order the sections appear in.
    ini = """
[Profile0]
Name=default
Path=abc.default
[Profile1]
Name=work
Path=xyz.work
[Install4F96D1932A9F858E]
Default=xyz.work
Locked=1
"""
    assert platform.parse_profiles_ini(ini) == [
        ("work", "xyz.work"),
        ("default", "abc.default"),
    ]


def test_parse_profiles_ini_legacy_default_flag():
    # Older registries mark the default inside the [ProfileN] section instead.
    ini = """
[Profile0]
Name=first
Path=a.first
[Profile1]
Name=second
Path=b.second
Default=1
"""
    assert platform.parse_profiles_ini(ini) == [("second", "b.second"), ("first", "a.first")]


def test_parse_profiles_ini_install_wins_over_legacy_flag():
    ini = """
[Profile0]
Name=legacy
Path=a.legacy
Default=1
[Profile1]
Name=pinned
Path=b.pinned
[Install01]
Default=b.pinned
"""
    assert platform.parse_profiles_ini(ini)[0] == ("pinned", "b.pinned")


def test_parse_profiles_ini_no_default_keeps_file_order():
    ini = """
[Profile0]
Name=one
Path=a.one
[Profile1]
Name=two
Path=b.two
"""
    assert platform.parse_profiles_ini(ini) == [("one", "a.one"), ("two", "b.two")]


def test_parse_profiles_ini_falls_back_to_path_when_unnamed():
    assert platform.parse_profiles_ini("[Profile0]\nPath=a.default\n") == [
        ("a.default", "a.default")]


def test_parse_profiles_ini_skips_entries_without_a_path():
    # A registry entry with no directory can't be launched, so it isn't offered.
    ini = "[Profile0]\nName=broken\n[Profile1]\nName=ok\nPath=b.ok\n"
    assert platform.parse_profiles_ini(ini) == [("ok", "b.ok")]


def test_parse_profiles_ini_tolerates_garbage():
    # Unreadable registries yield fewer profiles, never an exception — the picker just
    # offers less rather than the tool failing to start.
    assert platform.parse_profiles_ini("") == []
    assert platform.parse_profiles_ini("not an ini at all") == []
    assert platform.parse_profiles_ini("[General]\nStartWithLastProfile=1\n") == []


def test_parse_profiles_ini_ignores_general_section():
    ini = "[General]\nStartWithLastProfile=1\nVersion=2\n[Profile0]\nName=x\nPath=p.x\n"
    assert platform.parse_profiles_ini(ini) == [("x", "p.x")]


def test_firefox_profiles_missing_ini(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "firefox_root", lambda _b: str(tmp_path))
    assert platform.firefox_profiles("firefox") == []
    # ...and once profiles.ini exists, profiles parse through with their root attached.
    (tmp_path / "profiles.ini").write_text("[Profile0]\nName=Me\nPath=a.me\n")
    assert platform.firefox_profiles("firefox") == [(str(tmp_path), "Me", "a.me")]


def test_firefox_root_unknown_binary_falls_back_to_mozilla(monkeypatch):
    # Unlike Chrome — where each channel owns a distinct user-data-dir, so an unknown
    # binary maps nowhere — every Firefox channel shares one root. A binary we don't
    # recognize is far more likely a Firefox installed somewhere unusual (a tarball
    # build, FIREFOX_BIN pointing into /opt) than a different browser, so it gets the
    # Mozilla root rather than nothing.
    monkeypatch.setattr(platform.snap, "name", lambda _b: None)
    monkeypatch.setattr(platform.sys, "platform", "linux")
    monkeypatch.setattr(platform.os.path, "isdir", lambda _p: True)
    home = platform.os.path.expanduser("~")
    assert platform.firefox_root("/opt/firefox-custom/firefox-bin") == f"{home}/.mozilla/firefox"


def test_firefox_root_none_when_dir_absent(monkeypatch):
    # Nothing registered yet (a fresh machine, or a fork never launched) → no profiles.
    monkeypatch.setattr(platform.snap, "name", lambda _b: None)
    monkeypatch.setattr(platform.os.path, "isdir", lambda _p: False)
    assert platform.firefox_root("/usr/bin/firefox") is None


def test_firefox_profiles_empty_without_a_root(monkeypatch):
    monkeypatch.setattr(platform, "firefox_root", lambda _b: None)
    assert platform.firefox_profiles("/usr/bin/firefox") == []


def test_firefox_root_forks_are_separate(tmp_path, monkeypatch):
    # LibreWolf/Waterfox/Zen keep their profiles apart from Mozilla's. Keyed by fork, so
    # every channel of one fork shares a root (Developer Edition lists its profiles in
    # the same profiles.ini as release).
    monkeypatch.setattr(platform.snap, "name", lambda _b: None)
    monkeypatch.setattr(platform.sys, "platform", "linux")
    monkeypatch.setattr(platform.os.path, "isdir", lambda _p: True)
    home = platform.os.path.expanduser("~")
    assert platform.firefox_root("/usr/bin/firefox") == f"{home}/.mozilla/firefox"
    assert platform.firefox_root("/usr/bin/firefox-nightly") == f"{home}/.mozilla/firefox"
    assert platform.firefox_root("/usr/bin/librewolf") == f"{home}/.librewolf"
    assert platform.firefox_root("/usr/bin/waterfox") == f"{home}/.waterfox"


def test_firefox_root_snap_uses_snap_common(tmp_path, monkeypatch):
    # A snap Firefox can't see ~/.mozilla; its profiles live in its own writable area.
    monkeypatch.setattr(platform.snap, "name", lambda _b: "firefox")
    monkeypatch.setattr(platform.snap, "user_common", lambda _n: str(tmp_path))
    assert platform.firefox_root("/snap/bin/firefox") is None  # dir absent yet
    (tmp_path / ".mozilla" / "firefox").mkdir(parents=True)
    assert platform.firefox_root("/snap/bin/firefox") == str(tmp_path / ".mozilla" / "firefox")
