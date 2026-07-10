"""Unit tests for the host-independent Chrome discovery helpers (no browser needed)."""
from __future__ import annotations

import json

from capture_chrome import platform


def test_parse_chrome_profiles_orders_and_labels():
    state = {
        "profile": {
            "info_cache": {
                "Default": {"name": "Никита", "user_name": "me@gmail.com"},
                "Profile 1": {"name": "Work", "user_name": "me@corp.com"},
                "Profile 2": {"name": "Guest"},  # no account → name only
            },
            "profiles_order": ["Profile 1", "Default"],  # Profile 2 omitted on purpose
        }
    }
    profiles = platform.parse_chrome_profiles(state)
    # profiles_order is honoured first, then cache-only entries appended (sorted).
    assert profiles == [
        ("Profile 1", "Work (me@corp.com)"),
        ("Default", "Никита (me@gmail.com)"),
        ("Profile 2", "Guest"),
    ]


def test_parse_chrome_profiles_empty():
    assert platform.parse_chrome_profiles({}) == []
    assert platform.parse_chrome_profiles({"profile": {"info_cache": {}}}) == []


def test_parse_chrome_profiles_label_collapses_duplicate_email():
    # When name == user_name (common for unnamed accounts), don't repeat it.
    state = {"profile": {"info_cache": {"Default": {"name": "a@b.com", "user_name": "a@b.com"}}}}
    assert platform.parse_chrome_profiles(state) == [("Default", "a@b.com")]


def test_chrome_user_data_dir_unknown_binary():
    assert platform.chrome_user_data_dir("/usr/bin/not-a-browser") is None


def test_snap_name_shim_script(tmp_path, monkeypatch):
    # Ubuntu's transitional /usr/bin/chromium-browser shim: a shell script that execs the
    # snap launcher. Detected by the /snap/bin/<name> reference regardless of the filename.
    monkeypatch.setattr(platform.sys, "platform", "linux")
    shim = tmp_path / "chromium-browser"
    shim.write_text("#!/bin/sh\n# ...\nexec /snap/bin/chromium \"$@\"\n")
    assert platform.snap_name(str(shim)) == "chromium"


def test_snap_name_non_snap_binary(tmp_path, monkeypatch):
    # A plain (unconfined) executable has no snap reference → None (uses /tmp as usual).
    monkeypatch.setattr(platform.sys, "platform", "linux")
    exe = tmp_path / "google-chrome"
    exe.write_bytes(b"\x7fELF not a snap")
    assert platform.snap_name(str(exe)) is None
    # A missing binary is simply not a snap, not an error.
    assert platform.snap_name(str(tmp_path / "nope")) is None


def test_snap_name_darwin_never_snap(tmp_path, monkeypatch):
    monkeypatch.setattr(platform.sys, "platform", "darwin")
    shim = tmp_path / "chromium-browser"
    shim.write_text("exec /snap/bin/chromium\n")
    assert platform.snap_name(str(shim)) is None


def test_snap_user_common():
    assert platform.snap_user_common("chromium").endswith("/snap/chromium/common")


def test_chrome_user_data_dir_snap(tmp_path, monkeypatch):
    # A snap browser keeps its profiles under $SNAP_USER_COMMON/<name>, not ~/.config.
    monkeypatch.setattr(platform, "snap_name", lambda _b: "chromium")
    monkeypatch.setattr(platform, "snap_user_common", lambda _n: str(tmp_path))
    assert platform.chrome_user_data_dir("/snap/bin/chromium") is None  # dir absent yet
    (tmp_path / "chromium").mkdir()
    assert platform.chrome_user_data_dir("/snap/bin/chromium") == str(tmp_path / "chromium")


def test_chrome_profiles_missing_local_state(tmp_path, monkeypatch):
    # A known binary whose user-data-dir has no Local State yields no profiles.
    monkeypatch.setattr(platform, "chrome_user_data_dir", lambda _b: str(tmp_path))
    assert platform.chrome_profiles("google-chrome") == []
    # ...and once Local State exists, profiles parse through.
    (tmp_path / "Local State").write_text(
        json.dumps({"profile": {"info_cache": {"Default": {"name": "Me"}}}}))
    assert platform.chrome_profiles("google-chrome") == [(str(tmp_path), "Default", "Me")]
