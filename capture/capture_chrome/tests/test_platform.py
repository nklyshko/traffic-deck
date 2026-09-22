"""Unit tests for the host-independent Chrome discovery helpers (no browser needed)."""
from __future__ import annotations

import json
import os

from capture_chrome import platform, profiles


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


def test_chrome_user_data_dir_snap(tmp_path, monkeypatch):
    # A snap browser keeps its profiles under $SNAP_USER_COMMON/<name>, not ~/.config.
    # (Snap *detection* itself is capture_sdk's — see capture_sdk/tests/test_snap.py.)
    monkeypatch.setattr(platform.snap, "name", lambda _b: "chromium")
    monkeypatch.setattr(platform.snap, "user_common", lambda _n: str(tmp_path))
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


def test_running_instance(tmp_path):
    lock = tmp_path / "SingletonLock"
    assert platform.running_instance(str(tmp_path)) is None  # no lock at all

    # A lock naming a live pid (our own) means a Chrome holds this profile.
    lock.symlink_to(f"somehost-{os.getpid()}")
    assert platform.running_instance(str(tmp_path)) == os.getpid()

    # A lock left by a crashed instance names a pid that no longer exists — not running.
    lock.unlink()
    lock.symlink_to("somehost-2147483646")
    assert platform.running_instance(str(tmp_path)) is None

    # Anything that isn't <host>-<pid> is not a claim we can read.
    lock.unlink()
    lock.symlink_to("garbage")
    assert platform.running_instance(str(tmp_path)) is None


def test_user_data_dir_covers_every_launch_form(tmp_path, monkeypatch):
    # The singleton is keyed on the user-data-dir, so the preflight has to find it for all
    # three forms a profile resolves to — including the sentinel, where it is the binary's
    # own default dir (the case Cmd+Q actually bites).
    monkeypatch.setattr(platform, "chrome_user_data_dir", lambda _b: "/default/udd")
    assert profiles.user_data_dir("chrome", profiles.BUILTIN_PROFILE) == "/default/udd"
    assert profiles.user_data_dir("chrome", ("/some/udd", "Profile 1")) == "/some/udd"
    assert profiles.user_data_dir("chrome", str(tmp_path)) == str(tmp_path)
