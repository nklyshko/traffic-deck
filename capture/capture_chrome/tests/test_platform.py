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


def test_chrome_profiles_missing_local_state(tmp_path, monkeypatch):
    # A known binary whose user-data-dir has no Local State yields no profiles.
    monkeypatch.setattr(platform, "chrome_user_data_dir", lambda _b: str(tmp_path))
    assert platform.chrome_profiles("google-chrome") == []
    # ...and once Local State exists, profiles parse through.
    (tmp_path / "Local State").write_text(
        json.dumps({"profile": {"info_cache": {"Default": {"name": "Me"}}}}))
    assert platform.chrome_profiles("google-chrome") == [(str(tmp_path), "Default", "Me")]
