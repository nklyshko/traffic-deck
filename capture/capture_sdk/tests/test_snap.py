"""Snap detection (host-independent — no snap needed, no browser launched)."""
from __future__ import annotations

from capture_sdk import snap


def test_name_shim_script(tmp_path, monkeypatch):
    # Ubuntu's transitional /usr/bin/chromium-browser shim: a shell script that execs the
    # snap launcher. Detected by the /snap/bin/<name> reference regardless of the filename.
    monkeypatch.setattr(snap.sys, "platform", "linux")
    shim = tmp_path / "chromium-browser"
    shim.write_text("#!/bin/sh\n# ...\nexec /snap/bin/chromium \"$@\"\n")
    assert snap.name(str(shim)) == "chromium"


def test_name_non_snap_binary(tmp_path, monkeypatch):
    # A plain (unconfined) executable has no snap reference → None (uses /tmp as usual).
    monkeypatch.setattr(snap.sys, "platform", "linux")
    exe = tmp_path / "google-chrome"
    exe.write_bytes(b"\x7fELF not a snap")
    assert snap.name(str(exe)) is None
    # A missing binary is simply not a snap, not an error.
    assert snap.name(str(tmp_path / "nope")) is None


def test_name_darwin_never_snap(tmp_path, monkeypatch):
    monkeypatch.setattr(snap.sys, "platform", "darwin")
    shim = tmp_path / "firefox"
    shim.write_text("exec /snap/bin/firefox\n")
    assert snap.name(str(shim)) is None


def test_user_common():
    assert snap.user_common("firefox").endswith("/snap/firefox/common")


def test_writable_base_creates_dir_for_snap(tmp_path, monkeypatch):
    monkeypatch.setattr(snap, "name", lambda _b: "firefox")
    monkeypatch.setattr(snap, "user_common", lambda _n: str(tmp_path / "common"))
    assert snap.writable_base("/snap/bin/firefox") == str(tmp_path / "common")
    assert (tmp_path / "common").is_dir()  # created on demand


def test_writable_base_none_when_unconfined(monkeypatch):
    monkeypatch.setattr(snap, "name", lambda _b: None)
    assert snap.writable_base("/usr/bin/firefox") is None
