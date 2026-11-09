"""Where a capture runs, and under which frida (ADR-0017 §5)."""

from __future__ import annotations

import sys

import pytest

from capture_android import frida_env


@pytest.fixture
def prefix(tmp_path, monkeypatch):
    python = tmp_path / "venvs/android-frida-16.7.19/bin/python"
    python.parent.mkdir(parents=True)
    python.touch()
    monkeypatch.setattr(frida_env, "installed_prefix", lambda: tmp_path)
    return tmp_path


def test_checkout_layers_frida_on_with_uv(monkeypatch):
    monkeypatch.setattr(frida_env, "installed_prefix", lambda: None)
    cmd = frida_env.python_cmd("capture_android.headless", "17.15.1")
    assert cmd[:2] == ["uv", "run"] and "frida==17.15.1" in cmd
    assert "--with" not in frida_env.python_cmd("capture_android.headless")


def test_installed_runs_the_versions_venv_without_uv(prefix):
    cmd = frida_env.python_cmd("capture_android.headless", "16.7.19")
    assert cmd == [str(prefix / "venvs/android-frida-16.7.19/bin/python"), "-m",
                   "capture_android.headless"]


def test_installed_without_frida_runs_in_this_interpreter(prefix):
    # The proxy method loads no frida, so it needs no frida venv.
    assert frida_env.python_cmd("capture_android.headless") == [
        sys.executable, "-m", "capture_android.headless"]


def test_a_version_the_install_does_not_hold_is_refused(prefix):
    # Same major, different version: running it would be a client/server mismatch on the
    # device, so it must not pass for the 16.x that is there.
    with pytest.raises(RuntimeError, match="frida 16.7.0 is not part of the install"):
        frida_env.python_cmd("capture_android.headless", "16.7.0")


def test_install_builds_a_venv_for_every_supported_version():
    # install.sh reads the versions from frida_versions.py; the names must line up with
    # what python_cmd looks for.
    from pathlib import Path

    from capture_android import frida_versions

    script = (Path(__file__).resolve().parents[3] / "scripts/install.sh").read_text()
    assert "print(*v.SUPPORTED)" in script
    assert '"$PREFIX/venvs/android-frida-$v"' in script
    assert {frida_versions.V16, frida_versions.V17} <= set(frida_versions.SUPPORTED)
    for v in frida_versions.SUPPORTED:
        assert frida_env._env_dir(Path("/p"), v) == Path(f"/p/venvs/android-frida-{v}")
