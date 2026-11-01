"""Where a capture runs and how its frida venv comes to exist (ADR-0017 §5)."""

from __future__ import annotations

import subprocess
import threading

import pytest

from capture_android import frida_env


@pytest.fixture
def prefix(tmp_path, monkeypatch):
    (tmp_path / "venvs/android-frida17").mkdir(parents=True)
    monkeypatch.setattr(frida_env, "installed_prefix", lambda: tmp_path)
    monkeypatch.setattr(frida_env, "_builds", {})
    monkeypatch.setattr(frida_env, "_errors", {})
    return tmp_path


def test_checkout_layers_frida_on_with_uv(monkeypatch):
    monkeypatch.setattr(frida_env, "installed_prefix", lambda: None)
    cmd = frida_env.python_cmd("capture_android.headless", "17.15.1")
    assert cmd[:2] == ["uv", "run"] and "frida==17.15.1" in cmd
    assert "--with" not in frida_env.python_cmd("capture_android.headless")


def test_installed_runs_the_versions_venv_without_uv(prefix):
    cmd = frida_env.python_cmd("capture_android.headless", "16.7.19")
    assert cmd == [str(prefix / "venvs/android-frida16/bin/python"), "-m", "capture_android.headless"]


def test_a_built_venv_is_not_rebuilt(prefix, monkeypatch):
    (prefix / "venvs/android-frida17/.ready").touch()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("rebuilt"))
    frida_env.ensure_frida("17.15.1")


def test_a_build_installs_every_first_party_wheel(prefix, monkeypatch):
    # --no-deps, so a wheel missing here only shows up as an import error at first use.
    runs = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **_: runs.append(cmd))
    frida_env.ensure_frida("17.15.1")
    assert {"trafficdeck-proto", "trafficdeck-capture-sdk", "trafficdeck-capture-android"} <= set(runs[-1])


def test_a_timed_out_caller_leaves_the_build_running_for_its_retry(prefix, monkeypatch):
    release = threading.Event()
    runs = []

    def slow_run(cmd, **_):
        runs.append(cmd)
        release.wait(5)

    monkeypatch.setattr(subprocess, "run", slow_run)
    with pytest.raises(frida_env.FridaNotReady):
        frida_env.ensure_frida("17.15.1", wait=0.05)
    with pytest.raises(frida_env.FridaNotReady):
        frida_env.ensure_frida("17.15.1", wait=0.05)
    assert len(runs) == 1  # the retry joined the build rather than starting another

    release.set()
    frida_env.ensure_frida("17.15.1")
    assert (prefix / "venvs/android-frida17/.ready").exists()


def test_missing_uv_says_so(prefix, monkeypatch):
    def no_uv(*_a, **_k):
        raise FileNotFoundError("uv")

    monkeypatch.setattr(subprocess, "run", no_uv)
    with pytest.raises(RuntimeError, match="`uv` is needed"):
        frida_env.ensure_frida("17.15.1")


def test_a_failed_build_is_retried(prefix, monkeypatch):
    def fail(cmd, **_):
        raise subprocess.CalledProcessError(1, cmd, stderr="error: no route to host\n")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="no route to host"):
        frida_env.ensure_frida("17.15.1")

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: None)
    frida_env.ensure_frida("17.15.1")
