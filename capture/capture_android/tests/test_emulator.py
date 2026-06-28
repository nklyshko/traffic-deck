"""Unit tests for emulator boot-readiness (no real device/SDK)."""

from __future__ import annotations

import types

import pytest

from capture_android import emulator
from capture_android.emulator import Device, Sdk


def _sdk(monkeypatch) -> Sdk:
    # Bypass __init__/_sdk_root (no SDK on the test host) and stub the adb path.
    monkeypatch.setattr(Sdk, "adb", property(lambda self: "adb"))
    return object.__new__(Sdk)


def test_system_ready_waits_for_package_manager(monkeypatch):
    sdk = _sdk(monkeypatch)
    state = {"booted": "1", "pm_rc": 20, "pm_out": ""}

    def fake_run(argv, **kw):
        if "getprop" in argv:
            return types.SimpleNamespace(stdout=state["booted"] + "\n", returncode=0)
        if "pm" in argv:  # `pm path android`
            return types.SimpleNamespace(stdout=state["pm_out"], returncode=state["pm_rc"])
        return types.SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(emulator.subprocess, "run", fake_run)

    # booted, but pm not yet serving → not ready
    assert sdk._system_ready("emulator-5554") is False
    # pm comes up
    state["pm_rc"], state["pm_out"] = 0, "package:/system/framework/framework-res.apk\n"
    assert sdk._system_ready("emulator-5554") is True
    # boot flag not set → not ready (and pm isn't even probed)
    state["booted"] = "0"
    assert sdk._system_ready("emulator-5554") is False


def test_wait_for_boot_polls_until_ready(monkeypatch):
    sdk = _sdk(monkeypatch)
    monkeypatch.setattr(Sdk, "_emulator_serial", lambda self: "emulator-5554")
    seen = {"n": 0}

    def ready(self, serial):
        assert serial == "emulator-5554"
        seen["n"] += 1
        return seen["n"] >= 3  # not ready on the first two polls

    monkeypatch.setattr(Sdk, "_system_ready", ready)
    monkeypatch.setattr(emulator.time, "sleep", lambda _s: None)
    # No global `adb wait-for-device`/`shell` — would blow up against a real adb here.
    monkeypatch.setattr(emulator.subprocess, "run",
                        lambda *a, **k: pytest.fail("no global adb call expected"))

    assert sdk.wait_for_boot() == "emulator-5554"
    assert seen["n"] == 3


def test_wait_for_boot_times_out(monkeypatch):
    sdk = _sdk(monkeypatch)
    monkeypatch.setattr(Sdk, "_emulator_serial", lambda self: None)  # never appears
    monkeypatch.setattr(emulator.time, "sleep", lambda _s: None)
    ticks = iter([0.0, 100.0, 200.0, 300.0])
    monkeypatch.setattr(emulator.time, "monotonic", lambda: next(ticks))
    with pytest.raises(RuntimeError, match="did not finish booting"):
        sdk.wait_for_boot(timeout=240)


def test_avd_name_parses_emu_output(monkeypatch):
    sdk = _sdk(monkeypatch)
    monkeypatch.setattr(emulator.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout="retools\nOK\n", returncode=0))
    assert sdk.avd_name("emulator-5554") == "retools"

    monkeypatch.setattr(emulator.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout="OK\n", returncode=0))
    assert sdk.avd_name("emulator-5554") is None


def test_stop_and_delete_build_expected_argv(monkeypatch):
    sdk = _sdk(monkeypatch)
    monkeypatch.setattr(Sdk, "avdmanager", property(lambda self: "avdmanager"))
    calls = []
    monkeypatch.setattr(emulator.subprocess, "run",
                        lambda argv, **k: calls.append(argv) or types.SimpleNamespace(stdout="", returncode=0))
    sdk.stop_emulator("emulator-5554")
    sdk.delete_avd("retools")
    assert calls[0] == ["adb", "-s", "emulator-5554", "emu", "kill"]
    assert calls[1] == ["avdmanager", "delete", "avd", "-n", "retools"]


def test_is_running(monkeypatch):
    sdk = _sdk(monkeypatch)
    monkeypatch.setattr(Sdk, "connected_devices", lambda self: [
        Device(serial="emulator-5554", state="device", emulator=True)])
    assert sdk.is_running("emulator-5554") is True
    assert sdk.is_running("emulator-5556") is False
    monkeypatch.setattr(Sdk, "connected_devices", lambda self: [
        Device(serial="emulator-5554", state="offline", emulator=True)])
    assert sdk.is_running("emulator-5554") is False  # not ready


def test_emulator_serial_ignores_real_devices(monkeypatch):
    sdk = _sdk(monkeypatch)
    monkeypatch.setattr(Sdk, "connected_devices", lambda self: [
        Device(serial="2ccc4268251d7ece", state="device", emulator=False),  # real phone
        Device(serial="emulator-5554", state="device", emulator=True),
    ])
    assert sdk._emulator_serial() == "emulator-5554"

    monkeypatch.setattr(Sdk, "connected_devices", lambda self: [
        Device(serial="2ccc4268251d7ece", state="device", emulator=False)])
    assert sdk._emulator_serial() is None
