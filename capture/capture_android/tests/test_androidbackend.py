"""RealAndroidBackend's device choice, with adb and the SDK stubbed: what is offered when a
phone, emulators and AVDs coexist, and which serial each choice ends up on."""

from __future__ import annotations

import pytest

from capture_android import androidbackend
from capture_android.androidbackend import RealAndroidBackend
from capture_android.emulator import Device

PHONE = Device(serial="2ccc4268251d7ece", state="device", emulator=False)
EMU = Device(serial="emulator-5554", state="device", emulator=True)
NEW_EMU = "emulator-5556"


class FakeSdk:
    def __init__(self, avds=(), running_avds=None):
        self.avds = list(avds)
        self.running_avds = running_avds or {}
        self.booted = []
        self.ignored = None

    def list_avds(self):
        return self.avds

    def avd_name(self, serial):
        return self.running_avds.get(serial)

    def emulator_serials(self):
        return set(self.running_avds)

    def boot(self, name, headless=True):
        self.booted.append(name)

    def wait_for_boot(self, ignore=()):
        self.ignored = ignore
        return NEW_EMU


class FakeAdb:
    adb = "adb"

    def __init__(self, serial=None):
        self.serial = serial

    def shell(self, *_args):
        return "14\n"


def backend(monkeypatch, devices, sdk=None):
    monkeypatch.setattr(androidbackend, "AdbClient", FakeAdb)
    monkeypatch.setattr(RealAndroidBackend, "_running_devices", lambda self: devices)
    b = RealAndroidBackend("gw")
    b._sdk_inst = sdk or FakeSdk()
    return b


def test_a_connected_phone_does_not_hide_the_emulators(monkeypatch):
    b = backend(monkeypatch, [PHONE], FakeSdk(avds=["retools"]))
    assert [v for v, _ in b.provision_options()] == [
        f"attach:{PHONE.serial}", "retools", "__create__"]


def test_nothing_connected_offers_only_emulators(monkeypatch):
    b = backend(monkeypatch, [], FakeSdk(avds=["retools"]))
    assert [v for v, _ in b.provision_options()] == ["retools", "__create__"]


def test_every_connected_device_is_offered_and_a_running_avd_is_not_booted_again(monkeypatch):
    sdk = FakeSdk(avds=["retools", "pixel"], running_avds={EMU.serial: "retools"})
    options = backend(monkeypatch, [PHONE, EMU], sdk).provision_options()
    assert [v for v, _ in options] == [
        f"attach:{PHONE.serial}", f"attach:{EMU.serial}", "pixel", "__create__"]
    assert "device" in options[0][1] and "emulator" in options[1][1]


def test_without_the_sdk_connected_devices_are_still_offered(monkeypatch):
    class NoSdk(FakeSdk):
        def list_avds(self):
            raise RuntimeError("Android SDK not found; set ANDROID_HOME")

    b = backend(monkeypatch, [PHONE], NoSdk())
    assert [v for v, _ in b.provision_options()] == [f"attach:{PHONE.serial}"]


def test_without_the_sdk_or_a_device_the_error_is_kept(monkeypatch):
    class NoSdk(FakeSdk):
        def list_avds(self):
            raise RuntimeError("Android SDK not found; set ANDROID_HOME")

    with pytest.raises(RuntimeError, match="ANDROID_HOME"):
        backend(monkeypatch, [], NoSdk()).provision_options()


def test_attach_uses_the_chosen_device_not_the_first(monkeypatch):
    b = backend(monkeypatch, [PHONE, EMU])
    b.provision(f"attach:{EMU.serial}")
    assert b._serial == EMU.serial
    assert b.owns_resource is False


def test_attach_fails_when_the_device_has_gone(monkeypatch):
    b = backend(monkeypatch, [PHONE])
    with pytest.raises(RuntimeError, match="no longer connected"):
        b.provision(f"attach:{EMU.serial}")


def test_boot_owns_the_new_emulator_not_the_running_one(monkeypatch):
    sdk = FakeSdk(avds=["pixel"], running_avds={EMU.serial: "retools"})
    b = backend(monkeypatch, [PHONE, EMU], sdk)
    b.provision("pixel")
    assert sdk.booted == ["pixel"]
    assert sdk.ignored == {EMU.serial}
    assert b._serial == NEW_EMU
    assert b.owns_resource is True


def test_a_booted_emulator_still_serves_its_running_emulator_choice(monkeypatch):
    # After the boot the AVD is offered as a running emulator. Taking it must keep the
    # emulator, not stop it and then fail to attach to what was just stopped.
    b = backend(monkeypatch, [PHONE], FakeSdk())
    b.provision("pixel")
    assert b.serves("pixel")
    assert b.serves(f"attach:{NEW_EMU}")
    assert not b.serves(f"attach:{PHONE.serial}")
