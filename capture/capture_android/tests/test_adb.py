"""Unit tests for the device-independent Android adb helpers (no device needed)."""
import pytest
from capture_android.adb import frida_arch, parse_app_uid, nflog_rules


def test_frida_arch():
    assert frida_arch("arm64-v8a") == "arm64"
    assert frida_arch("armeabi-v7a") == "arm"
    assert frida_arch("x86_64") == "x86_64"
    assert frida_arch("x86") == "x86"
    with pytest.raises(RuntimeError):
        frida_arch("mips")


def test_parse_app_uid():
    out = ("package:com.android.chrome uid:10150\n"
           "package:com.android.chrome.beta uid:10151\n")
    assert parse_app_uid(out, "com.android.chrome") == 10150
    assert parse_app_uid(out, "com.android.chrome.beta") == 10151
    with pytest.raises(RuntimeError):
        parse_app_uid(out, "com.example.absent")


def test_nflog_rules():
    add, teardown = nflog_rules(10192, 0x2a, 30)
    assert add[0] == ["iptables", "-t", "mangle", "-A", "OUTPUT", "-m", "owner",
                      "--uid-owner", "10192", "-j", "CONNMARK", "--set-mark", "0x2a"]
    # add/teardown mirror each other except -A vs -D
    assert all(a[3] == "-A" and d[3] == "-D" for a, d in zip(add, teardown))
    assert [a[4:] for a in add] == [d[4:] for d in teardown]
    # both directions NFLOG'd by connmark
    assert any("INPUT" in r and "NFLOG" in r for r in add)
    assert any("OUTPUT" in r and "NFLOG" in r for r in add)


def test_parse_app_names():
    from capture_android.cli import parse_app_names
    out = ("com.android.chrome\tChrome\n"
           "com.google.android.apps.maps\tMaps\n"
           "malformed-no-tab\n")
    assert parse_app_names(out) == {
        "com.android.chrome": "Chrome",
        "com.google.android.apps.maps": "Maps",
    }


def test_app_choices_formats_label_with_package():
    from capture_android.cli import app_choices
    choices = app_choices(["com.a", "com.b"], {"com.a": "Alpha"})
    assert choices == [("Alpha  (com.a)", "com.a"), ("com.b", "com.b")]


def test_parse_devices():
    from capture_android.emulator import parse_devices
    out = ("List of devices attached\n"
           "emulator-5554          device product:sdk_gphone64_x86_64\n"
           "2ccc4268251d7ece       unauthorized usb:1-7 transport_id:1\n")
    ds = parse_devices(out)
    assert [(d.serial, d.state, d.emulator) for d in ds] == [
        ("emulator-5554", "device", True),
        ("2ccc4268251d7ece", "unauthorized", False),
    ]
