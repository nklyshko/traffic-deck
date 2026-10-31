"""Unit tests for the device-independent Android adb helpers (no device needed)."""
import pytest
from capture_android import adb as adbmod
from capture_android.adb import AdbClient, frida_arch, parse_app_uid, nflog_rules


def test_start_root_held_detaches_stdin(monkeypatch):
    # The held frida-server adb client must not inherit the tty, or it raws the terminal
    # and reads keystrokes away from the prompts / Ctrl-C that follow.
    captured = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            captured["argv"], captured["kw"] = argv, kw

    monkeypatch.setattr(adbmod.subprocess, "Popen", FakePopen)
    AdbClient(serial="emulator-5554", adb="adb").start_root_held("/data/local/tmp/frida-server")
    assert captured["kw"].get("stdin") is adbmod.subprocess.DEVNULL
    assert captured["kw"].get("stdout") is adbmod.subprocess.DEVNULL
    assert "shell" in captured["argv"]


def _listing_client(monkeypatch, listings):
    """An AdbClient whose `pm list packages` answers from `listings` — {with_-3: output} —
    recording the calls it was asked to make."""
    client = AdbClient(serial="emulator-5554", adb="adb")
    calls: list[tuple[str, ...]] = []

    def fake_pm(*args, retries=5):
        calls.append(args)
        return listings["-3" in args]

    monkeypatch.setattr(client, "_pm", fake_pm)
    return client, calls


def test_package_list_prefers_third_party(monkeypatch):
    client, calls = _listing_client(monkeypatch, {
        True: "package:com.b\npackage:com.a\n",
        False: "package:android\npackage:com.b\n",
    })
    # Sorted, and the system packages are left out while the user has apps of their own.
    assert client.list_packages() == ["com.a", "com.b"]
    assert len(calls) == 1


def test_package_list_falls_back_when_no_app_is_installed(monkeypatch):
    """A stock emulator has no third-party apps, and an empty list is worse than a long
    one: it leaves the picker with nothing in it, so the viewer asks for a package name
    typed from memory instead of offering a choice."""
    client, calls = _listing_client(monkeypatch, {
        True: "",  # `pm list packages -3` on a fresh AVD
        False: "package:com.android.chrome\npackage:android\n",
    })
    assert client.list_packages() == ["android", "com.android.chrome"]
    assert [("-3" in c) for c in calls] == [True, False], "it must try third-party first"


def test_asking_for_all_packages_does_not_double_list(monkeypatch):
    client, calls = _listing_client(monkeypatch, {True: "", False: ""})
    assert client.list_packages(third_party=False) == []
    assert len(calls) == 1  # already the full list — nothing to fall back to


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


def test_a_hung_adb_call_fails_with_a_clear_error(monkeypatch):
    # adb blocks forever on a device that dropped off USB; it must give up and say so.
    monkeypatch.setattr(AdbClient, "TIMEOUT", 0.2)
    client = AdbClient(serial=None, adb="sleep")  # `sleep shell 5` stands in for a hung adb
    monkeypatch.setattr(client, "_base", lambda: ["sleep"])
    with pytest.raises(RuntimeError, match="still connected"):
        client.run("5")


def test_quick_run_reports_a_hung_query_as_an_empty_failure():
    from capture_android.emulator import quick_run

    res = quick_run(["sleep", "5"], timeout=0.2)
    assert res.returncode != 0 and res.stdout == ""
