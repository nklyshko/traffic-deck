"""chromeproxy without a device or a proxy: the flag line, the browser list, and — the one
that matters — that the capture always undoes what it did to the device. A command-line
file left behind would silently proxy *and* stop verifying certificates for every later
browser launch, and a leftover `adb reverse` would hold the port."""

from __future__ import annotations

import json
import threading

import pytest

from capture_android import chromeproxy


class FakeAdb:
    """Records what the capture does to the device instead of doing it."""

    def __init__(self, packages=("com.android.chrome", "com.other.app")):
        self.packages = list(packages)
        self.serial = "emulator-5554"
        self.shell_cmds: list[str] = []
        self.runs: list[tuple[str, ...]] = []

    def list_packages(self, third_party=True):
        return list(self.packages)

    def shell(self, *args, check=True):
        self.shell_cmds.append(" ".join(args))
        return ""

    def run(self, *args, check=True):
        self.runs.append(tuple(args))
        return None


class FakeMitm:
    """A mitmdump that is already running and never exits on its own."""

    def __init__(self):
        self.stopped = False

    def poll(self):
        return None


@pytest.fixture
def wired(monkeypatch):
    """chromeproxy with the proxy subprocess replaced: no mitmdump, no uv, no network."""
    mitm = FakeMitm()
    monkeypatch.setattr(chromeproxy, "_start_mitmdump", lambda *a, **k: mitm)
    monkeypatch.setattr(chromeproxy, "_read_session", lambda _p: "sess-1")
    monkeypatch.setattr(chromeproxy, "_stop_mitmdump",
                        lambda p: setattr(p, "stopped", True))
    monkeypatch.setattr(chromeproxy.time, "sleep", lambda _s: None)
    return mitm


def test_command_line_file_is_named_after_the_app():
    assert chromeproxy.command_line_file("com.android.chrome") == "chrome-command-line"
    assert chromeproxy.command_line_file("com.chrome.canary") == "chrome-command-line"
    assert chromeproxy.command_line_file("com.android.webview.shell") == "webview-command-line"
    # An unknown Chromium build gets the Chrome default rather than nothing.
    assert chromeproxy.command_line_file("com.vendor.browser") == "chrome-command-line"


def test_flags_point_at_the_proxy_and_close_the_side_doors():
    flags = chromeproxy.chrome_flags(41234)
    assert "--proxy-server=127.0.0.1:41234" in flags
    # Without these two the capture is either empty (no CA trust) or quietly short (QUIC
    # leaving over UDP, which a CONNECT proxy never sees).
    assert "--ignore-certificate-errors" in flags
    assert "--disable-quic" in flags


def test_browsers_are_listed_even_though_a_preinstalled_one_is_a_system_app():
    adb = FakeAdb(packages=["com.other.app", "com.android.chrome", "com.chrome.beta"])
    # Offer order is ours, not the device's, and non-browsers are left out.
    assert chromeproxy.installed_browsers(adb) == ["com.android.chrome", "com.chrome.beta"]
    assert chromeproxy.installed_browsers(FakeAdb(packages=["com.other.app"])) == []


def test_free_port_is_bindable_and_distinct():
    a, b = chromeproxy.free_port(), chromeproxy.free_port()
    assert 1024 < a < 65536 and a != b


def test_capture_sets_up_the_device_and_tears_it_all_down(wired):
    adb = FakeAdb()
    stop = threading.Event()
    stop.set()  # stop immediately: we are testing the setup/teardown, not the waiting

    seen = []
    sid = chromeproxy.run_proxy_capture(
        adb, "com.android.chrome", gateway="127.0.0.1:7331", url="https://example.org",
        port=45678, stop_event=stop, on_session=seen.append, log=lambda _m: None)

    assert sid == "sess-1" and seen == ["sess-1"]
    cmds = adb.shell_cmds
    # Set up: flags written, browser restarted onto them, opened on the URL.
    assert any("--proxy-server=127.0.0.1:45678" in c
               and "> /data/local/tmp/chrome-command-line" in c for c in cmds)
    assert "am force-stop com.android.chrome" in cmds[1]
    assert any("am start" in c and "https://example.org" in c for c in cmds)
    # Torn down: the flags file gone, the browser not left pointing at a dead proxy, the
    # reverse removed, the proxy stopped.
    assert any(c.startswith("rm -f /data/local/tmp/chrome-command-line") for c in cmds)
    assert cmds.index("rm -f /data/local/tmp/chrome-command-line") < len(cmds) - 1
    assert adb.runs == [("reverse", "tcp:45678", "tcp:45678"),
                        ("reverse", "--remove", "tcp:45678")]
    assert wired.stopped


def test_teardown_runs_even_when_the_capture_fails_midway(wired, monkeypatch):
    """The device is not ours to leave broken. A failure after the flags are written must
    still remove them — otherwise every later Chrome launch is silently proxied with
    certificate checks off."""
    adb = FakeAdb()
    boom = RuntimeError("device went away")

    def explode(_adb, _package, _url):
        raise boom

    monkeypatch.setattr(chromeproxy, "_launch", explode)
    logged: list[str] = []

    sid = chromeproxy.run_proxy_capture(adb, "com.android.chrome", port=45678,
                                        log=logged.append)

    assert sid == "sess-1"  # the session was opened, so the caller can still close it
    assert any("device went away" in m for m in logged), "the failure must be reported"
    assert "rm -f /data/local/tmp/chrome-command-line" in adb.shell_cmds
    assert ("reverse", "--remove", "tcp:45678") in adb.runs
    assert wired.stopped


def test_session_records_which_app_on_which_device(wired, monkeypatch):
    """Without this the bundle says only "mitmproxy" — the per-app path records
    android.package for the same reason."""
    seen: dict = {}

    def spy(port, gateway, label, metadata, log):
        seen.update(metadata=json.loads(metadata), label=label)
        return wired

    monkeypatch.setattr(chromeproxy, "_start_mitmdump", spy)
    stop = threading.Event()
    stop.set()
    chromeproxy.run_proxy_capture(FakeAdb(), "com.android.chrome", url="https://example.org",
                                  port=45678, stop_event=stop, log=lambda _m: None)

    assert seen["metadata"] == {"android.package": "com.android.chrome",
                                "android.method": "proxy",
                                "android.serial": "emulator-5554",
                                "android.url": "https://example.org"}
    # The label says what it is even in a list that only shows source="mitmproxy".
    assert "com.android.chrome" in seen["label"]


def test_no_url_falls_back_to_launching_the_browser_itself(wired):
    adb = FakeAdb()
    stop = threading.Event()
    stop.set()
    chromeproxy.run_proxy_capture(adb, "com.android.chrome", port=45678,
                                  stop_event=stop, log=lambda _m: None)
    # `am start` has no resolvable intent without a URL, and a browser's launcher activity
    # name is not ours to know.
    assert any(c.startswith("monkey -p com.android.chrome") for c in adb.shell_cmds)
    assert not any("am start" in c for c in adb.shell_cmds)
