"""How Firefox is actually launched: the key-log goes in the environment (not a flag, as
it would for Chrome) and the profile selection differs by form. No browser is started —
Popen is faked."""

from __future__ import annotations

import pytest

from capture_firefox import capture as capture_mod
from capture_firefox.capture import BUILTIN_PROFILE, FirefoxCapture


@pytest.fixture
def launched(monkeypatch):
    """Capture the argv/env a launch would have used."""
    seen = {}

    def fake_popen(cmd, env=None):
        seen["cmd"] = cmd
        seen["env"] = env
        return object()

    monkeypatch.setattr(capture_mod.subprocess, "Popen", fake_popen)
    return seen


def make(profile, **kw):
    return FirefoxCapture(gateway="127.0.0.1:1", label="l", firefox="/usr/bin/firefox",
                          profile=profile, **kw)


def test_keylog_goes_in_the_environment(launched):
    # NSS reads SSLKEYLOGFILE from the environment; unlike Chrome there is no flag for it,
    # so a keylog passed as an argument would silently capture nothing decryptable.
    make("/tmp/prof").launch("/tmp/key.log")
    assert launched["env"]["SSLKEYLOGFILE"] == "/tmp/key.log"
    assert not any("key.log" in a for a in launched["cmd"])


def test_launch_inherits_the_rest_of_the_environment(launched, monkeypatch):
    monkeypatch.setenv("HOME", "/home/someone")
    make("/tmp/prof").launch("/tmp/key.log")
    assert launched["env"]["HOME"] == "/home/someone"


def test_path_profile_uses_profile_flag(launched):
    make("/tmp/prof").launch("/k")
    assert "--profile" in launched["cmd"]
    assert launched["cmd"][launched["cmd"].index("--profile") + 1] == "/tmp/prof"


def test_registered_profile_uses_p_flag(launched):
    # A (root, name) tuple is one of the browser's own profiles, selected by name.
    make(("/home/u/.mozilla/firefox", "work")).launch("/k")
    assert "-P" in launched["cmd"]
    assert launched["cmd"][launched["cmd"].index("-P") + 1] == "work"
    assert "--profile" not in launched["cmd"]


def test_builtin_profile_passes_no_profile_flag(launched):
    make(BUILTIN_PROFILE).launch("/k")
    assert "--profile" not in launched["cmd"] and "-P" not in launched["cmd"]


def test_no_remote_is_always_passed(launched):
    # Without --no-remote a launch hands the URL to an already-running Firefox and exits,
    # leaving us capturing a browser we never started and can't wait on.
    make(BUILTIN_PROFILE).launch("/k")
    assert "--no-remote" in launched["cmd"]


def test_url_goes_last(launched):
    make("/tmp/prof", url="https://example.com").launch("/k")
    assert launched["cmd"][-1] == "https://example.com"


def test_extra_args_pass_through_without_the_separator(launched):
    # argparse.REMAINDER keeps the "--" that separated them; Firefox must not see it.
    make("/tmp/prof", extra_args=["--", "-private-window"]).launch("/k")
    assert "--" not in launched["cmd"]
    assert "-private-window" in launched["cmd"]


def test_source_name_is_firefox():
    assert FirefoxCapture.name == "firefox"
