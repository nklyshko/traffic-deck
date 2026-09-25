"""Unit tests for the pktap capture's host-independent parts (no root, no tcpdump needed).

The two things worth pinning down are the ones that are silently wrong if they drift: the
process name the metadata filter matches, and the fact that root never reaches the browser.
"""
from __future__ import annotations

import os

import pytest

from capture_pktap import pktap, privdrop


def test_helper_process_name_targets_the_networkservice_helper():
    # Chrome's sockets belong to its NetworkService helper, never the main process, so
    # filtering on the browser's own name would capture nothing at all.
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    assert pktap.helper_process_name(chrome) == "Google Chrome He"
    # ...and the kernel truncates at MAXCOMLEN, which is the form -Q compares against.
    assert len(pktap.helper_process_name(chrome)) == pktap.MAXCOMLEN


def test_helper_process_name_per_browser():
    def name(binary: str) -> str:
        return pktap.helper_process_name(f"/Applications/{binary}.app/Contents/MacOS/{binary}")

    assert name("Brave Browser") == "Brave Browser He"
    assert name("Microsoft Edge") == "Microsoft Edge H"
    assert name("Chromium") == "Chromium Helper"  # short enough to survive intact


def test_capture_command_uses_the_metadata_filter_and_keeps_pcapng():
    cmd = pktap.capture_command("en0", 'proc = "Google Chrome He"', tcpdump="/usr/sbin/tcpdump")
    assert cmd[:3] == ["/usr/sbin/tcpdump", "-i", "pktap,en0"]
    # --apple-md-filter, not the overloaded -Q (which also means direction).
    assert cmd[cmd.index("--apple-md-filter") + 1] == 'proc = "Google Chrome He"'
    assert cmd[-2:] == ["-w", "-"]
    assert "-U" in cmd  # or the gateway sees packets a buffer at a time
    # -y RAW must never come back: it strips the metadata the filter reads, and the filter
    # then silently drops every outbound packet, so no handshake is captured and nothing
    # decodes. tcpdump(1): the filter "is meaningful only with ... the Pcap-ng file format
    # or for interfaces supporting the PKTAP data link type".
    assert "-y" not in cmd


def test_filter_expression_excludes_browsers_that_were_already_running():
    # Name alone matches every Chrome on the machine. Excluding the pids that existed just
    # before launch leaves only the instance we start — the whole point of this source.
    assert pktap.filter_expression("Google Chrome He") == 'proc = "Google Chrome He"'
    expr = pktap.filter_expression("Google Chrome He", [1167, 1165, 1166])
    assert expr == 'proc = "Google Chrome He" and pid != 1165 and pid != 1166 and pid != 1167'


def test_filter_expression_never_parenthesises_the_exclusion():
    # Apple's filter parser cannot read `A and not (B or C)` — it fails with "missing right
    # parenthesis", tcpdump exits before capturing anything, and the session is empty. The
    # single-term form `A and not (B)` parses, so the bug only appeared when two
    # Chrome-family browsers held sockets at once, which is why it took a real capture to
    # find. Chained `pid !=` parses at every length.
    expr = pktap.filter_expression("Google Chrome He", [1, 2, 3])
    assert "not (" not in expr
    assert " or " not in expr
    assert expr.count("pid != ") == 3


def test_matching_pids_keeps_only_socket_owners(monkeypatch):
    # The truncated name matches renderers too ("... Helper (Renderer)" -> same 16 chars),
    # which on a busy browser is ~200 pids. They own no sockets, so pktap never tags a
    # packet to them; listing them would build a multi-kilobyte per-packet filter for
    # nothing. Only the NetworkService helper actually competes with us.
    monkeypatch.setattr(pktap, "_named_pids", lambda _p: [471, 1165, 1166, 1167, 1936])
    monkeypatch.setattr(pktap, "_socket_owning_pids", lambda: {1166, 741, 9001})
    assert pktap.matching_pids("Google Chrome He") == [1166]


def test_matching_pids_falls_back_to_no_exclusion(monkeypatch):
    # If the socket owners can't be established, emit a valid name-only filter rather than
    # a giant one. Less precise, but the key-log still keeps foreign flows out of the decode.
    monkeypatch.setattr(pktap, "_named_pids", lambda _p: [471, 1165, 1166])
    monkeypatch.setattr(pktap, "_socket_owning_pids", lambda: None)
    assert pktap.matching_pids("Google Chrome He") == []


def test_named_pids_compares_the_truncated_name(monkeypatch):
    import subprocess as sp

    class Done:
        stdout = (
            "  PID COMM\n"
            " 1159 Google Chrome\n"
            " 1166 Google Chrome Helper\n"
            "  471 Google Chrome Helper (Renderer)\n"
            " 9001 Slack Helper\n"
        )

    monkeypatch.setattr(sp, "run", lambda *a, **k: Done())
    got = pktap._named_pids("Google Chrome He")
    assert got == [1166, 471]   # both truncate to the filtered name
    assert 1159 not in got      # "Google Chrome" alone is a different name
    assert 9001 not in got      # another app entirely


PS_OUTPUT = (
    # pid  ppid  command
    " 1159     1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    " --user-data-dir=/Users/me/Library/Application Support/Google/Chrome\n"
    # Ours: the network process, carrying the profile we launched against.
    " 1166  1159 /Applications/Google Chrome.app/.../Google Chrome Helper"
    " --type=utility --utility-sub-type=network.mojom.NetworkService"
    " --user-data-dir=/Users/me/Library/Application Support/Google/Chrome\n"
    # A renderer of ours: same name, same profile, but owns no socket.
    "  471  1159 /Applications/Google Chrome.app/.../Google Chrome Helper (Renderer)"
    " --type=renderer"
    " --user-data-dir=/Users/me/Library/Application Support/Google/Chrome\n"
    # Another Chrome's network process: same 16-character name, different profile. This is
    # the one the kernel filter cannot exclude when it starts mid-capture.
    " 4242  4200 /Applications/Google Chrome.app/.../Google Chrome Helper"
    " --type=utility --utility-sub-type=network.mojom.NetworkService"
    " --user-data-dir=/Users/me/other-profile\n"
    # A profile whose path merely starts the same way — must not match.
    " 4243  4201 /Applications/Google Chrome.app/.../Google Chrome Helper"
    " --type=utility --utility-sub-type=network.mojom.NetworkService"
    " --user-data-dir=/Users/me/Library/Application Support/Google/Chrome-backup\n"
)


def _fake_ps(monkeypatch):
    import subprocess as sp

    class Done:
        stdout = PS_OUTPUT

    monkeypatch.setattr(sp, "run", lambda *a, **k: Done())


def test_network_service_pids_identifies_our_browser_by_profile(monkeypatch):
    # The mark is the --user-data-dir we launched against: Chrome hands the resolved path
    # to every child, so our network process carries it and another Chrome's carries its
    # own. This is the identity the metadata filter cannot express, because a pid does not
    # exist until after the browser starts.
    _fake_ps(monkeypatch)
    udd = "/Users/me/Library/Application Support/Google/Chrome"
    got = pktap.network_service_pids(udd)
    assert got == {1166}, "only our own NetworkService, by profile"


def test_network_service_pids_ignores_a_longer_profile_path(monkeypatch):
    # ".../Chrome" must not match ".../Chrome-backup"; a plain substring test would, and
    # would silently adopt another browser's packets as ours.
    _fake_ps(monkeypatch)
    assert 4243 not in pktap.network_service_pids(
        "/Users/me/Library/Application Support/Google/Chrome")


def test_network_service_pids_falls_back_to_parentage(monkeypatch):
    # A built-in profile whose directory we could not resolve leaves no mark in argv, so
    # fall back to "a child of the browser we launched" — still exact, just less robust to
    # the process being re-parented.
    _fake_ps(monkeypatch)
    assert pktap.network_service_pids(None, browser_pid=1159) == {1166}
    assert pktap.network_service_pids(None, browser_pid=4200) == {4242}
    assert pktap.network_service_pids(None) == set()  # nothing to go on: claim nothing


def test_network_service_pids_ignores_processes_that_own_no_sockets(monkeypatch):
    # Renderers share the truncated process name and the profile, so they pass every test
    # except the one that matters: they are not the network service.
    _fake_ps(monkeypatch)
    udd = "/Users/me/Library/Application Support/Google/Chrome"
    assert 471 not in pktap.network_service_pids(udd)
    assert 1159 not in pktap.network_service_pids(udd)  # nor the browser itself


def test_network_service_pids_survives_ps_failing(monkeypatch):
    # An empty set means "we identified nothing", which the capture reports as no pids at
    # all — the gateway must never be handed an empty keep set, which would mean "drop
    # every packet".
    import subprocess as sp

    def boom(*a, **k):
        raise OSError("no ps")

    monkeypatch.setattr(sp, "run", boom)
    assert pktap.network_service_pids("/Users/me/profile") == set()


def _fake_bundle(tmp_path, app: str, framework: str, helper: str) -> str:
    """A Chromium app bundle: the app is named one thing, the framework another, and the
    helper follows the *framework*. Returns the main binary's path."""
    helpers = (tmp_path / f"{app}.app" / "Contents" / "Frameworks"
               / f"{framework} Framework.framework" / "Versions" / "156.0.8071.0" / "Helpers")
    for name in [f"{helper} Helper", f"{helper} Helper (Renderer)",
                 f"{helper} Helper (GPU)", f"{helper} Helper (Alerts)"]:
        (helpers / f"{name}.app").mkdir(parents=True, exist_ok=True)
    macos = tmp_path / f"{app}.app" / "Contents" / "MacOS"
    macos.mkdir(parents=True, exist_ok=True)
    (macos / app).write_text("")
    return str(macos / app)


def test_helper_process_name_comes_from_the_bundle_not_the_app_name(tmp_path):
    # The bug that made a whole capture empty while everything else worked: Chrome Canary
    # ships "Google Chrome Framework.framework", whose helper is "Google Chrome Helper".
    # Deriving the name from the app gives "Google Chrome Canary Helper" -> truncates to
    # "Google Chrome Ca", which no process on the machine is called, so the metadata filter
    # matches nothing at all and the capture is silently empty.
    canary = _fake_bundle(tmp_path, "Google Chrome Canary", "Google Chrome", "Google Chrome")
    assert pktap.helper_process_name(canary) == "Google Chrome He"
    assert pktap.helper_process_name(canary) != "Google Chrome Ca"


def test_helper_process_name_ignores_the_other_child_process_types(tmp_path):
    # Only the plain "… Helper" owns sockets; (Renderer)/(GPU)/(Alerts) are the other child
    # types and would each produce a different, useless filter.
    brave = _fake_bundle(tmp_path, "Brave Browser", "Brave Browser", "Brave Browser")
    assert pktap.helper_process_name(brave) == "Brave Browser He"


def test_helper_process_name_falls_back_when_there_is_no_bundle():
    # A layout we do not recognise still gets a plausible name rather than nothing.
    assert pktap.helper_process_name("/usr/bin/chromium") == "chromium Helper"


def test_invoking_user_is_none_when_unprivileged(monkeypatch):
    # Not root → no demotion anywhere; the tool behaves like any other capture source.
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert privdrop.invoking_user() is None


def test_invoking_user_reads_sudo_env(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    assert privdrop.invoking_user() == (501, 20)


def test_invoking_user_refuses_bare_root(monkeypatch):
    # Root with no SUDO_UID: there is no user to hand the browser to, and guessing would
    # launch Chrome as root against /var/root's profile. Fail loudly instead.
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    with pytest.raises(RuntimeError, match="SUDO_UID"):
        privdrop.invoking_user()


def test_adopt_user_home_points_tilde_at_the_user(monkeypatch, tmp_path):
    # Without this every path resolves against root's home: no real Chrome profiles would
    # be discovered and ~/.traffic-deck state would land in /var/root.
    import pwd

    fake = pwd.struct_passwd(("me", "x", 501, 20, "", str(tmp_path), "/bin/zsh"))
    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: fake)
    monkeypatch.setenv("HOME", "/var/root")
    privdrop.adopt_user_home((501, 20))
    assert os.environ["HOME"] == str(tmp_path)
    assert os.path.expanduser("~") == str(tmp_path)


def test_adopt_user_home_noop_when_unprivileged(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/me")
    privdrop.adopt_user_home(None)
    assert os.environ["HOME"] == "/Users/me"


def test_as_user_is_a_passthrough_when_unprivileged():
    with privdrop.as_user(None):
        pass  # must not attempt seteuid — it would raise for a non-root process


def test_user_tempdir_is_none_when_unprivileged():
    # Unprivileged: keep KeylogCapture's default, exactly as the Chrome source behaves.
    assert privdrop.user_tempdir(None) is None


def test_user_tempdir_avoids_roots_untraversable_tmpdir(monkeypatch):
    # The bug this exists for: under sudo, $TMPDIR is root's 0700 per-user darwin dir. The
    # browser runs as the user, cannot traverse it, and silently logs no TLS secrets — so
    # the capture looks perfect and every flow drops for "no key-log secret". Chowning the
    # leaf does not help; the *parent* is what blocks. So the dir must not come from
    # $TMPDIR at all.
    import subprocess as sp

    monkeypatch.setenv("TMPDIR", "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T")

    class Done:
        stdout = "/var/folders/g9/usershash/T\n"

    monkeypatch.setattr(os.path, "isdir", lambda p: p == "/var/folders/g9/usershash/T")
    monkeypatch.setattr(sp, "run", lambda *a, **k: Done())
    got = privdrop.user_tempdir((501, 20))
    assert got == "/var/folders/g9/usershash/T"
    assert not got.startswith(os.environ["TMPDIR"])


def test_user_tempdir_falls_back_to_tmp(monkeypatch):
    # getconf missing or unusable → /tmp, which is 1777 and always traversable. Never
    # silently fall through to root's TMPDIR, which is the failure mode itself.
    import subprocess as sp

    def boom(*a, **k):
        raise OSError("no getconf")

    monkeypatch.setattr(sp, "run", boom)
    assert privdrop.user_tempdir((501, 20)) == "/tmp"
