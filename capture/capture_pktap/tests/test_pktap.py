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
    assert expr == 'proc = "Google Chrome He" and not (pid = 1165 or pid = 1166 or pid = 1167)'


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
