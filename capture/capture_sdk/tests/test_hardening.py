"""Guards on paths that cross a trust boundary: request-supplied profile names, and the
key-log tail that runs as root inside a user-owned directory under pktap."""
from __future__ import annotations

import os
import queue
import threading

import pytest

from capture_sdk import browser
from capture_sdk.livecapture import _keylog_thread


@pytest.mark.parametrize("name", ["../escape", "a/b", "/etc", "..", "."])
def test_persistent_path_rejects_a_path_for_a_name(tmp_path, name):
    with pytest.raises(ValueError):
        browser.persistent_path(str(tmp_path), name)
    assert not (tmp_path.parent / "escape").exists()


def test_persistent_path_accepts_a_plain_name(tmp_path):
    p = browser.persistent_path(str(tmp_path), "work profile")
    assert p == str(tmp_path / "work profile") and os.path.isdir(p)
    assert browser.persistent_path(str(tmp_path), "") == str(tmp_path / "default")


def _tail(path: str) -> list:
    q: queue.Queue = queue.Queue()
    stop = threading.Event()
    stop.set()  # read what is there, then return
    _keylog_thread(path, q, stop)
    out = []
    while not q.empty():
        out.append(q.get())
    return out


def test_keylog_tail_reads_a_regular_file(tmp_path):
    kl = tmp_path / "key.log"
    kl.write_bytes(b"CLIENT_RANDOM aa bb\n")
    assert _tail(str(kl)) == [("keylog", b"CLIENT_RANDOM aa bb\n")]


def test_keylog_tail_refuses_a_symlink(tmp_path):
    secret = tmp_path / "root-only"
    secret.write_bytes(b"do not upload")
    kl = tmp_path / "key.log"
    kl.symlink_to(secret)
    assert _tail(str(kl)) == []


def test_keylog_tail_refuses_a_fifo(tmp_path):
    kl = tmp_path / "key.log"
    os.mkfifo(kl)
    assert _tail(str(kl)) == []  # would otherwise block forever on open/read
