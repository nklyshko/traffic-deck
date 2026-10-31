"""Guards on paths that cross a trust boundary: request-supplied profile names, and the
key-log tail that runs as root inside a user-owned directory under pktap."""
from __future__ import annotations

import os
import queue
import threading

import pytest

from capture_sdk import browser
from capture_sdk.livecapture import _keylog_thread


@pytest.mark.parametrize("name, folder", [
    ("../escape", "..-escape"), ("client/acme", "client-acme"), ("/etc", "-etc"),
    ("..", "--"), (".", "-"), ("a\\b", "a-b"), ("nul\0byte", "nul-byte"), ("100%", "100%"),
])
def test_any_profile_name_stays_one_folder_inside_the_root(tmp_path, name, folder):
    root = tmp_path / "profiles"
    root.mkdir()
    p = browser.persistent_path(str(root), name)
    assert p == str(root / folder) and os.path.isdir(p)
    assert not (tmp_path / "escape").exists()
    # The picker lists the folder name; choosing it again opens the same profile.
    assert browser.saved_profiles(str(root)) == [folder]
    assert browser.persistent_path(str(root), folder) == p


def test_a_profile_saved_nested_by_an_older_build_is_moved_to_its_dash_folder(tmp_path):
    # Older builds joined "a/b" raw, leaving root/a/b; the picker would list only "a" and
    # hand the browser the parent folder.
    root = tmp_path / "profiles"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "Local State").write_text("{}")
    (root / "x" / "y" / "z").mkdir(parents=True)
    (root / "x" / "y" / "z" / "prefs.js").write_text("")
    (root / "work").mkdir()
    (root / "work" / "Local State").write_text("{}")
    (root / "fresh").mkdir()  # created but never launched: no files, but no folders either
    (root / "killed" / "Default").mkdir(parents=True)  # Chrome died before Local State
    (root / "killed" / "Default" / "Preferences").write_text("{}")

    browser.flatten_nested_profiles(str(root))
    assert browser.saved_profiles(str(root)) == ["a-b", "fresh", "killed", "work", "x-y-z"]
    assert (root / "killed" / "Default" / "Preferences").exists()
    assert (root / "a-b" / "Local State").exists() and not (root / "a").exists()
    assert browser.persistent_path(str(root), "a/b") == str(root / "a-b")


def test_a_nested_profile_is_not_moved_over_an_existing_one(tmp_path):
    root = tmp_path / "profiles"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "Local State").write_text("old")
    (root / "a-b").mkdir()
    (root / "a-b" / "Local State").write_text("new")
    browser.flatten_nested_profiles(str(root))  # must not loop or clobber
    assert (root / "a-b" / "Local State").read_text() == "new"
    assert (root / "a" / "b" / "Local State").read_text() == "old"


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


def test_listing_profiles_moves_nothing_and_opening_the_root_does(tmp_path):
    # A listing is a query; the move belongs to profiles_root, which already creates the dir.
    root = tmp_path / "profiles"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "Local State").write_text("{}")
    assert browser.saved_profiles(str(root)) == ["a"]
    assert browser.profiles_root("/usr/bin/chrome", unconfined=str(root), snap_dir="x") == str(root)
    assert browser.saved_profiles(str(root)) == ["a-b"]
