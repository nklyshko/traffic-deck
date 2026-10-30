"""A spawned capture process announces its session as `SESSION <id>`; one that never does
must not hold the caller forever."""
from __future__ import annotations

import subprocess
import sys

from capture_sdk.sessionline import read_session_id


class _Proc:
    def __init__(self, lines):
        self.stdout = iter(lines)

    def kill(self):
        pass


def test_the_id_comes_from_the_session_line_and_every_line_is_echoed():
    seen = []
    assert read_session_id(_Proc(["starting\n", "SESSION abc-1\n", "after\n"]), echo=seen.append) == "abc-1"
    assert seen == ["starting\n", "SESSION abc-1\n"]


def test_output_that_ends_without_a_session_line_gives_none():
    assert read_session_id(_Proc(["error: port in use\n"])) is None


def test_a_process_that_never_announces_is_killed_after_the_grace():
    # Prints nothing and would run for a minute: the watchdog kill closes the pipe.
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                            stdout=subprocess.PIPE, text=True)
    try:
        assert read_session_id(proc, grace=0.2) is None
        assert proc.wait(timeout=5) != 0
    finally:
        proc.kill()
