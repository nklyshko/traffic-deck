"""Tests for capture_sdk.terminal.restore — it must turn signal generation (ISIG)
back on, which is what lets Ctrl-C reach the capture as SIGINT instead of a raw ^C."""

from __future__ import annotations

import pty
import sys

import pytest

from capture_sdk import terminal

termios = pytest.importorskip("termios")


def _flags(fd):
    a = termios.tcgetattr(fd)
    return (bool(a[3] & termios.ICANON), bool(a[0] & termios.ICRNL), bool(a[3] & termios.ISIG))


def test_restore_recooks_a_raw_tty(monkeypatch):
    _, slave = pty.openpty()
    # Put the pty in raw mode, as prompt_toolkit leaves it on a CPR-less terminal.
    a = termios.tcgetattr(slave)
    a[0] &= ~termios.ICRNL
    a[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
    termios.tcsetattr(slave, termios.TCSANOW, a)
    assert _flags(slave) == (False, False, False)

    monkeypatch.setattr(sys, "stdin", type("S", (), {"fileno": lambda self: slave})())
    terminal.restore()
    assert _flags(slave) == (True, True, True)  # canonical, CR→NL, signals back on


def test_restore_noop_without_tty():
    terminal.restore()  # pytest stdin isn't a tty — must not raise
