"""Tests for the two-stage Ctrl-C handler (capture_sdk.shutdown).

The handler logic is exercised by calling ._handle directly (no real signals), plus
one round-trip test that the context manager installs and restores the SIGINT handler.
"""

from __future__ import annotations

import signal

import pytest

from capture_sdk.shutdown import GracefulInterrupt


def test_first_ctrl_c_requests_stop_without_raising(capsys):
    gi = GracefulInterrupt(message="stopping…")
    gi._prev = signal.SIG_DFL
    gi._handle(signal.SIGINT, None)  # first press: must not raise
    assert gi.stopping is True
    assert "stopping…" in capsys.readouterr().err


def test_second_ctrl_c_aborts_and_restores_default(monkeypatch):
    gi = GracefulInterrupt()
    gi._prev = signal.SIG_DFL
    gi._prev_term = signal.SIG_DFL
    restored = []
    monkeypatch.setattr(signal, "signal", lambda num, handler: restored.append((num, handler)))

    gi._handle(signal.SIGINT, None)  # first: set the event
    with pytest.raises(KeyboardInterrupt):
        gi._handle(signal.SIGINT, None)  # second: abort
    # both handlers put back, so a third signal of either kind takes the default action
    assert restored == [(signal.SIGINT, signal.SIG_DFL), (signal.SIGTERM, signal.SIG_DFL)]


def test_sigterm_requests_a_graceful_stop_too():
    # The gateway reaps a source with SIGTERM; it must reach the same graceful stop as Ctrl-C.
    before_int, before_term = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    gi = GracefulInterrupt()
    with gi:
        assert signal.getsignal(signal.SIGTERM) == gi._handle
        gi._handle(signal.SIGTERM, None)
        assert gi.stopping
    assert signal.getsignal(signal.SIGINT) == before_int
    assert signal.getsignal(signal.SIGTERM) == before_term


def test_context_manager_installs_and_restores_handler():
    before = signal.getsignal(signal.SIGINT)
    gi = GracefulInterrupt()
    with gi:
        assert signal.getsignal(signal.SIGINT) == gi._handle
    assert signal.getsignal(signal.SIGINT) == before


def test_shares_a_caller_supplied_event():
    import threading
    ev = threading.Event()
    gi = GracefulInterrupt(ev)
    assert gi.stopping is False
    gi._prev = signal.SIG_DFL
    gi._handle(signal.SIGINT, None)
    assert ev.is_set()  # the capture loop watching `ev` will see the stop request
