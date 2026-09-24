"""A capture whose packet backend dies on startup must say so, not record nothing.

This is the failure that has cost the most time on this project: tcpdump or dumpcap
refuses its interface, exits in milliseconds, writes not even a file header, and the
session runs to completion anyway — browser opens, key-log fills, zero packets, no stated
reason. The backend always explains itself on stderr; the job here is to make sure that
explanation reaches the user instead of a terminal nobody is watching.
"""
from __future__ import annotations

import subprocess

import pytest

from capture_sdk.livecapture import CaptureBackendFailed, KeylogCapture


class _FakeIngest:
    """Just enough IngestService for start(): hand out a session, note the close."""

    def __init__(self) -> None:
        self.closed: list[str] = []

    def OpenSession(self, _req):  # noqa: N802 — gRPC stub naming
        return type("H", (), {"session_id": "sess-1", "max_chunk_bytes": 1 << 20})()

    def CloseSession(self, req):  # noqa: N802
        self.closed.append(req.session_id)
        return None

    def UploadCapture(self, _chunks):  # noqa: N802
        return None


class _FakeChannel:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Capture(KeylogCapture):
    """A capture whose backend command and browser launch are both ours to choose."""

    name = "test"

    def __init__(self, backend: list[str], **kw) -> None:
        super().__init__(gateway="127.0.0.1:1", label="t", iface="lo0", **kw)
        self.backend = backend
        self.launched = False

    def capture_command(self, iface: str) -> list[str]:
        return self.backend

    def launch(self, keylog: str) -> subprocess.Popen:
        self.launched = True
        return subprocess.Popen(["sleep", "30"])


def _wire(cap: _Capture, monkeypatch) -> _FakeIngest:
    """Replace the gRPC plumbing start() would otherwise dial."""
    ing = _FakeIngest()
    import capture_sdk.livecapture as lc

    monkeypatch.setattr(lc.grpc, "insecure_channel", lambda _t: _FakeChannel())
    monkeypatch.setattr(lc.ig, "IngestServiceStub", lambda _c: ing)
    return ing


def test_backend_that_dies_on_startup_raises_with_its_own_message(monkeypatch):
    # The shape of every real case: exits at once, having explained itself on stderr.
    cap = _Capture(["sh", "-c", "echo 'en0: You don-t have permission' >&2; exit 1"])
    ing = _wire(cap, monkeypatch)

    with pytest.raises(CaptureBackendFailed) as e:
        cap.start()

    assert "permission" in str(e.value), "the backend's own words must reach the user"
    assert "exited immediately" in str(e.value)
    assert not cap.launched, "the browser must not open for a capture that cannot record"
    assert ing.closed == ["sess-1"], "a refused start must not leave the session open"


def test_backend_that_dies_silently_still_raises(monkeypatch):
    # Nothing on stderr is still a failure; the message has to admit it has no reason.
    cap = _Capture(["sh", "-c", "exit 2"])
    _wire(cap, monkeypatch)

    with pytest.raises(CaptureBackendFailed, match="without saying why"):
        cap.start()


def test_a_healthy_backend_is_not_refused(monkeypatch):
    # The guard costs a fraction of a second at every start, so it must never fire on a
    # backend that is merely quiet — a capture recording an idle interface writes nothing
    # for a while either.
    cap = _Capture(["sh", "-c", "sleep 5"])
    _wire(cap, monkeypatch)

    sid = cap.start()
    try:
        assert sid == "sess-1"
        assert cap.launched, "the browser launches once the backend is recording"
    finally:
        cap._stop.set()
        cap._dump.kill()
        cap._proc.kill()


def test_backend_stderr_is_echoed_on(monkeypatch, capfd):
    # Kept *and* echoed: a supervised source's log is where this is read after the fact.
    cap = _Capture(["sh", "-c", "echo 'tcpdump: pktap,en0: No such device' >&2; exit 1"])
    _wire(cap, monkeypatch)

    with pytest.raises(CaptureBackendFailed):
        cap.start()
    assert "No such device" in capfd.readouterr().err


def test_start_grace_is_short_enough_to_not_be_felt():
    # A guard that made every capture visibly slower would get removed, and the failure it
    # catches would come back.
    from capture_sdk.livecapture import _START_GRACE

    assert _START_GRACE <= 0.5
