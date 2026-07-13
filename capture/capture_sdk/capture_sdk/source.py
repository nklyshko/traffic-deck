"""Serve a capture tool as a `CaptureSourceService` the gateway dials.

A tool becomes a controllable source by subclassing [CaptureSource][capture_sdk.source.CaptureSource]
— implement `describe`/`start_capture`/`stop_capture` (and `release` if it holds a warm
resource) in plain Python — and calling [serve_forever][capture_sdk.source.serve_forever]
from its `serve` subcommand. The harness wraps that into the gRPC servicer, tracks which
sessions are live so `Status` is automatic, and on SIGTERM/SIGINT (the supervisor's
group-kill) stops each live capture and releases the resource before exiting, so a
supervised tool finalizes cleanly rather than stranding sessions. See ADR-0010.

The control plane only lives here; the *data* plane (OpenSession/UploadCapture/PushFlows)
stays in the tool, exactly as the standalone CLI already does it — `start_capture` opens
the session and returns its id while capture continues in the background.
"""

from __future__ import annotations

import abc
import signal
import threading
from concurrent import futures
from typing import Mapping

import grpc

from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.proto import source_pb2 as sp
from capture_sdk.proto import source_pb2_grpc as sp_grpc

# Re-exported for ergonomic descriptors: `source.STRING`, `source.CHOICE`, …
STRING = sp.PARAM_TYPE_STRING
PATH = sp.PARAM_TYPE_PATH
BOOL = sp.PARAM_TYPE_BOOL
INT = sp.PARAM_TYPE_INT
CHOICE = sp.PARAM_TYPE_CHOICE


def choice(value: str, label: str = "") -> sp.Choice:
    return sp.Choice(value=value, label=label or value)


def param(key: str, label: str, type: int, *, choices=(), default: str = "",
          required: bool = False) -> sp.Param:
    return sp.Param(key=key, label=label, type=type, choices=list(choices),
                    default=default, required=required)


def descriptor(params, *, message: str = "") -> sp.SourceDescriptor:
    """A ready-to-fill form: these params, all options resolved."""
    return sp.SourceDescriptor(params=list(params), readiness=sp.READINESS_READY,
                               message=message)


def provision_required(message: str) -> sp.SourceDescriptor:
    """No options yet — the source must provision an expensive resource first (e.g. boot an
    emulator). The viewer shows `message` and asks the user to consent before proceeding."""
    return sp.SourceDescriptor(readiness=sp.READINESS_PROVISION_REQUIRED, message=message)


class CaptureSource(abc.ABC):
    """A capture source's control surface. Subclass and implement the three abstract
    methods; the harness handles proto marshaling, session tracking and shutdown."""

    #: Whether the source keeps an expensive resource warm across captures (Android's
    #: emulator, a module's connection). False (the default) → the supervisor may reap the
    #: process after a capture ends plus a short idle; True → held until `release`.
    keep_warm: bool = False

    def __init__(self) -> None:
        self._active: set[str] = set()
        self._lock = threading.Lock()
        #: Set True while bringing a warm resource up, so Status reads PROVISIONING.
        self.provisioning: bool = False

    # --- implement these ---------------------------------------------------

    @abc.abstractmethod
    def describe(self, params: Mapping[str, str]) -> sp.SourceDescriptor:
        """The options this source offers given the partial selection so far. Re-called as
        fields fill in (cascading); build the result with `descriptor`/`param`/`choice`, or
        `provision_required` when a resource must come up first."""

    @abc.abstractmethod
    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        """Open a session (IngestService.OpenSession), begin capturing in the background,
        and return the session id. The harness records it as live."""

    @abc.abstractmethod
    def stop_capture(self, session_id: str) -> None:
        """Stop the capture and close its session. A keep_warm source stays running."""

    def release(self) -> None:
        """Drop any warm resource. Default no-op. Teardown follows provisioning ownership:
        only tear down what this source created, never a resource it merely attached to."""

    # --- for the source to call --------------------------------------------

    def session_ended(self, session_id: str) -> None:
        """Report a capture that ended on its own (duration elapsed, browser closed), so
        Status stops listing it. `stop_capture` need not call this — the harness untracks
        after it — but a self-ending capture must."""
        with self._lock:
            self._active.discard(session_id)

    # --- used by the harness -----------------------------------------------

    def _track(self, session_id: str) -> None:
        with self._lock:
            self._active.add(session_id)

    def _status(self) -> sp.SourceStatus:
        with self._lock:
            active = sorted(self._active)
        if active:
            state = sp.SOURCE_STATE_CAPTURING
        elif self.provisioning:
            state = sp.SOURCE_STATE_PROVISIONING
        else:
            state = sp.SOURCE_STATE_READY
        return sp.SourceStatus(state=state, active_sessions=active)

    def _shutdown(self) -> None:
        """Graceful teardown on signal: stop every live capture, then release."""
        with self._lock:
            active = sorted(self._active)
        for sid in active:
            try:
                self.stop_capture(sid)
            except Exception:  # noqa: BLE001 — keep tearing the rest down
                pass
            self.session_ended(sid)
        try:
            self.release()
        except Exception:  # noqa: BLE001
            pass


class _Servicer(sp_grpc.CaptureSourceServiceServicer):
    """Adapts a CaptureSource to the generated servicer, marshaling proto<->Python and
    turning source-raised errors into gRPC status rather than crashing the server."""

    def __init__(self, source: CaptureSource) -> None:
        self._source = source

    def Describe(self, request, context):
        try:
            return self._source.describe(dict(request.params))
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"describe: {exc}")

    def StartCapture(self, request, context):
        try:
            sid = self._source.start_capture(request.label, dict(request.params))
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"start: {exc}")
        self._source._track(sid)
        return ctl.StartCaptureResponse(session_id=sid)

    def StopCapture(self, request, context):
        try:
            self._source.stop_capture(request.session_id)
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"stop: {exc}")
        self._source.session_ended(request.session_id)
        return ctl.Empty()

    def ReleaseSource(self, request, context):
        try:
            self._source.release()
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"release: {exc}")
        return ctl.Empty()

    def Status(self, request, context):
        return self._source._status()


def serve(source: CaptureSource, addr: str) -> tuple[grpc.Server, int]:
    """Start a gRPC server for `source` bound to `addr` (host:port; port 0 auto-assigns).
    Returns the running server and the bound port. Does not block."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    sp_grpc.add_CaptureSourceServiceServicer_to_server(_Servicer(source), server)
    port = server.add_insecure_port(addr)
    if port == 0:
        raise RuntimeError(f"could not bind {addr!r}")
    server.start()
    return server, port


def serve_forever(source: CaptureSource, addr: str, *, on_ready=None) -> None:
    """Serve `source` and block until SIGTERM/SIGINT, then shut down gracefully — stop
    every live capture and release the resource — so a supervised tool never strands a
    session. `on_ready(port)` is called once the server is up (e.g. to print the address
    the supervisor waits for)."""
    server, port = serve(source, addr)
    if on_ready is not None:
        on_ready(port)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    source._shutdown()
    server.stop(grace=5).wait()
