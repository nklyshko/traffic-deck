"""Serve a capture tool as a `CaptureSourceService` the gateway dials.

A tool becomes a controllable source by subclassing [CaptureSource][capture_sdk.source.CaptureSource]
— implement `describe`/`start_capture`/`stop_capture` (and `release` if it holds a warm
resource) in plain Python — and calling [serve_forever][capture_sdk.source.serve_forever]
from its `serve` subcommand. The harness wraps that into the gRPC servicer, tracks which
sessions are live so `Status` is automatic, and on SIGTERM/SIGINT (the supervisor's
group-kill) stops each live capture and releases the resource before exiting, so a
supervised tool finalizes cleanly rather than stranding sessions. See ADR-0010.

One process can serve **several named sources** — pass `{name: source}` to serve_forever.
That is for a module whose tools share one expensive resource: Android offers per-app
capture and browser capture as two sources over one emulator, booted once. Requests carry
the source name, so a single-source tool needs no change.

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
from capture_sdk.proto import source_pb2_grpc as sp_grpc
from capture_sdk.shutdown import signal_safe_set

# Re-exported for ergonomic descriptors: `source.STRING`, `source.CHOICE`, …
STRING = ctl.PARAM_TYPE_STRING
PATH = ctl.PARAM_TYPE_PATH
BOOL = ctl.PARAM_TYPE_BOOL
INT = ctl.PARAM_TYPE_INT
CHOICE = ctl.PARAM_TYPE_CHOICE


def choice(value: str, label: str = "") -> ctl.Choice:
    return ctl.Choice(value=value, label=label or value)


def param(key: str, label: str, type: int, *, choices=(), default: str = "",
          required: bool = False) -> ctl.Param:
    return ctl.Param(key=key, label=label, type=type, choices=list(choices),
                    default=default, required=required)


def descriptor(params, *, message: str = "") -> ctl.SourceDescriptor:
    """A ready-to-fill form: these params, all options resolved."""
    return ctl.SourceDescriptor(params=list(params), readiness=ctl.READINESS_READY,
                               message=message)


def provision_required(message: str) -> ctl.SourceDescriptor:
    """No options yet — the source must provision an expensive resource first (e.g. boot an
    emulator). The viewer shows `message` and asks the user to consent before proceeding."""
    return ctl.SourceDescriptor(readiness=ctl.READINESS_PROVISION_REQUIRED, message=message)


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
    def describe(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
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
        only tear down what this source created, never a resource it merely attached to —
        and never one another source in this process is still using (see serve)."""

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

    def _status(self) -> ctl.SourceStatus:
        with self._lock:
            active = sorted(self._active)
        if active:
            state = ctl.SOURCE_STATE_CAPTURING
        elif self.provisioning:
            state = ctl.SOURCE_STATE_PROVISIONING
        else:
            state = ctl.SOURCE_STATE_READY
        return ctl.SourceStatus(state=state, active_sessions=active)

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
    """Adapts one or more CaptureSources to the generated servicer, marshaling
    proto<->Python and turning source-raised errors into gRPC status rather than crashing
    the server.

    A module may serve several named sources over this one connection (ADR-0010), so each
    request names the one it addresses. An empty name means "the primary source" — what a
    single-source module always gets, and what an older gateway sends.
    """

    def __init__(self, sources: CaptureSource | Mapping[str, CaptureSource]) -> None:
        if isinstance(sources, CaptureSource):
            # A tool serving one source does not know the name the gateway registered it
            # under, and does not need to: it has exactly one tool, and the gateway would not
            # have dialed it for anything else. So it answers whatever name it is asked for.
            self._named: dict[str, CaptureSource] = {}
            self._primary = sources
            return
        if not sources:
            raise ValueError("serve needs at least one source")
        self._named = dict(sources)
        # First declared wins the unnamed requests — declaration order is the module's own
        # statement of which tool is the obvious one.
        self._primary = next(iter(self._named.values()))

    def _all(self) -> list[CaptureSource]:
        return list(self._named.values()) or [self._primary]

    def _pick(self, name: str, context) -> CaptureSource:
        if not name or not self._named:
            return self._primary
        src = self._named.get(name)
        if src is None:
            context.abort(grpc.StatusCode.NOT_FOUND,
                          f"this module does not serve source {name!r} "
                          f"(serves: {', '.join(sorted(self._named))})")
        return src

    def _owner(self, session_id: str) -> CaptureSource:
        """Which source started this session. Stop and its untracking must land on the
        source that owns the capture, and StopCapture carries no source name — the session
        id already identifies one capture across the whole module."""
        for src in self._all():
            if session_id in src._status().active_sessions:
                return src
        return self._primary

    def Describe(self, request, context):
        src = self._pick(request.source, context)
        try:
            return src.describe(dict(request.params))
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"describe: {exc}")

    def StartCapture(self, request, context):
        src = self._pick(request.source, context)
        try:
            sid = src.start_capture(request.label, dict(request.params))
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"start: {exc}")
        src._track(sid)
        return ctl.StartCaptureResponse(session_id=sid)

    def StopCapture(self, request, context):
        src = self._owner(request.session_id)
        try:
            src.stop_capture(request.session_id)
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"stop: {exc}")
        src.session_ended(request.session_id)
        return ctl.Empty()

    def ReleaseSource(self, request, context):
        src = self._pick(request.source, context)
        try:
            src.release()
        except Exception as exc:  # noqa: BLE001
            context.abort(grpc.StatusCode.INTERNAL, f"release: {exc}")
        return ctl.Empty()

    def Status(self, request, context):
        return self._pick(request.source, context)._status()


def serve(sources: CaptureSource | Mapping[str, CaptureSource],
          addr: str) -> tuple[grpc.Server, int]:
    """Start a gRPC server for `sources` bound to `addr` (host:port; port 0 auto-assigns).
    Returns the running server and the bound port. Does not block.

    `sources` is one CaptureSource, or a `{name: source}` mapping when this module offers
    several tools over one connection — the way to expose one warm resource (an emulator)
    as more than one source without provisioning it twice. The names are the ones the
    gateway registered; the first is the primary.
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    sp_grpc.add_CaptureSourceServiceServicer_to_server(_Servicer(sources), server)
    port = server.add_insecure_port(addr)
    if port == 0:
        raise RuntimeError(f"could not bind {addr!r}")
    server.start()
    return server, port


# Canonical line printed on stdout once the server is bound, so the supervisor knows the
# source is up and on which port — a stable contract independent of any tool's own logging.
READY_PREFIX = "traffic-deck source ready "


def serve_forever(sources: CaptureSource | Mapping[str, CaptureSource], addr: str,
                  *, on_ready=None) -> None:
    """Serve `sources` and block until SIGTERM/SIGINT, then shut down gracefully — stop
    every live capture and release each resource — so a supervised tool never strands a
    session. Prints the canonical READY_PREFIX line the supervisor waits for; `on_ready(port)`
    is an extra hook."""
    server, port = serve(sources, addr)
    print(f"{READY_PREFIX}127.0.0.1:{port}", flush=True)
    if on_ready is not None:
        on_ready(port)
    stop = threading.Event()
    request_stop = signal_safe_set(stop)
    # Further signals change nothing, on purpose: under `uv run` a second SIGTERM is the
    # same stop delivered twice (see signal_safe_set), so it can't mean "force". The gateway
    # bounds a teardown that hangs with SIGKILL (sourceShutdownGrace).
    signal.signal(signal.SIGTERM, lambda *_: request_stop())
    signal.signal(signal.SIGINT, lambda *_: request_stop())
    stop.wait()
    # Every source, not just the primary: each stops its own captures, and a resource shared
    # between them is torn down by whichever of them is last (see CaptureSource.release).
    for src in ([sources] if isinstance(sources, CaptureSource) else list(sources.values())):
        src._shutdown()
    server.stop(grace=5).wait()
