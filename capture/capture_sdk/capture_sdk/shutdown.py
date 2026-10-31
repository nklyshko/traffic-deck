"""Two-stage Ctrl-C for the capture tools.

A capture should *finish* cleanly on Ctrl-C — stop recording, flush the pending
upload, and close the gateway session — rather than leaving a half-open session
behind. But a user who really wants out shouldn't be stuck waiting on that teardown.

So the first Ctrl-C requests a graceful stop: it sets the event the capture loop
watches, *without* raising, so in-flight cleanup isn't torn apart mid-step. A second
Ctrl-C restores the previous handlers and raises ``KeyboardInterrupt``, aborting
immediately (by which point recording is already stopped, so nothing is left running).

Signals are delivered on the main thread only; off the main thread this no-ops and
the caller keeps the default Ctrl-C behaviour.
"""

from __future__ import annotations

import queue
import signal
import sys
import threading
from typing import Callable


def signal_safe_set(event: threading.Event, before: Callable[[], None] | None = None):
    """A callable that sets `event` and is safe to call from a signal handler.

    Event.set takes a non-reentrant lock, and a handler runs on the main thread between any
    two bytecodes, including while that same thread holds the lock: inside a wait on the
    event, or inside the set of a signal delivered just before. It then waits on itself
    forever, and every later signal joins it, so nothing short of SIGKILL ends the process.
    This is not a corner case: a process under `uv run` gets SIGTERM twice from a group
    kill, the kill and uv's forward, about 100µs apart.

    So the handler only queues the request, SimpleQueue.put being reentrant, and a thread
    sets the event. `before` runs on that thread first, for work a handler can't do either
    (print is not reentrant)."""
    requests: queue.SimpleQueue[None] = queue.SimpleQueue()

    def deliver() -> None:
        requests.get()
        if before is not None:
            before()
        event.set()

    threading.Thread(target=deliver, daemon=True, name="signal-stop").start()
    return lambda: requests.put(None)


class GracefulInterrupt:
    """Context manager installing the two-stage SIGINT/SIGTERM handler described above.

    The capture loop should poll [stopping][capture_sdk.shutdown.GracefulInterrupt.stopping]
    (or the shared `event`) and break when it's set, then run its teardown; wrap the
    slow part of that teardown (upload drain / session close) in
    ``try/except KeyboardInterrupt`` so a second Ctrl-C abandons it.
    """

    def __init__(self, event: threading.Event | None = None, *,
                 message: str = "stopping — press Ctrl-C again to force-quit") -> None:
        self.event = event or threading.Event()
        self._message = message
        self._requested = False
        self._request = signal_safe_set(self.event, self._announce)
        self._installed = False
        self._prev = None
        self._prev_term = None

    @property
    def stopping(self) -> bool:
        """Whether a graceful stop has been requested (the first Ctrl-C arrived)."""
        return self._requested or self.event.is_set()

    def _announce(self) -> None:
        print(f"\n{self._message}", file=sys.stderr, flush=True)

    def _handle(self, signum, frame) -> None:
        if not self.stopping:
            self._requested = True
            self._request()
            return
        # Restore the previous handlers so a third signal kills outright, even if the
        # teardown this abort starts hangs.
        signal.signal(signal.SIGINT, self._prev or signal.SIG_DFL)
        signal.signal(signal.SIGTERM, self._prev_term or signal.SIG_DFL)
        raise KeyboardInterrupt

    def __enter__(self) -> "GracefulInterrupt":
        try:
            self._prev = signal.signal(signal.SIGINT, self._handle)
            # Also catch SIGTERM: the gateway reaps a capture source by group-killing it
            # with SIGTERM (then SIGKILL after a grace), and a standalone capture that
            # dies on the default SIGTERM action runs no teardown — leaving the on-device
            # tcpdump/frida, iptables rules and a half-open session behind.
            self._prev_term = signal.signal(signal.SIGTERM, self._handle)
            self._installed = True
        except ValueError:
            self._installed = False  # not the main thread — leave the defaults as-is
        return self

    def __exit__(self, *exc) -> bool:
        if self._installed:
            signal.signal(signal.SIGINT, self._prev)
            signal.signal(signal.SIGTERM, self._prev_term)
        return False
