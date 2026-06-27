"""Two-stage Ctrl-C for the capture tools.

A capture should *finish* cleanly on Ctrl-C — stop recording, flush the pending
upload, and close the gateway session — rather than leaving a half-open session
behind. But a user who really wants out shouldn't be stuck waiting on that teardown.

So the first Ctrl-C requests a graceful stop: it sets the event the capture loop
watches, *without* raising, so in-flight cleanup isn't torn apart mid-step. A second
Ctrl-C restores Python's default handler and raises ``KeyboardInterrupt``, aborting
immediately (by which point recording is already stopped, so nothing is left running).

Signals are delivered on the main thread only; off the main thread this no-ops and
the caller keeps the default Ctrl-C behaviour.
"""

from __future__ import annotations

import signal
import sys
import threading


class GracefulInterrupt:
    """Context manager installing the two-stage SIGINT handler described above.

    The capture loop should poll [stopping][capture_sdk.shutdown.GracefulInterrupt.stopping]
    (or the shared `event`) and break when it's set, then run its teardown; wrap the
    slow part of that teardown (upload drain / session close) in
    ``try/except KeyboardInterrupt`` so a second Ctrl-C abandons it.
    """

    def __init__(self, event: threading.Event | None = None, *,
                 message: str = "stopping — press Ctrl-C again to force-quit") -> None:
        self.event = event or threading.Event()
        self._message = message
        self._installed = False
        self._prev = None

    @property
    def stopping(self) -> bool:
        """Whether a graceful stop has been requested (the first Ctrl-C arrived)."""
        return self.event.is_set()

    def _handle(self, signum, frame) -> None:
        if not self.event.is_set():
            self.event.set()  # first Ctrl-C: ask the capture to wind down
            print(f"\n{self._message}", file=sys.stderr, flush=True)
            return
        # Second Ctrl-C: hand SIGINT back to the default handler and abort now.
        signal.signal(signal.SIGINT, self._prev or signal.SIG_DFL)
        raise KeyboardInterrupt

    def __enter__(self) -> "GracefulInterrupt":
        try:
            self._prev = signal.signal(signal.SIGINT, self._handle)
            self._installed = True
        except ValueError:
            self._installed = False  # not the main thread — leave Ctrl-C as-is
        return self

    def __exit__(self, *exc) -> bool:
        if self._installed:
            signal.signal(signal.SIGINT, self._prev)
        return False
