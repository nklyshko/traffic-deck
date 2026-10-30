"""The session id a spawned capture process announces on its output (`SESSION <id>`)."""

from __future__ import annotations

import threading
from typing import Callable

SESSION_PREFIX = "SESSION "


def read_session_id(proc, *, echo: Callable[[str], None] | None = None,
                    grace: float = 30.0) -> str | None:
    """The id from the first `SESSION <id>` line proc prints, or None once its output ends
    without one.

    The process can keep running without ever printing it — mitmdump does when its addon's
    startup hook fails (the gateway is down) — and the read would then block forever,
    holding the caller, often a gRPC thread. So the process is killed after `grace`, which
    closes the pipe and ends the read. A process started through `uv run` needs a grace
    that covers a cold environment build before it even starts (ADR-0015 §6)."""
    watchdog = threading.Timer(grace, proc.kill)
    watchdog.start()
    try:
        for line in proc.stdout:
            if echo is not None:
                echo(line)
            if line.startswith(SESSION_PREFIX):
                return line[len(SESSION_PREFIX):].strip()
    finally:
        watchdog.cancel()
    return None
