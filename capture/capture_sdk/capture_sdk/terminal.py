"""Restore the controlling terminal to canonical (cooked) line mode.

questionary's prompt_toolkit backend switches the tty to raw mode for its arrow-key
prompts and, on a terminal that doesn't answer cursor-position requests (CPR) — e.g.
some IDE terminals — can leave it raw. A raw tty has signal generation disabled
(ISIG off), so Ctrl-C during the capture never becomes SIGINT: it arrives as a literal
``^C`` byte and the capture can't be stopped. Call [restore][capture_sdk.terminal.restore]
once the interactive prompts are done, before the capture starts, so Ctrl-C works.
"""

from __future__ import annotations

import os
import sys


def restore() -> None:
    """Re-enable canonical mode, echo, and signal generation on the controlling tty,
    and drop any keystrokes typed while it was raw. No-op when stdin isn't a tty or
    termios is unavailable (non-Unix / captured stdin)."""
    try:
        import termios
        fd = sys.stdin.fileno()
    except Exception:  # noqa: BLE001 (no termios / captured stdin)
        return
    if not os.isatty(fd):
        return
    try:
        attr = termios.tcgetattr(fd)
        attr[0] |= termios.ICRNL | termios.IXON                                   # iflag: CR→NL
        attr[1] |= termios.OPOST                                                  # oflag
        attr[3] |= termios.ICANON | termios.ECHO | termios.ISIG | termios.IEXTEN  # lflag
        termios.tcsetattr(fd, termios.TCSANOW, attr)
        termios.tcflush(fd, termios.TCIFLUSH)  # discard ^C/^M bytes typed while raw
    except (termios.error, OSError):
        pass
