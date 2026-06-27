"""Filesystem locations for persistent capture data, all rooted at ``~/.traffic-deck``
(override with ``$TRAFFIC_DECK_HOME``).

Keeping every tool's persistent state — remembered selections, named Chrome
profiles, dropped Frida scripts — under one directory makes a capture host's data
easy to find, back up, or wipe.
"""

from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    """Root directory for all persistent TrafficDeck capture data."""
    env = os.environ.get("TRAFFIC_DECK_HOME")
    return Path(env).expanduser() if env else Path.home() / ".traffic-deck"


def data_dir(*parts: str) -> Path:
    """A subdirectory under [home][capture_sdk.paths.home], created if missing."""
    p = home().joinpath(*parts)
    p.mkdir(parents=True, exist_ok=True)
    return p
