"""The viewer's own remembered choices, kept between runs in
$TRAFFIC_DECK_HOME/viewer.json (default ~/.traffic-deck) — the per-user root the gateway
and capture tools share. Best effort both ways: a missing or unreadable file means the
defaults, and a failed write costs only the memory of the choice."""

from __future__ import annotations

import json
import os
from pathlib import Path


def _path() -> Path:
    home = os.environ.get("TRAFFIC_DECK_HOME") or os.path.join(os.path.expanduser("~"), ".traffic-deck")
    return Path(home) / "viewer.json"


def load() -> dict:
    try:
        data = json.loads(_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get(key: str, default=None):
    return load().get(key, default)


def set(key: str, value) -> None:  # noqa: A001 — the module is the namespace
    data = load()
    data[key] = value
    try:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n")
        tmp.replace(p)
    except OSError:
        pass
