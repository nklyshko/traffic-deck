"""Remembered interactive selections for the capture CLIs.

Each tool gets a small JSON file under ``~/.traffic-deck/state/<tool>.json`` that
records the user's last choices (Chrome binary, frida version, app package, …) so
the next run can reoffer them as the default — less re-typing/re-picking across
captures. Values must be JSON-serializable (strings, numbers, lists of those).
"""

from __future__ import annotations

import json
from typing import Any, Collection

from .paths import data_dir


def _normalize(value: Any) -> Any:
    """JSON round-trip a value so it equals the form it takes once read back from
    disk — chiefly turning tuple-valued choices (e.g. a discovered Chrome profile's
    ``(user_data_dir, profile_directory)``) into the lists JSON stores them as, so a
    remembered selection still matches the freshly-built choice list next run."""
    return json.loads(json.dumps(value)) if value is not None else None


class Store:
    """A tool's remembered selections, backed by one JSON file.

    Reads are in-memory; [remember][capture_sdk.state.Store.remember] writes
    through to disk immediately so a CLI that's killed mid-run still keeps the
    choices made before the crash.
    """

    def __init__(self, tool: str) -> None:
        self._path = data_dir("state") / f"{tool}.json"
        try:
            data = json.loads(self._path.read_text())
            self._data: dict[str, Any] = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self._data = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def get_valid(self, key: str, valid: Collection, default: Any = None) -> Any:
        """The actual element of `valid` matching the remembered selection for `key`,
        or `default` if the remembered choice is no longer offered (a binary that's
        gone, an emulator no longer running, an app uninstalled). Matching is by
        normalized form, so tuple-valued choices round-trip correctly. Returns the
        live choice value (not the stored one) so it can feed a prompt's `default=`."""
        remembered = self._data.get(key)
        for v in valid:
            if _normalize(v) == remembered:
                return v
        return default

    def remember(self, key: str, value: Any) -> Any:
        """Persist `value` under `key`, then return it — so a selection can be
        wrapped inline, e.g. ``chrome = store.remember("chrome", pick())``. Stored in
        normalized form so it matches the freshly-built choices on the next run."""
        norm = _normalize(value)
        if self._data.get(key) != norm:
            self._data[key] = norm
            self._save()
        return value

    def _save(self) -> None:
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._data, indent=2, ensure_ascii=False))
        tmp.replace(self._path)  # atomic: never leave a half-written state file
