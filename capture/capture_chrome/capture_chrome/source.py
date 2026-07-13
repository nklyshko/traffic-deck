"""Chrome as a CaptureSourceService the gateway dials (ADR-0010).

`describe` reports the capture options — the discovered Chrome binaries, then (once one is
chosen) that binary's flattened profile choices — reading the same discovery and remembered
defaults the interactive picker uses, so the two can't drift. `start_capture` resolves the
chosen params, launches a `ChromeCapture` in the background and returns the session id; a
watcher ends the session if the browser is closed.
"""

from __future__ import annotations

import threading
from typing import Mapping

from capture_chrome import platform, profiles
from capture_chrome.capture import ChromeCapture
from capture_sdk import source
from capture_sdk.proto import source_pb2 as sp
from capture_sdk.state import Store


class ChromeSource(source.CaptureSource):
    """Chrome holds no warm resource, so it is transient (keep_warm stays False)."""

    def __init__(self, gateway: str) -> None:
        super().__init__()
        self._gateway = gateway
        self._store = Store("chrome")
        self._caps: dict[str, ChromeCapture] = {}
        self._caps_lock = threading.Lock()

    def describe(self, params: Mapping[str, str]) -> sp.SourceDescriptor:
        bins = platform.chrome_binaries()
        chrome = params.get("chrome") or self._store.get_valid("chrome", bins) or (bins[0] if bins else "")

        out = []
        if bins:
            out.append(source.param(
                "chrome", "Chrome binary", source.CHOICE,
                choices=[source.choice(b) for b in bins], default=chrome, required=True))
        else:
            out.append(source.param("chrome", "Chrome binary path", source.PATH,
                                    default=chrome, required=True))

        # Cascade: the profile (and the rest) only appear once a binary is known, so the
        # profile choices are for the chosen binary — the chrome->profiles dependency.
        if chrome:
            choices = profiles.profile_choices(chrome)
            default = self._store.get_valid("profile_value", [v for v, _ in choices]) or "temp"
            out.append(source.param(
                "profile", "Profile", source.CHOICE,
                choices=[source.choice(v, label) for v, label in choices], default=default))
            out.append(source.param("new_profile_name", "New profile name", source.STRING))
            out.append(source.param("url", "Open URL", source.STRING))
            out.append(source.param("duration", "Auto-stop after (seconds)", source.INT))
        return source.descriptor(out)

    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        chrome = params.get("chrome") or platform.chrome_binary()
        profile_value = params.get("profile") or "temp"
        # Remember the choices so the next Describe defaults to them, exactly as the CLI
        # picker's Store does — keeping the "defaults to your last run" behaviour in serve mode.
        self._store.remember("chrome", chrome)
        self._store.remember("profile_value", profile_value)
        profile = profiles.resolve_profile(chrome, profile_value, params.get("new_profile_name", ""))
        duration = float(params["duration"]) if params.get("duration") else None

        cap = ChromeCapture(
            gateway=self._gateway, label=label or "chrome", chrome=chrome, profile=profile,
            url=params.get("url") or None, duration=duration)
        sid = cap.start()
        with self._caps_lock:
            self._caps[sid] = cap
        threading.Thread(target=self._watch, args=(sid, cap), daemon=True).start()
        return sid

    def _watch(self, sid: str, cap: ChromeCapture) -> None:
        """Wait for the browser to close (or the duration to elapse), then finalize the
        session so a capture the user ended in the browser doesn't linger."""
        cap.wait()
        with self._caps_lock:
            still_here = self._caps.pop(sid, None) is not None
        if still_here:
            try:
                cap.stop()
            except Exception:  # noqa: BLE001
                pass
            self.session_ended(sid)

    def stop_capture(self, session_id: str) -> None:
        with self._caps_lock:
            cap = self._caps.pop(session_id, None)
        if cap is not None:
            cap.request_stop()  # unblock the watcher's wait()
            cap.stop()          # idempotent with the watcher
