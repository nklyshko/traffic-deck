"""Firefox as a CaptureSourceService the gateway dials (ADR-0010).

`describe` reports the capture options — the discovered Firefox binaries, then (once one is
chosen) that binary's flattened profile choices — reading the same discovery and remembered
defaults the interactive picker uses, so the two can't drift. `start_capture` resolves the
chosen params, launches a `FirefoxCapture` in the background and returns the session id; a
watcher ends the session if the browser is closed.
"""

from __future__ import annotations

import threading
from typing import Mapping

from capture_firefox import platform, profiles
from capture_firefox.capture import FirefoxCapture
from capture_sdk import source
from capture_sdk.proto import control_pb2 as ctl
from capture_sdk.state import Store


class FirefoxSource(source.CaptureSource):
    """Firefox holds no warm resource, so it is transient (keep_warm stays False)."""

    def __init__(self, gateway: str) -> None:
        super().__init__()
        self._gateway = gateway
        self._store = Store("firefox")
        self._caps: dict[str, FirefoxCapture] = {}
        self._caps_lock = threading.Lock()

    def describe(self, params: Mapping[str, str]) -> ctl.SourceDescriptor:
        bins = platform.firefox_binaries()
        firefox = params.get("firefox") or self._store.get_valid("firefox", bins) or (bins[0] if bins else "")

        out = []
        if bins:
            out.append(source.param(
                "firefox", "Firefox binary", source.CHOICE,
                choices=[source.choice(b) for b in bins], default=firefox, required=True))
        else:
            out.append(source.param("firefox", "Firefox binary path", source.PATH,
                                    default=firefox, required=True))

        # The profile tree, by re-description: profile_kind first (its choices are for the
        # chosen binary), then the which-one param appears only once its kind is picked —
        # the same drill-down the CLI picker prompts, no field shown before it applies.
        if firefox:
            out.extend(self._profile_params(firefox, params))
            out.append(source.param("url", "Open URL", source.STRING))
            out.append(source.param("duration", "Auto-stop after (seconds)", source.INT))
        return source.descriptor(out)

    def _profile_params(self, firefox: str, params: Mapping[str, str]) -> list:
        kinds = []
        if platform.firefox_profiles(firefox):  # only offer "existing" when some exist
            kinds.append(source.choice("existing", "An existing profile of this browser"))
        kinds += [source.choice("default", "The browser's own default profile"),
                  source.choice("temp", "A fresh temporary profile"),
                  source.choice("custom", "A saved persistent profile")]
        kind = (params.get("profile_kind")
                or self._store.get_valid("profile_kind", [c.value for c in kinds]) or "temp")
        out = [source.param("profile_kind", "Profile", source.CHOICE, choices=kinds, default=kind)]

        if kind == "existing":
            profs = platform.firefox_profiles(firefox)
            default = (self._store.get_valid("existing_profile", [n for _, n, _ in profs])
                       or (profs[0][1] if profs else ""))
            out.append(source.param(
                "existing_profile", "Which profile", source.CHOICE,
                choices=[source.choice(name, f"{name} [{path}]") for _, name, path in profs],
                default=default))
        elif kind == "custom":
            saved = profiles.saved_profiles(firefox)
            choices = [source.choice(n, n) for n in saved] + [source.choice("__new__", "＋ New profile…")]
            # Default to the first saved profile when any exist, so the name field only
            # appears when the user actually picks "new".
            sel = (params.get("saved_profile")
                   or self._store.get_valid("saved_profile", [c.value for c in choices])
                   or (saved[0] if saved else "__new__"))
            out.append(source.param("saved_profile", "Saved profile", source.CHOICE,
                                    choices=choices, default=sel))
            if sel == "__new__":
                out.append(source.param("new_profile_name", "New profile name", source.STRING,
                                        default=self._store.get("profile_name") or "default"))
        return out

    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        firefox = params.get("firefox") or platform.firefox_binary()
        # Remember choices so the next Describe defaults to them, exactly as the CLI picker's
        # Store does — keeping "defaults to your last run" in serve mode.
        self._store.remember("firefox", firefox)
        profile = self._resolve_profile(firefox, params)
        duration = float(params["duration"]) if params.get("duration") else None

        cap = FirefoxCapture(
            gateway=self._gateway, label=label or "firefox", firefox=firefox, profile=profile,
            url=params.get("url") or None, duration=duration)
        sid = cap.start()
        with self._caps_lock:
            self._caps[sid] = cap
        threading.Thread(target=self._watch, args=(sid, cap), daemon=True).start()
        return sid

    def _resolve_profile(self, firefox: str, params: Mapping[str, str]):
        """Turn the chosen profile params into the launch form, mirroring the kinds Describe
        offered, and remember each selection for next time."""
        kind = params.get("profile_kind") or "temp"
        self._store.remember("profile_kind", kind)
        if kind == "default":
            return profiles.BUILTIN_PROFILE
        if kind == "existing":
            name = params.get("existing_profile") or ""
            self._store.remember("existing_profile", name)
            return profiles.resolve_existing(firefox, name)
        if kind == "custom":
            sel = params.get("saved_profile") or "__new__"
            self._store.remember("saved_profile", sel)
            if sel == "__new__":
                name = params.get("new_profile_name") or "default"
                self._store.remember("profile_name", name)
            else:
                name = sel
            return profiles.persistent_path(firefox, name)
        return profiles.temp_profile(firefox)  # temp (the default)

    def _watch(self, sid: str, cap: FirefoxCapture) -> None:
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
