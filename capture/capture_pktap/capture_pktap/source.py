"""pktap as a `CaptureSourceService` the gateway dials.

Unlike every built-in source, this one is **not spawned by the gateway** — it needs root,
and the gateway spawns sources with `Setsid: true` and their stdio redirected to log files,
so `sudo` there has no terminal to prompt on. Instead the user starts it themselves, once,
under `sudo`, and enrols it as a module whose manifest carries only a `[control]` block:

    name = "pktap"

    [control]
    addr   = "127.0.0.1:7071"
    source = "chrome-pktap"
    label  = "Chrome (per-process)"

A manifest with no `[[process]]` entries registers a dial-only source — `ApplyManifests`
marks it lazy, `Services.StartModule` is a no-op with nothing to start, and the manager
dials `addr` rather than spawning anything. So one interactive `sudo` at startup buys
prompt-free start/stop for every capture after it, from the TUI and a web UI alike.

`describe` and the profile tree are inherited from `ChromeSource` wholesale; only the
runner differs (`capture_cls`) and the filesystem work that must not happen as root.
"""

from __future__ import annotations

from typing import Mapping

from capture_chrome.source import ChromeSource

from capture_pktap import privdrop
from capture_pktap.capture import PktapCapture


class PktapSource(ChromeSource):
    """Chrome captured per-process. Transient like the plain Chrome source: the privileged
    process stays up across captures, but it holds no resource *per* capture."""

    def __init__(self, gateway: str, run_as: tuple[int, int] | None,
                 tcpdump: str | None = None) -> None:
        super().__init__(gateway)
        self._run_as = run_as
        self._tcpdump = tcpdump

    def start_capture(self, label: str, params: Mapping[str, str]) -> str:
        return super().start_capture(label or "chrome-pktap", params)

    def new_capture(self, **kw) -> PktapCapture:
        return PktapCapture(run_as=self._run_as, tcpdump=self._tcpdump, **kw)

    def _resolve_profile(self, chrome: str, params: Mapping[str, str]):
        # Creates temp/saved profile dirs and writes the remembered-choices state file —
        # all inside the user's home, so none of it may be created as root.
        with privdrop.as_user(self._run_as):
            return super()._resolve_profile(chrome, params)
