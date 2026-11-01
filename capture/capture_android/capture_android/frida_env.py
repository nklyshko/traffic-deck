"""Where a capture process runs, and under which frida.

Client and frida-server versions must match, so frida is picked per device and is not in
this package's dependencies. From a checkout it is layered on by `uv run --with`. An installed
copy has no project to run against, so it keeps one venv per version, built the first time
that version is needed (ADR-0017 §5).
"""

from __future__ import annotations

import fcntl
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable

from capture_sdk.paths import installed_prefix

_PROJECT = str(Path(__file__).resolve().parents[1])  # the capture_android project dir

#: How long a viewer-driven start waits on a build. Under the 120s the source allows a start
#: to settle, with room left to launch the capture if the build finishes just in time.
START_WAIT = 90.0

_READY = ".ready"
_builds: dict[str, threading.Thread] = {}
_errors: dict[str, str] = {}
_guard = threading.Lock()


class FridaNotReady(RuntimeError):
    """The venv for a frida version does not exist yet. Retrying is the remedy."""


def _env_dir(prefix: Path, version: str) -> Path:
    return prefix / "venvs" / f"android-frida{version.split('.')[0]}"


def _build(prefix: Path, version: str, log: Callable[[str], None]) -> None:
    env = _env_dir(prefix, version)
    python = str(env / "bin" / "python")
    wheels = str(prefix / "wheels")
    # An flock, because the interactive CLI and the serve-mode source are separate processes
    # and either can get here first.
    with open(prefix / "venvs" / f".android-frida-{version}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (env / _READY).exists():
            return
        log(f"preparing frida {version} (first use; downloads about 30MB)…")
        for cmd in (
            ["uv", "venv", "--clear", "--python", sys.executable, str(env)],
            ["uv", "pip", "install", "--python", python,
             "-r", str(prefix / "requirements" / "capture_android.txt"), f"frida=={version}"],
            ["uv", "pip", "install", "--python", python, "--no-deps", "--no-index",
             "--find-links", wheels, "trafficdeck-proto", "trafficdeck-capture-sdk",
             "trafficdeck-capture-android"],
        ):
            subprocess.run(cmd, check=True, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        (env / _READY).touch()
        log(f"frida {version} is ready")


def _run_build(prefix: Path, version: str, log: Callable[[str], None]) -> None:
    try:
        _build(prefix, version, log)
    except FileNotFoundError:
        _errors[version] = "`uv` is needed to prepare frida on first use, and is not on PATH"
    except subprocess.CalledProcessError as exc:
        reason = (exc.stderr or "").strip().splitlines()
        detail = reason[-1] if reason else f"exit {exc.returncode}"
        _errors[version] = f"could not prepare frida {version} (network?): {detail}"


def ensure_frida(version: str, *, wait: float | None = None,
                 log: Callable[[str], None] = lambda _m: None) -> None:
    """Make sure `version`'s venv exists, waiting up to `wait` seconds (None: as long as it takes).

    The build runs on its own thread so it outlives a caller that runs out of time: the
    download can outlast any gRPC deadline, and a retry should find the work done rather than
    start it over. Does nothing from a checkout."""
    prefix = installed_prefix()
    if prefix is None or (_env_dir(prefix, version) / _READY).exists():
        return
    with _guard:
        build = _builds.get(version)
        if build is None or not build.is_alive():
            _errors.pop(version, None)
            build = threading.Thread(target=_run_build, args=(prefix, version, log), daemon=True)
            _builds[version] = build
            build.start()
    build.join(wait)
    if build.is_alive():
        raise FridaNotReady(f"frida {version} is still being prepared, retry shortly")
    if version in _errors:
        raise RuntimeError(_errors[version])


def python_cmd(module: str, frida_version: str | None = None) -> list[str]:
    """argv that runs `python -m module`, under `frida_version` if given. Call `ensure_frida`
    first."""
    prefix = installed_prefix()
    if prefix is None:
        cmd = ["uv", "run", "--project", _PROJECT]
        if frida_version:
            cmd += ["--with", f"frida=={frida_version}"]
        return [*cmd, "python", "-m", module]
    python = str(_env_dir(prefix, frida_version) / "bin" / "python") if frida_version else sys.executable
    return [python, "-m", module]
