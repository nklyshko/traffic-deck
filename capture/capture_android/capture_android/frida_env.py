"""Where a capture process runs, and under which frida.

Client and frida-server versions must match, so frida is picked per device and is not in
this package's dependencies. From a checkout it is layered on by `uv run --with`. An installed
copy has no project to run against, so `make install` builds one venv per version in
frida_versions.py (ADR-0017 §5).
"""

from __future__ import annotations

import sys
from pathlib import Path

from capture_sdk.paths import installed_prefix

_PROJECT = str(Path(__file__).resolve().parents[1])  # the capture_android project dir


def _env_dir(prefix: Path, version: str) -> Path:
    # Named for the exact version: a venv holding a different frida would pass for the right
    # one and fail on the device as a client/server mismatch.
    return prefix / "venvs" / f"android-frida-{version}"


def python_cmd(module: str, frida_version: str | None = None) -> list[str]:
    """argv that runs `python -m module`, under `frida_version` if given."""
    prefix = installed_prefix()
    if prefix is None:
        cmd = ["uv", "run", "--project", _PROJECT]
        if frida_version:
            cmd += ["--with", f"frida=={frida_version}"]
        return [*cmd, "python", "-m", module]
    if not frida_version:
        return [sys.executable, "-m", module]
    python = _env_dir(prefix, frida_version) / "bin" / "python"
    if not python.exists():
        raise RuntimeError(f"frida {frida_version} is not part of the install at {prefix}; "
                           "the supported versions are installed by `make install`")
    return [str(python), "-m", module]
