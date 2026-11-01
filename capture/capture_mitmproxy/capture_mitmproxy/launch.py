"""Which mitmdump a capture runs."""

from __future__ import annotations

import sys
from pathlib import Path


def mitmdump() -> str:
    """The mitmdump beside the running interpreter. PATH can't be trusted to reach it: only
    `uv run` puts the venv first, so an installed copy would find a system mitmdump, whose
    Python can't import the addon's dependencies. No resolve(): the venv's python is a symlink
    that leads out of the venv."""
    return str(Path(sys.executable).parent / "mitmdump")
