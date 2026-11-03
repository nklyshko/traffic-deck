"""Frida version choices + Android-compatibility recommendation (library).

Frida's Python client and the device frida-server must be the *same* version, and
frida 17 dropped support for older Android (e.g. Android 10 → spawn "unable to pick a
payload base"), while 16.7.x covers Android 10–15. We offer two fixed majors and
default to the one recommended for the device's Android release; the capture then runs
under the chosen frida (frida_env).
"""

from __future__ import annotations

V16 = "16.7.19"  # last v16 — for Android ≤ 11 (and works through 15)
V17 = "17.15.1"  # current v17 — for Android ≥ 12

#: Every version offered, newest first. `make install` builds a venv for each (ADR-0017 §5).
SUPPORTED = (V17, V16)


def recommended(android_release: str) -> str:
    """v16 for Android ≤ 11 (17 can't spawn on older Android), v17 otherwise."""
    try:
        major = int((android_release or "0").split(".")[0])
    except ValueError:
        major = 0
    return V16 if (major and major <= 11) else V17


def choices(recommend: str) -> list[str]:
    """Both supported versions, the recommended one first."""
    return [recommend] + [v for v in SUPPORTED if v != recommend]
