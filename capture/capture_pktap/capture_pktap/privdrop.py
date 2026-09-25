"""Holding root for the capture without letting it reach the browser or the user's files.

This source runs as root because PKTAP demands it, but almost nothing else here should be
root: a browser launched as root uses `/var/root`'s profile (and refuses to start at all on
Linux), and a profile directory or state file created as root inside the user's home
silently breaks the *unprivileged* Chrome source the next time it runs.

So root is spent on exactly one thing — the tcpdump that opens the pktap interface — and
everything else happens as the user who ran `sudo`: `invoking_user` finds them,
[as_user][capture_pktap.privdrop.as_user] wraps the filesystem work, and
`KeylogCapture.run_as` carries the ids down to the browser launch.
"""

from __future__ import annotations

import contextlib
import os
import pwd
import subprocess


def invoking_user() -> tuple[int, int] | None:
    """The (uid, gid) of whoever ran `sudo`, or None when we aren't privileged.

    None means "we are already an ordinary process" — the tool then behaves like any other
    capture source and needs no demotion anywhere. Root with no SUDO_UID (a login shell as
    root, a launchd job) is an error rather than a guess: there is no user to hand the
    browser to, and launching it as root would quietly use the wrong profile."""
    if os.geteuid() != 0:
        return None
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid):
        raise RuntimeError(
            "running as root with no SUDO_UID — start this source with `sudo` from your own "
            "shell so it knows which user to launch the browser as")
    return int(uid), int(gid)


def adopt_user_home(run_as: tuple[int, int] | None) -> None:
    """Point `~` at the invoking user's home instead of root's.

    Called once at startup. Every path this tool resolves — the browser's profiles under
    ~/Library, ~/.traffic-deck for saved profiles and the picker's remembered state — goes
    through `os.path.expanduser`, which reads $HOME. Under sudo that is root's home, so
    without this the source would discover none of the user's real Chrome profiles and
    would scribble its state into /var/root."""
    if run_as is None:
        return
    pw = pwd.getpwuid(run_as[0])
    os.environ["HOME"] = pw.pw_dir
    os.environ["USER"] = os.environ["LOGNAME"] = pw.pw_name


@contextlib.contextmanager
def as_user(run_as: tuple[int, int] | None):
    """Do filesystem work with the invoking user's credentials, so whatever it creates
    belongs to them and the browser can write it.

    Wraps profile resolution: a temp profile, a saved profile under ~/.traffic-deck, and
    the state file the pickers remember choices in are all created here, and a root-owned
    one is both unusable by the browser and a hazard for the unprivileged source later.

    Drops the group first and restores euid before egid — the standard order, so the
    window never has a uid that could refuse to take its privileges back."""
    if run_as is None:
        yield
        return
    uid, gid = run_as
    # ponytail: euid is process-wide, so two captures resolving profiles at once could
    # interleave. Fork a helper if this source ever starts captures concurrently.
    os.setegid(gid)
    os.seteuid(uid)
    try:
        yield
    finally:
        os.seteuid(0)
        os.setegid(0)


def user_tempdir(run_as: tuple[int, int] | None) -> str | None:
    """The invoking user's own temp directory — where the keylog has to live.

    Under `sudo`, `$TMPDIR` is *root's* per-user darwin temp dir
    (`/var/folders/zz/…/T`, mode 0700 root:wheel). Creating the key-log dir there and
    chowning it to the user is not enough: the browser runs as the user and cannot
    **traverse** the root-owned parent, so it silently fails to open its
    `--ssl-key-log-file` and logs no secrets at all. The capture then looks perfect — every
    packet recorded — and every single flow drops with "no TLS key-log secret".

    So ask the OS for the user's own temp dir, the same one an unprivileged capture would
    use, by querying it *as them*. Falls back to /tmp, which is 1777 and always traversable.

    Returns None when unprivileged, meaning "keep the default"."""
    if run_as is None:
        return None
    uid, gid = run_as
    try:
        out = subprocess.run(["getconf", "DARWIN_USER_TEMP_DIR"], user=uid, group=gid,
                             capture_output=True, text=True, timeout=10)
        path = out.stdout.strip()
        if path and os.path.isdir(path):
            return path
    except (OSError, subprocess.SubprocessError):
        pass
    return "/tmp"
