"""Browser capture on Android through mitmproxy — no root, no Frida.

A Chromium browser is the one app the per-app path in capture.py cannot decrypt. Chrome's
BoringSSL is statically linked into libmonochrome with no exported symbols, so the Frida
keylog hook resolves *conscrypt's* libssl instead and silently produces an empty key.log;
Chrome's own `--ssl-key-log-file` is read on Android but aborts its NetworkService on fdsan.
So a browser is captured the other way round: terminate TLS in mitmproxy and point the
browser at it.

Chrome reads its flags from `/data/local/tmp/<name>-command-line` on a debuggable build (or
with `chrome://flags#enable-command-line-on-non-rooted-devices` turned on), and that file
an **unrooted** adb shell can write — /data/local/tmp belongs to the shell user. mitmproxy
binds loopback only and the device reaches it over `adb reverse`, so no port is exposed to
the network and the same flags work on an emulator and on a USB-attached phone.

The flows reach the gateway from mitmproxy's own addon (PushFlows), so this is a FLOWS
session like every other mitmproxy capture: no pcap, no key.log, and a terminating proxy
costs the real client fingerprint and the conn/stream columns. The Frida path keeps those —
for apps whose TLS it can actually see.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from capture_android.adb import AdbClient
from capture_sdk.shutdown import GracefulInterrupt

# The sibling mitmproxy module. We run mitmdump out of *its* project rather than depending
# on it, so mitmproxy stays out of this module's environment — which uv rebuilds per frida
# version, and which a proxy capture needs no frida in at all.
_MITM_PROJECT = Path(__file__).resolve().parents[2] / "capture_mitmproxy"
_MITM_ADDON = _MITM_PROJECT / "capture_mitmproxy" / "addon.py"

# Browsers offered as targets. Chrome ships *preinstalled*, i.e. as a system app, so it
# never shows up in `pm list packages -3` — the app picker's usual source — which is why
# this is a list rather than a filter over the installed apps.
BROWSER_PACKAGES = (
    "com.android.chrome",
    "com.chrome.beta",
    "com.chrome.dev",
    "com.chrome.canary",
    "org.chromium.chrome",
    "com.android.webview.shell",
)

# Chromium names its command-line file after the app. Every Chrome channel is the same code
# reading "chrome-command-line" (verified on com.android.chrome); the WebView shell reads
# its own. An unlisted package gets the Chrome default, the right guess for a Chromium build.
_COMMAND_LINE_FILES = {"com.android.webview.shell": "webview-command-line"}


def command_line_file(package: str) -> str:
    """Basename under /data/local/tmp that `package` reads its command line from."""
    return _COMMAND_LINE_FILES.get(package, "chrome-command-line")


def installed_browsers(adb: AdbClient) -> list[str]:
    """Which BROWSER_PACKAGES are on the device, in offer order."""
    present = set(adb.list_packages(third_party=False))
    return [p for p in BROWSER_PACKAGES if p in present]


def free_port() -> int:
    """A port for the proxy, picked by the OS and released at once — mitmdump binds it a
    moment later. Something else on the machine can take it in between; that loses the race
    loudly (mitmdump exits before opening a session) rather than quietly."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def chrome_flags(port: int) -> str:
    """The command line the browser is restarted with. The leading token stands in for
    argv[0], which Chromium ignores when reading this file.

    --ignore-certificate-errors is what saves installing mitmproxy's CA on the device (the
    system store needs root, the user store needs a trip through Settings). It turns off
    certificate checking for this browser run — the same bargain the mitmproxy source
    already makes, since terminating TLS has already taken away the client's own view of
    trust. It is why this capture restarts the browser on the way out, too.

    --disable-quic because a proxy only sees what goes through it: HTTP rides a CONNECT
    tunnel, and this keeps nothing from slipping out over UDP instead and leaving the
    capture quietly short.
    """
    return f"chrome --proxy-server=127.0.0.1:{port} --ignore-certificate-errors --disable-quic"


def run_proxy_capture(
    adb: AdbClient,
    package: str,
    *,
    gateway: str = "127.0.0.1:7331",
    label: str | None = None,
    url: str | None = None,
    duration: float | None = None,
    port: int | None = None,
    stop_event: threading.Event | None = None,
    on_session: Callable[[str], None] | None = None,
    log: Callable[[str], None] = print,
) -> str | None:
    """Capture `package`'s traffic through mitmproxy until `duration` elapses, `stop_event`
    is set, or Ctrl-C. Returns the gateway session id (opened by mitmproxy's addon)."""
    port = port or free_port()
    remote = f"/data/local/tmp/{command_line_file(package)}"
    label = label or f"{package} (proxy)"

    mitm = _start_mitmdump(port, gateway, label, _metadata(adb, package, url), log)
    sid: str | None = None
    reversed_port = False
    interrupt = GracefulInterrupt()
    with interrupt:
        try:
            sid = _read_session(mitm)
            log(f"session {sid}")
            if on_session is not None:
                on_session(sid)  # let a supervisor learn the id while the capture runs

            # The device dials the proxy on its *own* loopback and adbd forwards it to ours:
            # no host address to discover (10.0.2.2 vs a LAN IP), and nothing listening
            # off-box. Same flags on an emulator and a phone.
            adb.run("reverse", f"tcp:{port}", f"tcp:{port}")
            reversed_port = True

            adb.shell(f"echo {shlex.quote(chrome_flags(port))} > {remote} && chmod 644 {remote}")
            # Chromium reads the file once, at process start, so the browser has to be
            # restarted — one already running would keep its unproxied network stack.
            adb.shell(f"am force-stop {shlex.quote(package)}", check=False)
            time.sleep(1.0)
            _launch(adb, package, url)

            log(f"capturing {package} through mitmproxy on 127.0.0.1:{port}"
                + (f" (auto-stop in {duration:g}s)" if duration else " (Ctrl-C to stop)"))
            deadline = (time.monotonic() + duration) if duration else None
            while mitm.poll() is None:
                if deadline and time.monotonic() >= deadline:
                    break
                if interrupt.stopping or (stop_event is not None and stop_event.is_set()):
                    break
                time.sleep(0.3)
        except Exception as exc:  # noqa: BLE001 — surface it; the finally still cleans up
            log(f"capture error: {type(exc).__name__}: {exc}")
        finally:
            # Leave the device as we found it, and in this order: the flags file would
            # otherwise proxy — and stop verifying certificates for — every later browser
            # launch, long after this capture, and a browser left running would be pointing
            # at a proxy that is about to die.
            adb.shell(f"rm -f {remote}", check=False)
            adb.shell(f"am force-stop {shlex.quote(package)}", check=False)
            if reversed_port:
                adb.run("reverse", "--remove", f"tcp:{port}", check=False)
            _stop_mitmdump(mitm)
            log("stopped")
    return sid


def _launch(adb: AdbClient, package: str, url: str | None) -> None:
    """Start the browser — on `url` if given, else at whatever it opens with."""
    if url:
        adb.shell(f"am start -a android.intent.action.VIEW -d {shlex.quote(url)} "
                  f"{shlex.quote(package)}", check=False)
        return
    # No URL: `am start` needs a resolvable intent, and a browser's launcher activity name
    # is not ours to know — monkey resolves it from the package.
    adb.shell(f"monkey -p {shlex.quote(package)} -c android.intent.category.LAUNCHER 1",
              check=False)


def _metadata(adb: AdbClient, package: str, url: str | None) -> str:
    """The capture's own options, recorded on the session as the per-app path records
    android.package/uid — a bundle read back a week later otherwise says only "mitmproxy",
    with nothing about which app on which device. Strings for a person reading them."""
    md = {"android.package": package, "android.method": "proxy"}
    if adb.serial:
        md["android.serial"] = adb.serial
    if url:
        md["android.url"] = url
    return json.dumps(md)


def _start_mitmdump(port: int, gateway: str, label: str, metadata: str,
                    log: Callable[[str], None]) -> subprocess.Popen:
    cmd = ["uv", "run", "--project", str(_MITM_PROJECT), "mitmdump",
           "-s", str(_MITM_ADDON), "--mode", "regular",
           "--listen-host", "127.0.0.1", "--listen-port", str(port)]
    env = dict(os.environ, GATEWAY_ADDR=gateway, CAPTURE_LABEL=label,
               CAPTURE_METADATA=metadata, PYTHONUNBUFFERED="1")
    log(f"starting mitmproxy on 127.0.0.1:{port}")
    # Own session, so the escalation in _stop_mitmdump can group-kill without touching us.
    return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, start_new_session=True)


def _read_session(proc: subprocess.Popen) -> str:
    """Read mitmdump's output until its addon prints the session id, then keep draining so
    the pipe never fills. (The twin of capture_mitmproxy's own reader — duplicated rather
    than imported, to keep mitmproxy out of this module's dependencies.)"""
    # Watchdog: if the addon never prints SESSION (its startup hook failed, the gateway is
    # down) mitmdump keeps running and this read would block forever, holding the caller.
    # Kill it after a grace so the pipe closes and we raise below instead of hanging.
    watchdog = threading.Timer(30.0, lambda: proc.kill())
    watchdog.start()
    try:
        for line in proc.stdout:
            if line.startswith("SESSION "):
                watchdog.cancel()
                sid = line[len("SESSION "):].strip()
                threading.Thread(target=_drain, args=(proc,), daemon=True).start()
                return sid
    finally:
        watchdog.cancel()
    raise RuntimeError("mitmdump exited before opening a session (port taken? uv failed? gateway down?)")


def _drain(proc: subprocess.Popen) -> None:
    for line in proc.stdout:
        print(f"[mitm] {line.rstrip()}", flush=True)


def _stop_mitmdump(proc: subprocess.Popen) -> None:
    """Stop mitmdump and wait, so its addon's CloseSession has run by the time we return.

    The SIGINT goes to `proc` — the `uv run` wrapper — alone, never its group: uv forwards
    exactly one SIGINT to mitmdump, whereas signalling the group delivers one directly *and*
    one through uv, and mitmproxy treats the second as force-quit, which skips the addon's
    session close. (The same lesson as RealAndroidBackend._reap.) If the graceful window
    overruns we group-kill, so no orphan proxy is left holding the port.
    """
    if proc.poll() is not None:
        return
    try:
        os.kill(proc.pid, signal.SIGINT)
        proc.wait(timeout=15)
        return
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        pass
    for sig, grace in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(os.getpgid(proc.pid), sig)
            proc.wait(timeout=grace)
            return
        except ProcessLookupError:
            return
        except subprocess.TimeoutExpired:
            continue
