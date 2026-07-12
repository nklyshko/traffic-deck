"""Formatting/rendering helpers for the viewer: time, URLs, body pretty-printing,
hexdumps, the flow-table flags cell, and curl/raw export."""

from __future__ import annotations

import json
import os
import shlex
import sys
import time
import urllib.parse
from datetime import datetime, timezone

from textual.content import Content
from rich.console import Console
from rich.json import JSON
from rich.text import Text

SESSION_STATUS = {0: "?", 1: "open", 2: "decoding", 3: "closed", 4: "error"}

# Color-mark / tag palette — standard Rich color names so they render both as the
# row's ● marker and as tag/text styling.
MARK_COLORS = ["red", "yellow", "green", "blue", "magenta", "cyan"]

_UNSET = object()

# A plain Rich console resolves the JSON highlighter's named theme styles
# (json.brace, json.str, …) to concrete styles so the result can be wrapped as
# Textual Content without an active app/theme.
_RICH_CONSOLE = Console()


def fmt_time(ts_micros: int) -> str:
    if not ts_micros:
        return ""
    dt = datetime.fromtimestamp(ts_micros / 1e6, tz=timezone.utc)
    return dt.strftime("%H:%M:%S.%f")[:-3]


def url(f) -> str:
    u = f"{f.scheme or 'https'}://{f.authority}{f.path}"
    if f.query:
        u += f"?{f.query}"
    return u


def bytes_preview(data: bytes, limit: int = 64) -> str:
    """One-line preview: UTF-8 text if decodable, else hex."""
    if not data:
        return ""
    try:
        s = data.decode("utf-8")
        s = s.replace("\n", "⏎").replace("\r", "")
        return s[:limit] + ("…" if len(s) > limit else "")
    except UnicodeDecodeError:
        return data[:limit].hex() + ("…" if len(data) > limit else "")


def hexdump(data: bytes, width: int = 16) -> str:
    """Classic offset / hex / ascii dump."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  {asc}")
    return "\n".join(lines)


def _plain_truncated(text: str, limit: int, nbytes: int) -> Content:
    """Plain text body, truncated to `limit` chars with a size note (literal text)."""
    if len(text) <= limit:
        return Content(text)
    return Content(text[:limit]).append(
        Content.from_markup("\n[dim]… ($n bytes total — save to see all)[/dim]", n=str(nbytes)))


def format_body(content_type: str, data: bytes, limit: int) -> Content:
    """Pretty-print a decoded body for the detail view: JSON is reindented with
    light syntax color, form-urlencoded becomes key/value lines, everything else is
    shown as-is. Truncated to `limit` chars. All values are inserted literally and
    never reparsed as Textual markup (a stray '[' must not raise MarkupError)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Content(hexdump(data[:limit]))
    ct = (content_type or "").lower()
    stripped = text.lstrip()

    if "json" in ct or stripped[:1] in "{[":
        obj = _UNSET
        try:
            obj = json.loads(text)
        except ValueError:
            pass
        if obj is not _UNSET:
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
            if len(pretty) <= limit:
                # JSON.from_data returns a syntax-highlighted rich Text (styled
                # spans, not markup) — safe to wrap as Content.
                return Content.from_rich_text(JSON.from_data(obj, indent=2).text, _RICH_CONSOLE)
            return _plain_truncated(pretty, limit, len(data))

    if "x-www-form-urlencoded" in ct and "=" in text:
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
        if pairs:
            return Content("\n").join(
                Content.from_markup("[cyan]$k[/cyan] = $v", k=k, v=v) for k, v in pairs)

    return _plain_truncated(text, limit, len(data))


def is_text(data: bytes) -> bool:
    """Whether a body decodes as UTF-8 (so it can be shown/edited as text)."""
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# Map a content-type to a file suffix so an external editor can syntax-highlight a
# body opened outside the TUI. Order matters: more specific needles first.
_CT_SUFFIX = [
    ("json", ".json"),
    ("html", ".html"),
    ("xml", ".xml"),
    ("javascript", ".js"),
    ("css", ".css"),
    ("csv", ".csv"),
]


def editor_suffix(content_type: str, data: bytes) -> str:
    ct = (content_type or "").lower()
    for needle, suf in _CT_SUFFIX:
        if needle in ct:
            return suf
    if ct.startswith("text/") or "x-www-form-urlencoded" in ct:
        return ".txt"
    return ".txt" if is_text(data) else ".bin"


def body_for_editor(content_type: str, data: bytes) -> bytes:
    """Bytes to write to the temp file an editor opens. JSON is pretty-printed
    (minified JSON is unreadable, which is exactly the large-body case); anything
    else is written verbatim so the editor shows the true bytes."""
    ct = (content_type or "").lower()
    if "json" in ct or data.lstrip()[:1] in (b"{", b"["):
        try:
            obj = json.loads(data)
        except ValueError:
            return data
        return json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
    return data


def editor_command(path: str) -> tuple[list[str], bool]:
    """Resolve a command to open `path`. Returns (argv, is_terminal).

    A terminal editor ($VISUAL/$EDITOR) runs in the same terminal and needs the
    TUI suspended while it's open; the GUI fallback (xdg-open/open) launches a
    separate program and must NOT suspend the TUI."""
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if editor:
        return shlex.split(editor) + [path], True
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    return [opener, path], False


def status_cell(f) -> Text:
    """The flow list's status column: the HTTP status coloured by class (2xx green,
    3xx yellow, 4xx/5xx red), or a red error marker for a request that failed / never
    got a response — so non-2xx and failed flows stand out and are easy to spot.

    status 0 = no response: shown as a red 'err' when the capture recorded a failure
    reason (flow.error), otherwise blank (the request may still be pending)."""
    s = f.status
    if s == 0:
        if f.error:
            return Text("✗ err", style="bold red")
        return Text("")
    if s >= 500:
        style = "bold red"
    elif s >= 400:
        style = "red"
    elif s >= 300:
        style = "yellow"
    elif s >= 200:
        style = "green"
    else:
        style = "white"
    return Text(str(s), style=style)


_H2_SETTINGS = {
    "1": "HEADER_TABLE_SIZE", "2": "ENABLE_PUSH", "3": "MAX_CONCURRENT_STREAMS",
    "4": "INITIAL_WINDOW_SIZE", "5": "MAX_FRAME_SIZE", "6": "MAX_HEADER_LIST_SIZE",
}
_H2_PSEUDO = {"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}


def format_http2_fingerprint(fp: str) -> list[str]:
    """Break the Akamai HTTP/2 fingerprint (settings|window|priority|order) into readable
    lines, naming the SETTINGS ids and pseudo-header order."""
    parts = fp.split("|")
    if len(parts) != 4:
        return [fp]
    settings, window, priority, order = parts
    lines = []
    if settings:
        named = ", ".join(
            f"{_H2_SETTINGS.get(k, k)}={v}"
            for k, _, v in (s.partition(":") for s in settings.split(";")) if k
        )
        lines.append(f"SETTINGS: {named}")
    lines.append(f"WINDOW_UPDATE: {window}")
    lines.append(f"PRIORITY: {'none' if priority in ('', '0') else priority}")
    if order:
        lines.append("pseudo-header order: " + ", ".join(_H2_PSEUDO.get(c, c) for c in order.split(",")))
    return lines


def format_cookie_attrs(c) -> str:
    """Compact Set-Cookie attribute string (only the attributes present)."""
    parts = []
    if c.domain:
        parts.append(f"Domain={c.domain}")
    if c.path:
        parts.append(f"Path={c.path}")
    if c.expires:
        parts.append(f"Expires={c.expires}")
    if c.max_age:
        parts.append(f"Max-Age={c.max_age}")
    if c.secure:
        parts.append("Secure")
    if c.http_only:
        parts.append("HttpOnly")
    if c.same_site:
        parts.append(f"SameSite={c.same_site}")
    return "; ".join(parts)


def fmt_duration(seconds: float) -> str:
    """Compact human duration: 42ms, 1.3s, 2m05s."""
    if seconds < 0:
        seconds = 0
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m{s:02d}s"


def duration_cell(f, live: bool = True) -> Text:
    """The flow's duration column: the final request→response time once known, or a live
    stopwatch (⏱ elapsed since the request) while the request is still in flight in an open
    session — so a pending request is visibly ticking. The stopwatch is only shown while
    `live` (the session is open); once the session closes a still-pending flow goes blank
    rather than ticking forever. Blank too for a failed / response-less flow."""
    if f.duration_micros:
        return Text(fmt_duration(f.duration_micros / 1_000_000), style="dim")
    if live and f.status == 0 and not f.error and f.ts_unix_micros:
        elapsed = time.time() - f.ts_unix_micros / 1_000_000
        return Text("⏱ " + fmt_duration(elapsed), style="yellow")
    return Text("")


def flags_cell(f, selected: bool) -> Text:
    """Compact annotation indicators, shared by the flow table and the message timeline:
    selection ✓, favorite ★, color mark ●, tag count #N, comment 💬, group ⬡. The tail
    (WebSocket ⇅N, proxy ⇄, redirect ↪) is flow-only and guarded, so a WsMessage — which
    carries the same annotation fields but not those — renders cleanly too."""
    t = Text()
    if selected:
        t.append("✓ ", style="bold green")
    if f.favorite:
        t.append("★ ", style="yellow")
    if f.mark_color:
        t.append("● ", style=f.mark_color if f.mark_color in MARK_COLORS else "white")
    if f.tag_ids:
        t.append(f"#{len(f.tag_ids)} ", style="cyan")
    if f.comments:
        t.append("💬 ", style="dim")
    if f.group_ids:
        t.append("⬡ ", style="blue")
    if getattr(f, "websocket", False):
        t.append(f"⇅{f.ws_message_count} ", style="bold magenta")
    if getattr(getattr(f, "proxy", None), "addr", ""):
        t.append("⇄ ", style="yellow")  # went through a proxy
    if getattr(f, "redirect_location", "") or getattr(f, "redirected_from_id", ""):
        t.append("↪ ", style="blue")  # part of a redirect chain
    return t


def curl(flow, idprefix: str, body: bytes):
    """Build a curl command reproducing the request. Returns (command, bodyfile|None);
    a non-empty body is referenced as `--data-binary @<bodyfile>`."""
    parts = [f"curl -X {flow.method or 'GET'} {shlex.quote(url(flow))}"]
    if flow.protocol == "HTTP/2":
        parts.append("--http2")
    elif flow.protocol == "HTTP/1.1":
        parts.append("--http1.1")
    for h in flow.request_headers:
        if h.name.startswith(":") or h.name.lower() == "host":
            continue  # pseudo-headers / Host are implied by -X and the URL
        parts.append(f"-H {shlex.quote(f'{h.name}: {h.value}')}")
    bodyfile = None
    if body:
        bodyfile = os.path.abspath(f"{idprefix}-request.body")
        parts.append(f"--data-binary @{shlex.quote(bodyfile)}")
    return " \\\n  ".join(parts), bodyfile


def raw_message(flow, body: bytes, response: bool) -> bytes:
    """Reconstruct a raw HTTP message (start line + headers in wire order + body).
    For HTTP/2 the pseudo-headers are kept as-is, preserving order for fingerprinting."""
    if response:
        start = f"{flow.protocol or 'HTTP/1.1'} {flow.status}"
        headers = flow.response_headers
    else:
        target = flow.path + (f"?{flow.query}" if flow.query else "")
        start = f"{flow.method} {target} {flow.protocol or 'HTTP/1.1'}"
        headers = flow.request_headers
    lines = [start] + [f"{h.name}: {h.value}" for h in headers]
    return ("\n".join(lines) + "\n\n").encode() + (body or b"")
