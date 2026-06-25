"""Formatting/rendering helpers for the viewer: time, URLs, body pretty-printing,
hexdumps, the flow-table flags cell, and curl/raw export."""

from __future__ import annotations

import json
import os
import shlex
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


def flags_cell(f, selected: bool) -> Text:
    """Compact annotation indicators for the flow table: selection ✓, favorite ★,
    color mark ●, tag count #N, comment 💬, group ⬡, WebSocket ⇅N."""
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
    if f.websocket:
        t.append(f"⇅{f.ws_message_count} ", style="bold magenta")
    if f.proxy.addr:
        t.append("⇄ ", style="yellow")  # went through a proxy
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
