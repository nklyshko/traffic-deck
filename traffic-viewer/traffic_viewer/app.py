"""Traffic-viewer TUI (plan §7.3, Phase 1 MVP).

Session list -> flow table -> flow detail. Read-only, backfill from the gateway's
ViewerService. HTTP/1.1 + HTTP/2.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import urllib.parse
from datetime import datetime, timezone

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.content import Content
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, OptionList, Static
from textual.widgets.option_list import Option
from rich.console import Console
from rich.json import JSON
from rich.text import Text

from traffic_viewer.client import GatewayClient

SESSION_STATUS = {0: "?", 1: "open", 2: "decoding", 3: "closed", 4: "error"}

# Color-mark / tag palette (plan §12) — standard Rich color names so they render
# both as the row's ● marker and as tag/text styling.
MARK_COLORS = ["red", "yellow", "green", "blue", "magenta", "cyan"]


def _fmt_time(ts_micros: int) -> str:
    if not ts_micros:
        return ""
    dt = datetime.fromtimestamp(ts_micros / 1e6, tz=timezone.utc)
    return dt.strftime("%H:%M:%S.%f")[:-3]


def _url(f) -> str:
    u = f"{f.scheme or 'https'}://{f.authority}{f.path}"
    if f.query:
        u += f"?{f.query}"
    return u


# mitmproxy-style filter fields (subset) over the flow summary (plan §9 Phase 3).
_FILTER_FIELDS = {
    "~m": lambda f: f.method,
    "~d": lambda f: f.authority,
    "~u": _url,
    "~c": lambda f: str(f.status) if f.status else "",
    "~t": lambda f: f.content_type,
}


def _comment_text(f) -> str:
    return " ".join(c.body for c in f.comments)


def _bytes_preview(data: bytes, limit: int = 64) -> str:
    """One-line preview: UTF-8 text if decodable, else hex."""
    if not data:
        return ""
    try:
        s = data.decode("utf-8")
        s = s.replace("\n", "⏎").replace("\r", "")
        return s[:limit] + ("…" if len(s) > limit else "")
    except UnicodeDecodeError:
        return data[:limit].hex() + ("…" if len(data) > limit else "")


def _hexdump(data: bytes, width: int = 16) -> str:
    """Classic offset / hex / ascii dump."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  {asc}")
    return "\n".join(lines)


_UNSET = object()

# A plain Rich console resolves the JSON highlighter's named theme styles
# (json.brace, json.str, …) to concrete styles so the result can be wrapped as
# Textual Content without an active app/theme.
_RICH_CONSOLE = Console()


def _plain_truncated(text: str, limit: int, nbytes: int) -> Content:
    """Plain text body, truncated to `limit` chars with a size note (literal text)."""
    if len(text) <= limit:
        return Content(text)
    return Content(text[:limit]).append(
        Content.from_markup("\n[dim]… ($n bytes total — save to see all)[/dim]", n=str(nbytes)))


def _format_body(content_type: str, data: bytes, limit: int) -> Content:
    """Pretty-print a decoded body for the detail view: JSON is reindented with
    light syntax color, form-urlencoded becomes key/value lines, everything else is
    shown as-is. Truncated to `limit` chars. All values are inserted literally and
    never reparsed as Textual markup (a stray '[' must not raise MarkupError)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Content(_hexdump(data[:limit]))
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


def compile_filter(expr: str, tagnames: dict | None = None, groupnames: dict | None = None):
    """Compile a filter expression to a predicate(flow)->bool, or None if empty.

    Terms (space-separated, ANDed): `~m/~d/~u/~c/~t <regex>`, `~s`/`~q`
    (has/no response), `~fav` (favorited), annotation fields `~mark/~tag/~group/
    ~comment <regex>` (plan §12), a naked regex (matches the URL), and a leading `!`
    negates a term. Raises ValueError on a bad regex. (Full `& | ()` grammar is future.)
    """
    tagnames = tagnames or {}
    groupnames = groupnames or {}
    fields = {
        **_FILTER_FIELDS,
        "~mark": lambda f: f.mark_color,
        "~tag": lambda f: " ".join(tagnames.get(t, t) for t in f.tag_ids),
        "~group": lambda f: " ".join(groupnames.get(g, g) for g in f.group_ids),
        "~comment": _comment_text,
    }

    def _rx(s: str):
        try:
            return re.compile(s, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"bad regex {s!r}: {e}")

    expr = expr.strip()
    if not expr:
        return None
    toks = expr.split()
    preds = []
    i = 0
    while i < len(toks):
        t, neg = toks[i], False
        if t == "!":
            neg, i = True, i + 1
            if i >= len(toks):
                break
            t = toks[i]
        elif t.startswith("!") and len(t) > 1:
            neg, t = True, t[1:]

        if t in ("~s", "~q"):
            base = (lambda f: bool(f.status)) if t == "~s" else (lambda f: not f.status)
            i += 1
        elif t == "~fav":
            base = lambda f: f.favorite
            i += 1
        elif t in fields:
            i += 1
            if i >= len(toks):
                raise ValueError(f"{t} needs an argument")
            rx, getter, i = _rx(toks[i]), fields[t], i + 1
            base = lambda f, rx=rx, g=getter: bool(rx.search(g(f) or ""))
        else:
            rx = _rx(t)
            base = lambda f, rx=rx: bool(rx.search(_url(f)))
            i += 1
        preds.append(lambda f, b=base, n=neg: (not b(f)) if n else b(f))
    return lambda f: all(p(f) for p in preds)


def _flags_cell(f, selected: bool) -> Text:
    """Compact annotation indicators for the flow table (plan §12): selection ✓,
    favorite ★, color mark ●, tag count #N, comment 💬."""
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
    return t


def _curl(flow, idprefix: str, body: bytes):
    """Build a curl command reproducing the request. Returns (command, bodyfile|None);
    a non-empty body is referenced as `--data-binary @<bodyfile>`."""
    parts = [f"curl -X {flow.method or 'GET'} {shlex.quote(_url(flow))}"]
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


def _raw_message(flow, body: bytes, response: bool) -> bytes:
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


class TextPrompt(ModalScreen[str | None]):
    """Modal single-line text input; dismisses with the entered text, or None on Esc."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, label: str, value: str = "") -> None:
        super().__init__()
        self._label = label
        self._value = value

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt"):
            yield Label(self._label)
            yield Input(value=self._value, id="prompt-input")

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class SelectPrompt(ModalScreen[str | None]):
    """Modal pick-one list; dismisses with the chosen option id, or None on Esc."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, label: str, options: list[tuple[str, object]]) -> None:
        super().__init__()
        self._label = label
        self._options = options  # (id, renderable-label)

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt"):
            yield Label(self._label)
            yield OptionList(*[Option(lbl, id=val) for val, lbl in self._options])

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class SessionsScreen(Screen):
    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("e", "export", "Export"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        table = DataTable(id="sessions", cursor_type="row", zebra_stripes=True)
        table.add_columns("Session", "Label", "Status", "Flows", "pcap", "Created")
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self.sub_title = "sessions"
        self.load_sessions()

    def action_refresh(self) -> None:
        self.load_sessions()

    @work(exclusive=True)
    async def load_sessions(self) -> None:
        table = self.query_one("#sessions", DataTable)
        table.clear()
        try:
            sessions = await self.app.client.list_sessions()
        except Exception as exc:  # noqa: BLE001
            self.notify(f"list_sessions failed: {exc}", severity="error")
            return
        for s in sessions:
            created = datetime.fromtimestamp(s.created_at_unix_ms / 1e3).strftime("%Y-%m-%d %H:%M")
            table.add_row(
                s.id[:8],
                s.label or "—",
                SESSION_STATUS.get(s.status, "?"),
                str(s.flow_count),
                f"{s.pcap_bytes/1_048_576:.1f}M",
                created,
                key=s.id,
            )
        if not sessions:
            self.notify("no sessions — import one with `gateway import`")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.app.push_screen(FlowsScreen(str(event.row_key.value)))

    def _focused_session_id(self) -> str | None:
        table = self.query_one("#sessions", DataTable)
        if table.cursor_coordinate is None or table.row_count == 0:
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    @work(exclusive=True)
    async def action_export(self) -> None:
        """Export the focused session as a .tar.gz bundle in the current directory."""
        sid = self._focused_session_id()
        if sid is None:
            return
        dest = os.path.abspath(f"{sid}.tar.gz")
        self.notify(f"exporting {sid[:8]} …")
        try:
            n = await self.app.client.export_session(sid, dest)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"export failed: {exc}", severity="error")
            return
        self.notify(f"exported {n/1_048_576:.1f}M → {dest}")


class FlowsScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("f", "filter", "Filter"),
        Binding("c", "compare", "Compare A/B"),
        Binding("space", "select", "Select"),
        Binding("m", "mark", "Mark"),
        Binding("t", "tag", "Tag"),
        Binding("F", "favorite", "Favorite"),
        Binding("n", "comment", "Comment"),
        Binding("g", "group", "Group"),
        Binding("M", "messages", "WS msgs"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str) -> None:
        super().__init__()
        self.session_id = session_id
        self.flows: dict[str, object] = {}  # flow id -> cached Flow (for live detail)
        self._rows: set[str] = set()
        self._cols: list = []
        self._predicate = None  # active filter
        self._selected: set[str] = set()       # multi-selection for bulk annotation
        self._tags: list = []                  # tag defs (catalog)
        self._groups: list = []                # group defs (catalog)
        self._tagnames: dict[str, str] = {}
        self._groupnames: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(id="filter", placeholder="filter: ~m GET  ~d example.com  ~fav  ~tag auth  ~mark red  (f focus, Enter apply)")
        table = DataTable(id="flows", cursor_type="row", zebra_stripes=True)
        self._cols = table.add_columns("", "Time", "Method", "Status", "Proto", "Authority", "Path")
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self._update_subtitle()
        self.query_one("#flows", DataTable).focus()
        self.load_defs()
        self.load_flows()

    @work(exclusive=True, group="defs")
    async def load_defs(self) -> None:
        """Load tag/group definitions for the palette + filter name resolution."""
        try:
            self._tags = await self.app.client.list_tags()
            self._groups = await self.app.client.list_groups()
        except Exception as exc:  # noqa: BLE001
            self.notify(f"load annotations failed: {exc}", severity="warning")
            return
        self._tagnames = {t.id: t.name for t in self._tags}
        self._groupnames = {g.id: g.name for g in self._groups}

    def _update_subtitle(self) -> None:
        base = f"flows · {self.session_id[:8]}"
        if self._selected:
            base += f" · {len(self._selected)} selected"
        if self._predicate is not None:
            base += f" · {len(self._rows)}/{len(self.flows)} shown"
        self.sub_title = base

    def _matches(self, f) -> bool:
        return self._predicate is None or self._predicate(f)

    def action_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        try:
            self._predicate = compile_filter(event.value, self._tagnames, self._groupnames)
        except Exception as exc:  # noqa: BLE001 (bad regex / syntax)
            self.notify(f"bad filter: {exc}", severity="error")
            return
        self._apply_filter()
        self.query_one("#flows", DataTable).focus()

    def _apply_filter(self) -> None:
        table = self.query_one("#flows", DataTable)
        table.clear()
        self._rows.clear()
        for f in self.flows.values():
            if self._matches(f):
                table.add_row(*self._cells(f), key=f.id)
                self._rows.add(f.id)
        self._update_subtitle()

    def on_key(self, event) -> None:
        # Escape while editing the filter returns to the table without going back.
        if event.key == "escape" and self.query_one("#filter", Input).has_focus:
            self.query_one("#flows", DataTable).focus()
            event.stop()

    def _cells(self, f) -> tuple:
        return (
            _flags_cell(f, f.id in self._selected),
            _fmt_time(f.ts_unix_micros),
            f.method or "",
            str(f.status) if f.status else "",
            f.protocol or "",
            f.authority or "",
            (f.path or "")[:80],
        )

    def _upsert(self, f) -> None:
        table = self.query_one("#flows", DataTable)
        self.flows[f.id] = f
        if not self._matches(f):
            if f.id in self._rows:
                table.remove_row(f.id)
                self._rows.discard(f.id)
                self._update_subtitle()
            return
        cells = self._cells(f)
        if f.id in self._rows:
            for col, val in zip(self._cols, cells):
                table.update_cell(f.id, col, val)
        else:
            table.add_row(*cells, key=f.id)
            self._rows.add(f.id)
            self._update_subtitle()

    @work(exclusive=True)
    async def load_flows(self) -> None:
        self.query_one("#flows", DataTable).clear()
        self.flows.clear()
        self._rows.clear()
        try:
            async for ev in self.app.client.stream_flows(self.session_id, follow=True):
                kind = ev.WhichOneof("event")
                if kind == "flow_added":
                    self._upsert(ev.flow_added)
                elif kind == "flow_updated":
                    self._upsert(ev.flow_updated)
                elif kind == "session_event":
                    self.notify("session closed — live capture ended")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"stream_flows failed: {exc}", severity="error")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        fid = str(event.row_key.value)
        self.app.push_screen(
            FlowDetailScreen(self.session_id, fid, self.flows.get(fid),
                             self._tagnames, self._groupnames))

    def _focused_flow_id(self) -> str | None:
        table = self.query_one("#flows", DataTable)
        if table.cursor_coordinate is None or table.row_count == 0:
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    def action_compare(self) -> None:
        fid = self._focused_flow_id()
        if fid is None:
            return
        sel = (self.session_id, fid)
        if self.app.compare_a is None:
            self.app.compare_a = sel
            self.notify("marked A — focus a flow in another session and press c")
        elif self.app.compare_a == sel:
            self.app.compare_a = None
            self.notify("cleared compare selection")
        else:
            a = self.app.compare_a
            self.app.compare_a = None
            self.app.push_screen(CompareScreen(a, sel))

    def action_messages(self) -> None:
        fid = self._focused_flow_id()
        if fid is None:
            return
        f = self.flows.get(fid)
        if not (f and f.websocket):
            self.notify("not a WebSocket flow", severity="warning")
            return
        self.app.push_screen(WsMessagesScreen(self.session_id, fid))

    # --- annotations (plan §12) ----------------------------------------------

    def action_select(self) -> None:
        """Toggle the focused row's membership in the bulk-annotation selection."""
        fid = self._focused_flow_id()
        if fid is None:
            return
        if fid in self._selected:
            self._selected.discard(fid)
        else:
            self._selected.add(fid)
        f = self.flows.get(fid)
        if f is not None:
            self._upsert(f)  # re-render the flags cell
        self._update_subtitle()

    def _targets(self) -> list[str]:
        """Records an annotation applies to: the selection if any, else the focus."""
        if self._selected:
            return list(self._selected)
        fid = self._focused_flow_id()
        return [fid] if fid else []

    async def _refresh(self, ids: list[str]) -> None:
        """Re-fetch annotated flows so their row/cache reflect the change."""
        for rid in ids:
            try:
                f = await self.app.client.get_flow(self.session_id, rid)
            except Exception:  # noqa: BLE001 (live/unpersisted record — best effort)
                continue
            self._upsert(f)

    @work(exclusive=True, group="annotate")
    async def action_mark(self) -> None:
        targets = self._targets()
        if not targets:
            return
        opts = [(c, Text("● " + c, style=c)) for c in MARK_COLORS] + [("__clear__", "✕ clear")]
        choice = await self.app.push_screen_wait(SelectPrompt("Color mark", opts))
        if choice is None:
            return
        try:
            if choice == "__clear__":
                await self.app.client.clear_mark(self.session_id, targets)
            else:
                await self.app.client.set_mark(self.session_id, targets, choice)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"mark failed: {exc}", severity="error")
            return
        await self._refresh(targets)

    @work(exclusive=True, group="annotate")
    async def action_tag(self) -> None:
        targets = self._targets()
        if not targets:
            return
        opts = [(t.id, Text(("★ " if t.is_favorite else "") + t.name, style=t.color or "white"))
                for t in self._tags]
        opts.append(("__new__", "＋ new tag…"))
        choice = await self.app.push_screen_wait(SelectPrompt("Toggle tag", opts))
        if choice is None:
            return
        if choice == "__new__":
            name = await self.app.push_screen_wait(TextPrompt("New tag name"))
            if not name:
                return
            color = await self.app.push_screen_wait(
                SelectPrompt("Tag color", [(c, Text("● " + c, style=c)) for c in MARK_COLORS]))
            try:
                tag = await self.app.client.create_tag(name, color or "")
                await self.app.client.set_tags(self.session_id, targets, add=[tag.id])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"tag failed: {exc}", severity="error")
                return
            self.load_defs()
        else:
            present = all(choice in (self.flows[r].tag_ids if r in self.flows else []) for r in targets)
            try:
                if present:
                    await self.app.client.set_tags(self.session_id, targets, remove=[choice])
                else:
                    await self.app.client.set_tags(self.session_id, targets, add=[choice])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"tag failed: {exc}", severity="error")
                return
        await self._refresh(targets)

    @work(exclusive=True, group="annotate")
    async def action_favorite(self) -> None:
        targets = self._targets()
        if not targets:
            return
        try:
            await self.app.client.toggle_favorite(self.session_id, targets)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"favorite failed: {exc}", severity="error")
            return
        await self._refresh(targets)

    @work(exclusive=True, group="annotate")
    async def action_comment(self) -> None:
        fid = self._focused_flow_id()  # comments target a single record
        if fid is None:
            return
        f = self.flows.get(fid)
        existing = f.comments[0] if (f and f.comments) else None
        body = await self.app.push_screen_wait(
            TextPrompt("Comment (empty to delete)", existing.body if existing else ""))
        if body is None:
            return
        try:
            if existing and body == "":
                await self.app.client.delete_comment(self.session_id, existing.id)
            elif existing:
                await self.app.client.edit_comment(self.session_id, existing.id, body)
            elif body:
                await self.app.client.add_comment(self.session_id, fid, body)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"comment failed: {exc}", severity="error")
            return
        await self._refresh([fid])

    @work(exclusive=True, group="annotate")
    async def action_group(self) -> None:
        targets = self._targets()
        if not targets:
            return
        opts = [(g.id, Text(g.name, style=g.color or "white")) for g in self._groups]
        opts.append(("__new__", "＋ new group…"))
        choice = await self.app.push_screen_wait(SelectPrompt("Toggle group", opts))
        if choice is None:
            return
        if choice == "__new__":
            name = await self.app.push_screen_wait(TextPrompt("New group name"))
            if not name:
                return
            color = await self.app.push_screen_wait(
                SelectPrompt("Group color", [(c, Text("● " + c, style=c)) for c in MARK_COLORS]))
            try:
                grp = await self.app.client.create_group(name, color or "")
                await self.app.client.set_groups(self.session_id, targets, add=[grp.id])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"group failed: {exc}", severity="error")
                return
            self.load_defs()
        else:
            present = all(choice in (self.flows[r].group_ids if r in self.flows else []) for r in targets)
            try:
                if present:
                    await self.app.client.set_groups(self.session_id, targets, remove=[choice])
                else:
                    await self.app.client.set_groups(self.session_id, targets, add=[choice])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"group failed: {exc}", severity="error")
                return
        await self._refresh(targets)


class FlowDetailScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "save_request", "Save req body"),
        Binding("s", "save_response", "Save resp body"),
        Binding("x", "export_curl", "Export curl"),
        Binding("w", "export_raw", "Export raw"),
        Binding("M", "messages", "WS msgs"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, flow_id: str, cached=None,
                 tagnames: dict | None = None, groupnames: dict | None = None) -> None:
        super().__init__()
        self.session_id = session_id
        self.flow_id = flow_id
        self.cached = cached  # full Flow from a live event, used if not yet persisted
        self._flow = None     # the loaded Flow (for export)
        self._tagnames = tagnames or {}
        self._groupnames = groupnames or {}

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="detail"):
            yield Static("loading…", id="body")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self.sub_title = "flow detail"
        self.load_flow()

    @work(exclusive=True)
    async def load_flow(self) -> None:
        # Persisted flows come from GetFlow (full headers+bodies); live flows aren't
        # persisted yet, so fall back to the cached flow from the live stream.
        f = None
        try:
            f = await self.app.client.get_flow(self.session_id, self.flow_id)
        except Exception:  # noqa: BLE001
            f = self.cached
        if f is None:
            self.query_one("#body", Static).update("[red]flow unavailable[/red]")
            return
        self._flow = f
        self.query_one("#body", Static).update(self._format_flow(f))

    def action_messages(self) -> None:
        if not (self._flow and self._flow.websocket):
            self.notify("not a WebSocket flow", severity="warning")
            return
        self.app.push_screen(WsMessagesScreen(self.session_id, self.flow_id))

    async def _full_body(self, response: bool) -> bytes:
        try:
            return await self.app.client.get_body(self.session_id, self.flow_id, response)
        except Exception:  # noqa: BLE001 (no body)
            return b""

    @work(exclusive=True)
    async def action_export_curl(self) -> None:
        if self._flow is None:
            return
        body = await self._full_body(response=False)
        cmd, bodyfile = _curl(self._flow, self.flow_id[:8], body)
        if bodyfile:
            with open(bodyfile, "wb") as fp:
                fp.write(body)
        path = os.path.abspath(f"{self.flow_id[:8]}.curl")
        with open(path, "w") as fp:
            fp.write(cmd + "\n")
        self.notify(f"wrote {path}" + (f" (+ {bodyfile})" if bodyfile else ""))

    @work(exclusive=True)
    async def action_export_raw(self) -> None:
        if self._flow is None:
            return
        req = _raw_message(self._flow, await self._full_body(response=False), response=False)
        resp = _raw_message(self._flow, await self._full_body(response=True), response=True)
        rp = os.path.abspath(f"{self.flow_id[:8]}-request.http")
        sp = os.path.abspath(f"{self.flow_id[:8]}-response.http")
        with open(rp, "wb") as fp:
            fp.write(req)
        with open(sp, "wb") as fp:
            fp.write(resp)
        self.notify(f"wrote {rp} and {sp}")

    @work(exclusive=True)
    async def action_save_request(self) -> None:
        await self._save_body(response=False, label="request")

    @work(exclusive=True)
    async def action_save_response(self) -> None:
        await self._save_body(response=True, label="response")

    async def _save_body(self, response: bool, label: str) -> None:
        try:
            data = await self.app.client.get_body(self.session_id, self.flow_id, response)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"no {label} body to save ({exc})", severity="warning")
            return
        path = os.path.abspath(f"{self.flow_id[:8]}-{label}.bin")
        with open(path, "wb") as fp:
            fp.write(data)
        self.notify(f"saved {len(data)} bytes → {path}")

    # Cap body rendering so a large body doesn't choke the TUI.
    _BODY_RENDER_LIMIT = 20000

    def _format_flow(self, f) -> Content:
        # Build a Textual Content with $-substitution for all flow-derived text:
        # values are inserted literally, never reparsed as markup (a stray '[' / byte
        # sequence in a header or body must not raise MarkupError — see _render_payload).
        cls = type(self)
        lines: list[Content] = []
        url = f"{f.scheme or 'https'}://{f.authority}{f.path}"
        if f.query:
            url += f"?{f.query}"
        lines.append(Content.from_markup("[b]$v[/b]", v=f.method + " " + url))
        lines.append(Content.from_markup(
            "[dim]$proto  status=$status  tls=$tls  $src → $dst[/dim]",
            proto=f.protocol, status=str(f.status),
            tls="yes" if f.tls_decrypted else "no", src=f.src_addr, dst=f.dst_addr))
        self._append_annotations(lines, f)
        lines.append(Content(""))
        lines.append(Content.from_markup("[b u]Request headers[/b u]"))
        for h in f.request_headers:
            lines.append(Content.from_markup("  [cyan]$n[/cyan]: $val", n=h.name, val=h.value))
        cls._append_body(lines, "Request body", f.request_body, "r")
        lines.append(Content(""))
        lines.append(Content.from_markup("[b u]Response headers[/b u]"))
        for h in f.response_headers:
            lines.append(Content.from_markup("  [green]$n[/green]: $val", n=h.name, val=h.value))
        cls._append_body(lines, "Response body", f.response_body, "s")
        return Content("\n").join(lines)

    def _append_annotations(self, lines: list[Content], f) -> None:
        """Render the record's annotations (plan §12): mark, favorite, tags, groups,
        comments. Names resolve via the maps passed from the flow list."""
        bits: list[Content] = []
        if f.favorite:
            bits.append(Content.from_markup("[yellow]★ favorite[/yellow]"))
        if f.mark_color:
            color = f.mark_color if f.mark_color in MARK_COLORS else "white"
            bits.append(Content.from_markup(f"[{color}]● $c[/{color}]", c=f.mark_color))
        if f.tag_ids:
            names = ", ".join(self._tagnames.get(t, t) for t in f.tag_ids)
            bits.append(Content.from_markup("[cyan]tags:[/cyan] $names", names=names))
        if f.group_ids:
            names = ", ".join(self._groupnames.get(g, g) for g in f.group_ids)
            bits.append(Content.from_markup("[blue]groups:[/blue] $names", names=names))
        if bits:
            lines.append(Content.from_markup("[dim]│[/dim] ").append(Content("   ").join(bits)))
        for c in f.comments:
            lines.append(Content.from_markup("  [dim]💬[/dim] $body", body=c.body))

    @classmethod
    def _append_body(cls, lines: list[Content], title: str, body, save_key: str) -> None:
        if body is None or body.size == 0:
            return
        meta = f"{body.content_type or '?'} · {body.size} bytes"
        lines.append(Content(""))
        lines.append(Content.from_markup(
            "[b u]$title[/b u] [dim]$meta · press $key to save[/dim]",
            title=title, meta=meta, key=save_key))
        if body.WhichOneof("content") != "inline":
            lines.append(Content.from_markup(
                "  [dim]large body — press $key to save the full $size bytes[/dim]",
                key=save_key, size=str(body.size)))
            return
        data = body.inline
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            lines.append(Content.from_markup(
                "  [dim]$txt[/dim]", txt=f"[binary {len(data)} bytes — press {save_key} to save]"))
            return
        lines.append(_format_body(body.content_type, data, cls._BODY_RENDER_LIMIT))


class WsMessagesScreen(Screen):
    """WebSocket message timeline for an Upgrade flow (plan §8.6) — directional
    frames in time order, distinct from the request/response view."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, flow_id: str) -> None:
        super().__init__()
        self.session_id = session_id
        self.flow_id = flow_id
        self._msgs: dict[str, object] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        table = DataTable(id="msgs", cursor_type="row", zebra_stripes=True)
        table.add_columns("Time", "Dir", "Opcode", "Len", "Preview")
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self.sub_title = f"websocket · {self.flow_id[:8]}"
        self.query_one("#msgs", DataTable).focus()
        self.load()

    def _add_message(self, m) -> None:
        if m.id in self._msgs:
            return
        self._msgs[m.id] = m
        arrow = "[cyan]C→S[/cyan]" if m.from_client else "[magenta]S→C[/magenta]"
        size = m.payload.size if m.payload else 0
        inline = m.payload.inline if (m.payload and m.payload.WhichOneof("content") == "inline") else b""
        preview = _bytes_preview(inline) if inline else (f"[dim]{size} bytes[/dim]" if size else "")
        self.query_one("#msgs", DataTable).add_row(
            _fmt_time(m.ts_unix_micros), arrow, m.opcode, str(size),
            Text.from_markup(preview), key=m.id)

    @work(exclusive=True)
    async def load(self) -> None:
        # Stream frames: backfill of stored frames, then (for a live session) new
        # frames as they're decoded — so a live WebSocket timeline updates in place.
        try:
            async for ev in self.app.client.stream_messages(self.session_id, self.flow_id, follow=True):
                kind = ev.WhichOneof("event")
                if kind == "message_added":
                    self._add_message(ev.message_added)
                elif kind == "session_event":
                    self.notify("session closed — live capture ended")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"stream_messages failed: {exc}", severity="error")
            return
        if not self._msgs:
            self.notify("no websocket frames recorded for this flow")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        mid = str(event.row_key.value)
        self.app.push_screen(WsPayloadScreen(self.session_id, self._msgs[mid]))


class WsPayloadScreen(Screen):
    """Full payload of a single WebSocket frame (UTF-8 text or a hex dump)."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("s", "save", "Save"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, msg) -> None:
        super().__init__()
        self.session_id = session_id
        self.msg = msg
        self._data = b""

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="payload"):
            yield Static("loading…", id="pbody")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self.sub_title = f"{self.msg.opcode} · {'C→S' if self.msg.from_client else 'S→C'}"
        self.load()

    @work(exclusive=True)
    async def load(self) -> None:
        try:
            self._data = await self.app.client.get_message_body(self.session_id, self.msg.id)
        except Exception:  # noqa: BLE001 (empty payload — e.g. a bare close/ping frame)
            self._data = self.msg.payload.inline if self.msg.payload else b""
        self.query_one("#pbody", Static).update(self._render_payload())

    def _render_payload(self) -> Text:
        # Build a Rich Text (not a markup string): payload bytes are arbitrary and
        # must never be parsed as Textual markup (a stray '[' or '<' raises MarkupError).
        if not self._data:
            return Text("empty payload", style="dim")
        try:
            return Text(self._data.decode("utf-8"))
        except UnicodeDecodeError:
            out = Text(f"binary {len(self._data)} bytes — press s to save", style="dim")
            out.append("\n\n")
            out.append(_hexdump(self._data))
            return out

    @work(exclusive=True)
    async def action_save(self) -> None:
        path = os.path.abspath(f"{self.msg.id[:8]}.ws.bin")
        with open(path, "wb") as fp:
            fp.write(self._data)
        self.notify(f"saved {len(self._data)} bytes → {path}")


class CompareScreen(Screen):
    """Side-by-side diff of two requests from different sessions (plan §7.5).

    Compares (order-sensitively): HTTP version, pseudo-header order, header order +
    values, cookie order, and request body — the client/parser fingerprint surface.
    """

    BINDINGS = [Binding("escape", "app.pop_screen", "Back"), Binding("q", "quit", "Quit")]

    def __init__(self, a: tuple[str, str], b: tuple[str, str]) -> None:
        super().__init__()
        self.a, self.b = a, b

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="cmp"):
            yield Static("loading…", id="diff")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self.sub_title = "compare A ⟷ B"
        self.load()

    @work(exclusive=True)
    async def load(self) -> None:
        try:
            fa = await self.app.client.get_flow(*self.a)
            fb = await self.app.client.get_flow(*self.b)
        except Exception as exc:  # noqa: BLE001
            self.query_one("#diff", Static).update(
                f"[red]could not load both flows: {exc}[/red]\n[dim](live/unpersisted "
                f"sessions can't be compared yet — close them first)[/dim]")
            return
        self.query_one("#diff", Static).update(self._render_diff(fa, fb))

    # --- diff helpers ---------------------------------------------------------

    @staticmethod
    def _pseudo(f) -> list[str]:
        return [h.name for h in f.request_headers if h.name.startswith(":")]

    @staticmethod
    def _regular(f) -> list:  # list of (name, value)
        return [(h.name, h.value) for h in f.request_headers if not h.name.startswith(":")]

    @staticmethod
    def _cookies(f) -> list:  # ordered (name, value) from the Cookie header
        for h in f.request_headers:
            if h.name.lower() == "cookie":
                out = []
                for part in h.value.split(";"):
                    part = part.strip()
                    if not part:
                        continue
                    k, _, v = part.partition("=")
                    out.append((k.strip(), v))
                return out
        return []

    @staticmethod
    def _mark(equal: bool) -> Content:
        return Content.from_markup(
            "[green]✓ match[/green]" if equal else "[red]✗ differ[/red]")

    def _render_diff(self, a, b) -> Content:
        # Content with $-substitution: header/cookie/body-derived text is inserted
        # literally, never reparsed as markup (see _format_flow / _render_payload).
        out: list[Content] = []
        out.append(Content.from_markup(
            "[b]A[/b] [dim]$m $auth$path[/dim]", m=a.method, auth=a.authority, path=a.path))
        out.append(Content.from_markup(
            "[b]B[/b] [dim]$m $auth$path[/dim]", m=b.method, auth=b.authority, path=b.path))

        def section(title, va, vb, equal):
            out.append(Content(""))
            out.append(Content.from_markup("[b u]$t[/b u]  ", t=title).append(self._mark(equal)))
            if not equal:
                out.append(Content.from_markup("  [cyan]A[/cyan] $v", v=va))
                out.append(Content.from_markup("  [magenta]B[/magenta] $v", v=vb))

        # HTTP version
        section("HTTP version", a.protocol, b.protocol, a.protocol == b.protocol)
        # Pseudo-header order
        pa, pb = self._pseudo(a), self._pseudo(b)
        section("Pseudo-header order", " ".join(pa), " ".join(pb), pa == pb)
        # Header order (names only)
        na = [n for n, _ in self._regular(a)]
        nb = [n for n, _ in self._regular(b)]
        section("Header order", ", ".join(na), ", ".join(nb), na == nb)
        # Cookie order (names)
        ca, cb = self._cookies(a), self._cookies(b)
        section("Cookie order", ", ".join(n for n, _ in ca), ", ".join(n for n, _ in cb),
                [n for n, _ in ca] == [n for n, _ in cb])

        # Header values (per name present in either side, in A's order then B-only)
        out.append(Content(""))
        da, db = dict(self._regular(a)), dict(self._regular(b))
        names = list(dict.fromkeys(na + nb))
        diffs = [n for n in names if da.get(n) != db.get(n)]
        out.append(Content.from_markup("[b u]Header values[/b u]  ").append(self._mark(not diffs)))
        for n in diffs:
            out.append(Content.from_markup("  [yellow]$n[/yellow]", n=n))
            out.append(Content.from_markup("    [cyan]A[/cyan] $v", v=da.get(n, "∅")))
            out.append(Content.from_markup("    [magenta]B[/magenta] $v", v=db.get(n, "∅")))

        # Request body
        ba = a.request_body.inline if a.request_body.size else b""
        bb = b.request_body.inline if b.request_body.size else b""
        out.append(Content(""))
        sizes = f"A={a.request_body.size}B B={b.request_body.size}B"
        out.append(
            Content.from_markup("[b u]Request body[/b u]  ")
            .append(self._mark(ba == bb))
            .append(Content.from_markup("  [dim]$s[/dim]", s=sizes)))
        return Content("\n").join(out)


class TrafficViewerApp(App):
    CSS = """
    DataTable { height: 1fr; }
    TextPrompt, SelectPrompt { align: center middle; }
    #prompt {
        width: 60; height: auto; max-height: 80%;
        padding: 1 2; border: thick $accent; background: $surface;
    }
    #prompt Label { margin-bottom: 1; }
    #prompt OptionList { height: auto; max-height: 16; }
    """
    BINDINGS = [Binding("q", "quit", "Quit")]

    def __init__(self, address: str) -> None:
        super().__init__()
        self.address = address
        self.client = GatewayClient(address)
        self.compare_a: tuple[str, str] | None = None  # (session_id, flow_id) for compare slot A

    def get_default_screen(self) -> Screen:
        return SessionsScreen()

    async def on_unmount(self) -> None:
        await self.client.close()


def main() -> None:
    address = os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080")
    TrafficViewerApp(address).run()


if __name__ == "__main__":
    main()
