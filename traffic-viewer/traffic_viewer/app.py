"""Traffic-viewer TUI (plan §7.3, Phase 1 MVP).

Session list -> flow table -> flow detail. Read-only, backfill from the gateway's
ViewerService. HTTP/1.1 + HTTP/2.
"""

from __future__ import annotations

import os
import re
import shlex
from datetime import datetime, timezone

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static
from rich.markup import escape

from traffic_viewer.client import GatewayClient

SESSION_STATUS = {0: "?", 1: "open", 2: "decoding", 3: "closed", 4: "error"}


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


def compile_filter(expr: str):
    """Compile a filter expression to a predicate(flow)->bool, or None if empty.

    Terms (space-separated, ANDed): `~m/~d/~u/~c/~t <regex>`, `~s`/`~q`
    (has/no response), a naked regex (matches the URL), and a leading `!` negates a
    term. Raises ValueError on a bad regex. (Full `& | ()` grammar is future.)
    """
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
        elif t in _FILTER_FIELDS:
            i += 1
            if i >= len(toks):
                raise ValueError(f"{t} needs an argument")
            rx, getter, i = _rx(toks[i]), _FILTER_FIELDS[t], i + 1
            base = lambda f, rx=rx, g=getter: bool(rx.search(g(f) or ""))
        else:
            rx = _rx(t)
            base = lambda f, rx=rx: bool(rx.search(_url(f)))
            i += 1
        preds.append(lambda f, b=base, n=neg: (not b(f)) if n else b(f))
    return lambda f: all(p(f) for p in preds)


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


class SessionsScreen(Screen):
    BINDINGS = [Binding("r", "refresh", "Refresh"), Binding("q", "quit", "Quit")]

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


class FlowsScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("f", "filter", "Filter"),
        Binding("c", "compare", "Compare A/B"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str) -> None:
        super().__init__()
        self.session_id = session_id
        self.flows: dict[str, object] = {}  # flow id -> cached Flow (for live detail)
        self._rows: set[str] = set()
        self._cols: list = []
        self._predicate = None  # active filter

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(id="filter", placeholder="filter: ~m GET  ~d example.com  ~c 2..  !~t json  (f focus, Enter apply)")
        table = DataTable(id="flows", cursor_type="row", zebra_stripes=True)
        self._cols = table.add_columns("Time", "Method", "Status", "Proto", "Authority", "Path")
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self._update_subtitle()
        self.query_one("#flows", DataTable).focus()
        self.load_flows()

    def _update_subtitle(self) -> None:
        base = f"flows · {self.session_id[:8]}"
        if self._predicate is not None:
            base += f" · {len(self._rows)}/{len(self.flows)} shown"
        self.sub_title = base

    def _matches(self, f) -> bool:
        return self._predicate is None or self._predicate(f)

    def action_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        try:
            self._predicate = compile_filter(event.value)
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

    @staticmethod
    def _cells(f) -> tuple:
        return (
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
        self.app.push_screen(FlowDetailScreen(self.session_id, fid, self.flows.get(fid)))

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


class FlowDetailScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "save_request", "Save req body"),
        Binding("s", "save_response", "Save resp body"),
        Binding("x", "export_curl", "Export curl"),
        Binding("w", "export_raw", "Export raw"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, flow_id: str, cached=None) -> None:
        super().__init__()
        self.session_id = session_id
        self.flow_id = flow_id
        self.cached = cached  # full Flow from a live event, used if not yet persisted
        self._flow = None     # the loaded Flow (for export)

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

    @classmethod
    def _format_flow(cls, f) -> str:
        e = escape
        lines: list[str] = []
        url = f"{f.scheme or 'https'}://{f.authority}{f.path}"
        if f.query:
            url += f"?{f.query}"
        lines.append(f"[b]{e(f.method + ' ' + url)}[/b]")
        lines.append(
            f"[dim]{f.protocol}  status={f.status}  tls={'yes' if f.tls_decrypted else 'no'}  "
            f"{e(f.src_addr)} → {e(f.dst_addr)}[/dim]"
        )
        lines.append("")
        lines.append("[b u]Request headers[/b u]")
        for h in f.request_headers:
            lines.append(f"  [cyan]{e(h.name)}[/cyan]: {e(h.value)}")
        cls._append_body(lines, "Request body", f.request_body, "r")
        lines.append("")
        lines.append("[b u]Response headers[/b u]")
        for h in f.response_headers:
            lines.append(f"  [green]{e(h.name)}[/green]: {e(h.value)}")
        cls._append_body(lines, "Response body", f.response_body, "s")
        return "\n".join(lines)

    @classmethod
    def _append_body(cls, lines: list[str], title: str, body, save_key: str) -> None:
        if body is None or body.size == 0:
            return
        meta = f"{body.content_type or '?'} · {body.size} bytes"
        lines.append("")
        lines.append(f"[b u]{title}[/b u] [dim]{escape(meta)} · press {save_key} to save[/dim]")
        if body.WhichOneof("content") != "inline":
            lines.append(f"  [dim]large body — press {save_key} to save the full {body.size} bytes[/dim]")
            return
        data = body.inline
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            lines.append(f"  [dim]\\[binary {len(data)} bytes — press {save_key} to save][/dim]")
            return
        if len(text) > cls._BODY_RENDER_LIMIT:
            text = text[: cls._BODY_RENDER_LIMIT] + f"\n[dim]… ({body.size} bytes total — press {save_key} to save full)[/dim]"
        lines.append(escape(text))


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
    def _mark(equal: bool) -> str:
        return "[green]✓ match[/green]" if equal else "[red]✗ differ[/red]"

    def _render_diff(self, a, b) -> str:
        e = escape
        out: list[str] = []
        out.append(f"[b]A[/b] [dim]{e(a.method)} {e(a.authority)}{e(a.path)}[/dim]")
        out.append(f"[b]B[/b] [dim]{e(b.method)} {e(b.authority)}{e(b.path)}[/dim]")

        def section(title, va, vb, equal):
            out.append("")
            out.append(f"[b u]{title}[/b u]  {self._mark(equal)}")
            if not equal:
                out.append(f"  [cyan]A[/cyan] {e(va)}")
                out.append(f"  [magenta]B[/magenta] {e(vb)}")

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
        out.append("")
        da, db = dict(self._regular(a)), dict(self._regular(b))
        names = list(dict.fromkeys(na + nb))
        diffs = [n for n in names if da.get(n) != db.get(n)]
        out.append(f"[b u]Header values[/b u]  {self._mark(not diffs)}")
        for n in diffs:
            out.append(f"  [yellow]{e(n)}[/yellow]")
            out.append(f"    [cyan]A[/cyan] {e(da.get(n, '∅'))}")
            out.append(f"    [magenta]B[/magenta] {e(db.get(n, '∅'))}")

        # Request body
        ba = a.request_body.inline if a.request_body.size else b""
        bb = b.request_body.inline if b.request_body.size else b""
        out.append("")
        out.append(f"[b u]Request body[/b u]  {self._mark(ba == bb)}  "
                   f"[dim]A={a.request_body.size}B B={b.request_body.size}B[/dim]")
        return "\n".join(out)


class TrafficViewerApp(App):
    CSS = "DataTable { height: 1fr; }"
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
