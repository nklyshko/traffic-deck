"""Traffic-viewer TUI (plan §7.3, Phase 1 MVP).

Session list -> flow table -> flow detail. Read-only, backfill from the gateway's
ViewerService. HTTP/1.1 + HTTP/2.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static
from rich.markup import escape

from traffic_viewer.client import GatewayClient

SESSION_STATUS = {0: "?", 1: "open", 2: "decoding", 3: "closed", 4: "error"}


def _fmt_time(ts_micros: int) -> str:
    if not ts_micros:
        return ""
    dt = datetime.fromtimestamp(ts_micros / 1e6, tz=timezone.utc)
    return dt.strftime("%H:%M:%S.%f")[:-3]


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
    BINDINGS = [Binding("escape", "app.pop_screen", "Back"), Binding("q", "quit", "Quit")]

    def __init__(self, session_id: str) -> None:
        super().__init__()
        self.session_id = session_id

    def compose(self) -> ComposeResult:
        yield Header()
        table = DataTable(id="flows", cursor_type="row", zebra_stripes=True)
        table.add_columns("Time", "Method", "Status", "Proto", "Authority", "Path")
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.title = "traffic-viewer"
        self.sub_title = f"flows · {self.session_id[:8]}"
        self.load_flows()

    @work(exclusive=True)
    async def load_flows(self) -> None:
        table = self.query_one("#flows", DataTable)
        table.clear()
        try:
            async for f in self.app.client.stream_flows(self.session_id):
                table.add_row(
                    _fmt_time(f.ts_unix_micros),
                    f.method or "",
                    str(f.status) if f.status else "",
                    f.protocol or "",
                    f.authority or "",
                    (f.path or "")[:80],
                    key=f.id,
                )
        except Exception as exc:  # noqa: BLE001
            self.notify(f"stream_flows failed: {exc}", severity="error")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.app.push_screen(FlowDetailScreen(self.session_id, str(event.row_key.value)))


class FlowDetailScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "save_request", "Save req body"),
        Binding("s", "save_response", "Save resp body"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, flow_id: str) -> None:
        super().__init__()
        self.session_id = session_id
        self.flow_id = flow_id

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
        try:
            f = await self.app.client.get_flow(self.session_id, self.flow_id)
        except Exception as exc:  # noqa: BLE001
            self.query_one("#body", Static).update(f"[red]get_flow failed: {exc}[/red]")
            return
        self.query_one("#body", Static).update(self._format_flow(f))

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


class TrafficViewerApp(App):
    CSS = "DataTable { height: 1fr; }"
    BINDINGS = [Binding("q", "quit", "Quit")]

    def __init__(self, address: str) -> None:
        super().__init__()
        self.address = address
        self.client = GatewayClient(address)

    def get_default_screen(self) -> Screen:
        return SessionsScreen()

    async def on_unmount(self) -> None:
        await self.client.close()


def main() -> None:
    address = os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080")
    TrafficViewerApp(address).run()


if __name__ == "__main__":
    main()
