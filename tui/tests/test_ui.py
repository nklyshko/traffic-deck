"""UI tests driving the Textual app headlessly via App.run_test()/Pilot, with an
in-memory fake gateway client so screens get deterministic data (real proto objects)
without a live gateway. They exercise navigation + data wiring; rendering/DSL logic is
covered by test_render.py / test_filters.py."""

from __future__ import annotations

import asyncio
import os

from textual.app import App, ComposeResult
from textual.widgets import DataTable, Input, Label, OptionList, Static, TabPane

import traffic_viewer.client  # noqa: F401 — puts the generated stubs on sys.path
from traffic_viewer import screens
from traffic.v1 import common_pb2 as cp
from traffic.v1 import control_pb2 as cp2
from traffic.v1 import viewer_pb2 as vp
from traffic_viewer.app import TrafficViewerApp
from traffic_viewer.screens import (
    BodyScreen,
    CaptureWizardScreen,
    SelectPrompt,
    ConfirmScreen,
    QuitConfirmScreen,
    FlowDetailScreen,
    SessionPane,
    WorkspaceScreen,
    SessionsScreen,
    LogsScreen,
    LogViewScreen,
    CompareScreen,
    WsMessagesScreen,
    WsPayloadScreen,
)


# --- fixtures: canned data + fake client ----------------------------------

SESSION_ID = "sess-1"


def _session():
    return cp.Session(id=SESSION_ID, label="demo", status=3, flow_count=3,
                      pcap_bytes=1024, created_at_unix_ms=1_700_000_000_000)


def _flow(fid, method, status, websocket=False, tcp_stream="", h2_stream_id="", frame=204):
    # frame defaults to a fixed number for the small fixtures, but paging keys off
    # (ts_micros, frame_number) and needs it distinct per flow — as it is on the wire,
    # where a frame number identifies a packet.
    f = cp.Flow(id=fid, method=method, scheme="https", authority="api.example.com",
                path="/" + fid, protocol="HTTP/2", status=status, ts_unix_micros=1,
                tcp_stream=tcp_stream, h2_stream_id=h2_stream_id, frame_number=frame,
                # The 4-tuple the Wireshark hand-off filters on; a shared connection
                # (tcp_stream 12) shares the client port, as on the wire.
                src_addr="192.168.1.5:5100" + (tcp_stream[-1] if tcp_stream else "0"),
                dst_addr="93.184.216.34:443")
    if method:
        f.request_headers.append(cp.Header(name="content-type", value="application/json"))
        f.request_body.CopyFrom(cp.Body(size=7, content_type="application/json", inline=b'{"k":1}'))
    if status:
        f.response_headers.append(cp.Header(name="server", value="nginx"))
    if websocket:
        f.websocket = True
        f.ws_message_count = 2
    if fid == "f1":  # a TLS flow with two captured ClientHellos (as after a HelloRetryRequest)
        f.ja3 = "a" * 32
        f.tls_hrr = True
        f.client_hellos.extend([b"\x01\x00\x00\x02\x03\x03", b"\x01\x00\x00\x01\x03"])
    if fid == "f2":  # source metadata (as a scrape manager would attach)
        f.metadata["proxy_provider"] = "brightdata"
        f.metadata["scrape_group"] = "us-1"
    return f


# f1 and f2 are multiplexed onto one HTTP/2 connection (tcp stream 12, h2 streams 1 and 3);
# f3 sits on a second connection — enough to exercise the Conn/Stream columns and ~conn/~stream.
_FLOWS = [
    _flow("f1", "GET", 200, tcp_stream="12", h2_stream_id="1"),
    _flow("f2", "POST", 201, tcp_stream="12", h2_stream_id="3"),
    _flow("f3", "", 0, websocket=True, tcp_stream="13", h2_stream_id="1"),
]

SESSION_ID2 = "sess-2"
_FLOWS2 = [_flow("g1", "GET", 200), _flow("g2", "DELETE", 204)]


def _session2():
    return cp.Session(id=SESSION_ID2, label="prod", status=3, flow_count=len(_FLOWS2),
                      pcap_bytes=2048, created_at_unix_ms=1_700_000_100_000)


_BY_SESSION = {SESSION_ID: _FLOWS, SESSION_ID2: _FLOWS2}


def _ws_messages():
    return [
        cp.WsMessage(id="m1", flow_id="f3", from_client=True, opcode="text", ts_unix_micros=2,
                     payload=cp.Body(size=9, inline=b"subscribe")),
        cp.WsMessage(id="m2", flow_id="f3", from_client=False, opcode="binary", ts_unix_micros=3,
                     payload=cp.Body(size=2, inline=b"\x01\x02")),
    ]


class _RefusedFilter(Exception):
    """Stands in for the gateway refusing an expression: an AioRpcError carrying
    InvalidArgument and the parser's message, which is what the screens read."""

    def __init__(self, details: str) -> None:
        super().__init__(details)
        self._details = details

    def code(self):
        import grpc
        return grpc.StatusCode.INVALID_ARGUMENT

    def details(self) -> str:
        return self._details


class FakeClient:
    """Implements the async surface the screens call, served from memory."""

    def __init__(self):
        self._sessions = [_session(), _session2()]
        self.force_closed = []
        self.marks = []     # recorded (record_ids, color|None) from set_mark/clear_mark
        self.comments = []  # recorded (record_id, body) from add_comment
        # Capture control.
        self.capture_sources = [cp2.CaptureSourceInfo(name="chrome", label="Chrome")]
        self.describe_calls = []  # (source, params) each DescribeCaptureSource
        self.started = []         # (source, label, params) each StartCapture
        self.stopped = []         # session ids stopped
        self.mcp_running = False
        self.android_provision_calls = 0
        self.hold_flows = False   # keep stream_flows open, as a live session's would be
        self.stream_attempts = 0  # StreamFlows subscriptions made (a viewer reconnects)
        self.msg_streams = 0      # StreamMessages subscriptions made
        self.drop_streams = 0     # ...end this many of them at once, as a gateway hang-up
        self.close_session = False  # ...or end them by reporting the session closed
        self.partial_bodies = False  # serve bodies as live previews (capped mid-capture)
        self.artifacts = {}       # GetSessionArtifacts reply fields (pcap/keylog paths)

    async def list_capture_sources(self):
        return list(self.capture_sources)

    async def describe_capture_source(self, source, params=None):
        params = dict(params or {})
        self.describe_calls.append((source, params))
        if source == "android":
            # A persistent source: PROVISION_REQUIRED until consent; then it "provisions" in
            # the background (one in-progress describe with no params) before going READY.
            if params.get("provision") != "start":
                return cp2.SourceDescriptor(
                    readiness=cp2.READINESS_PROVISION_REQUIRED, message="set up the device",
                    params=[cp2.Param(key="provision", label="Set up", type=cp2.PARAM_TYPE_CHOICE,
                                      required=True, choices=[cp2.Choice(value="start", label="Set up")])])
            self.android_provision_calls += 1
            if self.android_provision_calls < 2:  # still provisioning
                return cp2.SourceDescriptor(
                    readiness=cp2.READINESS_PROVISION_REQUIRED, message="Setting up the device…")
            return cp2.SourceDescriptor(
                readiness=cp2.READINESS_READY,
                params=[cp2.Param(key="package", label="App", type=cp2.PARAM_TYPE_CHOICE,
                                  choices=[cp2.Choice(value="com.a")])])
        # A tiny cascade: "profile" only appears once a "mode" is chosen.
        out = [cp2.Param(key="mode", label="Mode", type=cp2.PARAM_TYPE_CHOICE,
                         choices=[cp2.Choice(value="fast"), cp2.Choice(value="slow")],
                         default=params.get("mode", ""))]
        if params.get("mode"):
            out.append(cp2.Param(key="profile", label="Profile", type=cp2.PARAM_TYPE_STRING,
                                 default="p1"))
        return cp2.SourceDescriptor(params=out, readiness=cp2.READINESS_READY)

    async def start_capture(self, source, label, params):
        self.started.append((source, label, dict(params)))
        return "cap-sess-1"

    async def stop_capture(self, session_id):
        self.stopped.append(session_id)

    async def list_services(self):
        return [cp2.ServiceInfo(name="mcp", label="MCP server", running=self.mcp_running,
                                url="http://127.0.0.1:8765/mcp", detail="loopback, read-only")]

    async def start_service(self, name):
        self.mcp_running = True
        return cp2.ServiceInfo(name=name, running=True, url="http://127.0.0.1:8765/mcp",
                               detail="loopback, read-only")

    async def stop_service(self, name):
        self.mcp_running = False

    async def list_logs(self):
        return [
            cp2.LogInfo(name="gateway", label="gateway", size_bytes=2048,
                        modified_unix_ms=1_700_000_000_000),
            cp2.LogInfo(name="chrome", label="Chrome", size_bytes=512,
                        modified_unix_ms=1_700_000_050_000),
        ]

    async def get_log(self, name, max_bytes=0):
        return f"=== {name} started ===\n[{name}] hello\n".encode()

    async def list_sessions(self, limit=200):
        return list(self._sessions)

    async def delete_session(self, session_id):
        self._sessions = [s for s in self._sessions if s.id != session_id]

    async def set_session_label(self, session_id, label):
        for s in self._sessions:
            if s.id == session_id:
                s.label = label

    async def import_session(self, src_path):
        s = cp.Session(id="imported-1", label="imported", status=3, flow_count=0)
        self._sessions.append(s)
        return s

    async def force_close_session(self, session_id):
        self.force_closed.append(session_id)

    async def get_session_artifacts(self, session_id):
        # Where the gateway keeps the session's raw capture; tests point these at real
        # temp files (see _stub_wireshark) so the local-readability check passes.
        return cp2.SessionArtifacts(hostname="gw-host", **self.artifacts)

    # --- gateway-side filtering and paging (ADR-0012) ---------------------
    #
    # The real predicate lives in the gateway; this stands in for it with the handful of
    # terms the UI tests exercise, so the pane is driven the way the server drives it:
    # one window at a time, with cursors rather than offsets.

    @staticmethod
    def _matches(f, expr: str) -> bool:
        import re as _re
        if not expr:
            return True
        toks = expr.split()
        i = 0
        while i < len(toks):
            t = toks[i]
            if t == "~m" and i + 1 < len(toks):
                if not _re.search(toks[i + 1], f.method or "", _re.I):
                    return False
                i += 2
            elif t == "~d" and i + 1 < len(toks):
                if not _re.search(toks[i + 1], f.authority or "", _re.I):
                    return False
                i += 2
            elif t == "~c" and i + 1 < len(toks):
                if not _re.search(toks[i + 1], str(f.status or ""), _re.I):
                    return False
                i += 2
            elif t == "~s":
                if not f.status:
                    return False
                i += 1
            elif t == "~q":
                if f.status:
                    return False
                i += 1
            else:
                url = f"{f.scheme or 'https'}://{f.authority}{f.path}"
                if not _re.search(t, url, _re.I):
                    return False
                i += 1
        return True

    async def query_flows(self, session_id, filter_expr="", limit=250,
                          after=None, before=None, last=False):
        rows = [f for f in _BY_SESSION.get(session_id, _FLOWS)
                if self._matches(f, filter_expr)]
        rows.sort(key=lambda f: (f.ts_unix_micros, f.frame_number))
        key = lambda f: (f.ts_unix_micros, f.frame_number)
        if after is not None:
            rows = [f for f in rows if key(f) > (after.ts_micros, after.frame_number)]
        if before is not None:
            rows = [f for f in rows if key(f) < (before.ts_micros, before.frame_number)]
        matched = len(rows)
        window = rows[-limit:] if (last or before is not None) else rows[:limit]
        page = vp.FlowPage(flows=window, matched=matched)
        if window:
            first, lastf = window[0], window[-1]
            # A cursor is offered only when there is something that way — being at an end
            # is not the same as the window merely being short.
            all_rows = [f for f in _BY_SESSION.get(session_id, _FLOWS)
                        if self._matches(f, filter_expr)]
            all_rows.sort(key=key)
            if any(key(f) > key(lastf) for f in all_rows):
                page.next.ts_micros, page.next.frame_number = lastf.ts_unix_micros, lastf.frame_number
            if any(key(f) < key(first) for f in all_rows):
                page.prev.ts_micros, page.prev.frame_number = first.ts_unix_micros, first.frame_number
        return page

    async def stream_flows(self, session_id, follow=False, filter_expr=""):
        # A following subscription carries liveness only — query_flows serves the rows a
        # viewer displays, so replaying here would undo the paging.
        if not follow:
            for f in _BY_SESSION.get(session_id, _FLOWS):
                if self._matches(f, filter_expr):
                    yield vp.FlowEvent(flow_added=f)
        if follow:
            # The gateway marks a live subscription as established, which is the viewer's
            # cue to re-issue its query and close the gap between the two calls.
            self.stream_attempts += 1
            yield vp.FlowEvent(session_event=vp.SessionEvent(session_id=session_id, status=1))
            if self.close_session:
                # The capture ended: the viewer is told so, and must not resubscribe.
                yield vp.FlowEvent(session_event=vp.SessionEvent(session_id=session_id, status=3))
                return
            if self.drop_streams > 0:
                self.drop_streams -= 1
                return  # a subscription that ended without the session closing
        if self.hold_flows:
            # Stand in for a session still capturing: the real stream stays open until the
            # session closes, so the pane keeps its live state instead of finalizing.
            await asyncio.Event().wait()

    async def get_flow(self, session_id, flow_id):
        for f in _BY_SESSION.get(session_id, _FLOWS):
            if f.id == flow_id:
                return f
        raise KeyError(flow_id)

    async def get_body(self, session_id, flow_id, response):
        # (bytes, partial) — partial marks a body the live decode only kept the start of.
        return b'{"k":1}', self.partial_bodies

    # The message filter is its own dialect (payload/opcode/direction), evaluated by the
    # gateway; this stands in for it with the terms the UI tests exercise — including the
    # refusal of a flow term, which is what keeps `~m GET` from reading as an empty
    # timeline.
    _MSG_TERMS = {"~b", "~op", "~from", "~mark", "~tag", "~group", "~comment", "~fav"}

    @classmethod
    def _msg_matches(cls, m, expr: str) -> bool:
        import re as _re
        toks = expr.split()
        i = 0
        while i < len(toks):
            t = toks[i]
            if t.startswith("~") and t not in cls._MSG_TERMS:
                raise _RefusedFilter(f"unknown message filter term {t!r}")
            if t == "~op" and i + 1 < len(toks):
                if not _re.search(toks[i + 1], m.opcode or "", _re.I):
                    return False
                i += 2
            elif t == "~from" and i + 1 < len(toks):
                if not _re.search(toks[i + 1], "client" if m.from_client else "server", _re.I):
                    return False
                i += 2
            else:  # ~b <re>, or a bare regex — both match the payload
                pat = toks[i + 1] if (t == "~b" and i + 1 < len(toks)) else t
                if not _re.search(pat, (m.payload.inline or b"").decode("utf-8", "replace"), _re.I):
                    return False
                i += 2 if t == "~b" else 1
        return True

    async def stream_messages(self, session_id, flow_id, follow=True, filter_expr=""):
        self.msg_streams += 1
        if "&" in filter_expr:
            # The grammar has no operators, so a stray one is a payload regex — advisory,
            # not an error, and the gateway says so before sending any frame.
            yield vp.MessageEvent(filter_hints=vp.FilterHints(
                hints=["`&` is not an operator — terms are ANDed automatically."]))
        for m in _ws_messages():
            if self._msg_matches(m, filter_expr):
                yield vp.MessageEvent(message_added=m)

    async def get_message(self, session_id, message_id):
        for m in _ws_messages():
            if m.id == message_id:
                return m
        raise KeyError(message_id)

    async def get_message_body(self, session_id, message_id):
        return b"hello"

    async def set_mark(self, session_id, ids, color):
        self.marks.append((tuple(ids), color))

    async def clear_mark(self, session_id, ids):
        self.marks.append((tuple(ids), None))

    async def add_comment(self, session_id, record_id, body):
        self.comments.append((record_id, body))
        return cp.Comment(id="c1", record_id=record_id, body=body)

    async def list_tags(self):
        return []

    async def list_groups(self):
        return []

    async def close(self):
        pass


def make_app():
    app = TrafficViewerApp("127.0.0.1:0")
    app.client = FakeClient()  # replace the real (unconnected) client
    return app


async def settle(pilot, n=8):
    """Let the screens' async workers (list/stream/get) run to completion."""
    for _ in range(n):
        await pilot.pause()


async def focus(pilot, selector):
    """Focus a widget and let the focus change apply before the next keypress."""
    pilot.app.screen.query_one(selector).focus()
    await pilot.pause()


# --- tests ----------------------------------------------------------------

async def test_sessions_screen_lists():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        assert isinstance(app.screen, SessionsScreen)
        table = app.screen.query_one("#sessions", DataTable)
        assert table.row_count == 2  # two sessions in the fixture


async def test_sessions_list_refreshes_when_reopened():
    """Returning to the session list (e.g. exiting a session) auto-refreshes it, so a
    session that appeared on the gateway while the user was away shows up."""
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        sessions = app.screen
        assert isinstance(sessions, SessionsScreen)
        assert sessions.query_one("#sessions", DataTable).row_count == 2

        await focus(pilot, "#sessions")
        await pilot.press("enter")        # drill into a session (pushes the workspace)
        await settle(pilot)
        assert isinstance(app.screen, WorkspaceScreen)

        # A new session appears on the gateway while we're inside the workspace.
        app.client._sessions.append(
            cp.Session(id="sess-3", label="fresh", status=3, flow_count=0))

        app.pop_screen()                  # exit back to the list → ScreenResume refreshes it
        await settle(pilot)
        assert app.screen is sessions
        assert sessions.query_one("#sessions", DataTable).row_count == 3


async def test_sessions_refresh_keeps_the_cursor_put():
    """An auto-refresh must not yank the selection back to the top row."""
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        table = app.screen.query_one("#sessions", DataTable)
        await focus(pilot, "#sessions")
        await pilot.press("down")         # move off the first row
        await settle(pilot)
        assert table.cursor_coordinate.row == 1
        key_before = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value

        app.screen.load_sessions(quiet=True)  # a periodic refresh
        await settle(pilot)
        key_after = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        assert key_after == key_before        # same session still selected


async def test_delete_session():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        table = app.screen.query_one("#sessions", DataTable)
        assert table.row_count == 2
        await focus(pilot, "#sessions")
        await pilot.press("d")   # delete the focused session
        await settle(pilot)
        await pilot.press("y")   # confirm
        await settle(pilot)
        assert app.screen.query_one("#sessions", DataTable).row_count == 1


async def test_force_close_session():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("c")   # force-close the focused session
        await settle(pilot)
        await pilot.press("y")   # confirm
        await settle(pilot)
        assert app.client.force_closed == [SESSION_ID]


async def test_rename_session():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("n")   # rename
        await settle(pilot)
        app.screen.query_one("#prompt-input", Input).value = "new-name"
        await pilot.press("enter")
        await settle(pilot)
        assert app.client._sessions[0].label == "new-name"


async def test_import_session():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        assert app.screen.query_one("#sessions", DataTable).row_count == 2
        await pilot.press("i")   # import
        await settle(pilot)
        app.screen.query_one("#prompt-input", Input).value = "/tmp/bundle.tar.gz"
        await pilot.press("enter")
        await settle(pilot)
        assert app.screen.query_one("#sessions", DataTable).row_count == 3


async def test_ctrl_c_opens_quit_dialog_then_confirms():
    app = make_app()
    exits = []
    app.exit = lambda *a, **k: exits.append(True)  # spy: don't actually tear down
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("ctrl+c")           # first: open the quit dialog
        await settle(pilot)
        assert isinstance(app.screen, QuitConfirmScreen)
        assert not exits                      # first press must not quit
        await pilot.press("ctrl+c")           # second: confirm quit
        await settle(pilot)
        assert exits == [True]


async def test_ctrl_c_can_be_cancelled():
    app = make_app()
    exits = []
    app.exit = lambda *a, **k: exits.append(True)
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("ctrl+c")
        await settle(pilot)
        assert isinstance(app.screen, QuitConfirmScreen)
        await pilot.press("n")                # decline
        await settle(pilot)
        assert isinstance(app.screen, SessionsScreen)
        assert not exits


async def test_drill_session_to_flows():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")  # open the focused session
        await settle(pilot)
        assert isinstance(app.screen, WorkspaceScreen)
        pane = app.screen.query_one(SessionPane)
        assert pane.session_id == SESSION_ID
        assert pane.query_one("#flows", DataTable).row_count == len(_FLOWS)


async def test_filter_reduces_rows():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#filter")
        flt = app.screen.query_one("#filter", Input)
        flt.value = "~m POST"
        await pilot.press("enter")  # apply the filter
        await settle(pilot)
        assert app.screen.query_one("#flows", DataTable).row_count == 1  # only f2


async def test_filter_help_shown_only_while_filter_focused():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        help_ = app.screen.query_one("#filter-help", Static)
        assert help_.display is False      # hidden while browsing the table
        await pilot.press("f")             # focus the filter input
        await settle(pilot)
        assert help_.display is True       # cheat sheet revealed
        await pilot.press("escape")        # leave the filter
        await settle(pilot)
        assert help_.display is False      # hidden again


async def _open_flows(pilot):
    """Navigate sessions → the first session's flow table."""
    await settle(pilot)
    await focus(pilot, "#sessions")
    await pilot.press("enter")
    await settle(pilot)


async def _toggle_column(pilot, cid):
    """Open the column picker (C) and toggle the option carrying the given column id."""
    await pilot.press("C")
    await settle(pilot)
    opts = pilot.app.screen.query_one(OptionList)
    opts.highlighted = next(i for i in range(opts.option_count)
                            if opts.get_option_at_index(i).id == cid)
    await pilot.press("enter")
    await settle(pilot)


async def test_logs_screen_lists_and_opens_a_log():
    """L from the sessions list opens the log browser; Enter on a row shows that log's
    tail, fetched from the gateway (get_log), rendered literally."""
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("L")
        await settle(pilot)
        assert isinstance(pilot.app.screen, LogsScreen)
        table = pilot.app.screen.query_one("#logs", DataTable)
        assert table.row_count == 2                       # gateway + chrome (from FakeClient)

        await pilot.press("enter")                        # open the focused log (gateway)
        await settle(pilot)
        assert isinstance(pilot.app.screen, LogViewScreen)
        rendered = pilot.app.screen.query_one("#logbody", Static).render().plain
        assert "[gateway] hello" in rendered              # markup-looking line kept literal


async def test_metadata_column_picker_toggles_column():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        pane = app.screen.query_one(SessionPane)
        table = pane.query_one("#flows", DataTable)
        base_cols = len(table.ordered_columns)
        assert pane._extra_cols == []           # nothing shown by default

        await focus(pilot, "#flows")
        await _toggle_column(pilot, "meta:proxy_provider")

        assert pane._extra_cols == ["meta:proxy_provider"]
        assert len(table.ordered_columns) == base_cols + 1
        # f2 carries proxy_provider=brightdata; its row shows it in the new column.
        assert str(table.get_cell("f2", pane._extra_col_keys["meta:proxy_provider"])) == "brightdata"

        # Toggling the same key again removes the column.
        await _toggle_column(pilot, "meta:proxy_provider")
        assert pane._extra_cols == []
        assert len(table.ordered_columns) == base_cols


async def test_conn_stream_columns_are_optional_and_toggleable():
    # The HTTP/2 connection/stream columns are off by default and toggle on from the same
    # picker; f1 and f2 share connection 12 on distinct streams.
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        pane = app.screen.query_one(SessionPane)
        table = pane.query_one("#flows", DataTable)
        base_cols = len(table.ordered_columns)
        assert pane._extra_cols == []

        await focus(pilot, "#flows")
        await _toggle_column(pilot, "conn")
        await _toggle_column(pilot, "stream")

        assert pane._extra_cols == ["conn", "stream"]
        assert len(table.ordered_columns) == base_cols + 2
        assert [c.label.plain for c in table.ordered_columns[-2:]] == ["Conn", "Stream"]
        # Same connection, different streams — the multiplexing the columns exist to show.
        assert str(table.get_cell("f1", pane._extra_col_keys["conn"])) == "12"
        assert str(table.get_cell("f2", pane._extra_col_keys["conn"])) == "12"
        assert str(table.get_cell("f1", pane._extra_col_keys["stream"])) == "1"
        assert str(table.get_cell("f2", pane._extra_col_keys["stream"])) == "3"
        assert str(table.get_cell("f3", pane._extra_col_keys["conn"])) == "13"

        await _toggle_column(pilot, "conn")
        assert pane._extra_cols == ["stream"]
        assert len(table.ordered_columns) == base_cols + 1


async def test_source_declared_columns_seed_table():
    # A capture source declaring viewer.columns seeds the pane's default columns.
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(WorkspaceScreen(SESSION_ID, "demo", source_columns=["proxy_provider"]))
        await settle(pilot)
        pane = app.screen.query_one(SessionPane)
        assert pane._extra_cols == ["meta:proxy_provider"]
        table = pane.query_one("#flows", DataTable)
        assert str(table.get_cell("f2", pane._extra_col_keys["meta:proxy_provider"])) == "brightdata"


def test_resolve_columns_unions_env_and_source(monkeypatch):
    from traffic_viewer.screens import _resolve_columns, _session_view_columns

    monkeypatch.setenv("TRAFFICDECK_META_COLUMNS", "region, proxy_provider")
    # env first, then source-declared, de-duplicated and order-preserving.
    assert _resolve_columns(["proxy_provider", "scrape_group"]) == \
        ["region", "proxy_provider", "scrape_group"]

    s = cp.Session(id="s1")
    s.metadata["viewer.columns"] = "scrape_group, proxy_provider"
    assert _session_view_columns(s) == ["scrape_group", "proxy_provider"]
    assert _session_view_columns(cp.Session(id="s2")) == []


def test_col_id_maps_field_names_and_metadata_keys():
    from traffic_viewer.screens import _col_id

    # A built-in field name resolves to the field column; anything else is a metadata key.
    assert _col_id("conn") == "conn"
    assert _col_id("stream") == "stream"
    assert _col_id("proxy_provider") == "meta:proxy_provider"


async def test_pcap_source_declared_conn_stream_columns_shown_by_default():
    # A pcap-based source declares viewer.columns="conn,stream" (capture_sdk's
    # PCAP_VIEWER_COLUMNS); the pane shows both without the user toggling anything.
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(WorkspaceScreen(SESSION_ID, "demo", source_columns=["conn", "stream"]))
        await settle(pilot)
        pane = app.screen.query_one(SessionPane)
        assert pane._extra_cols == ["conn", "stream"]
        table = pane.query_one("#flows", DataTable)
        assert [c.label.plain for c in table.ordered_columns[-2:]] == ["Conn", "Stream"]
        assert str(table.get_cell("f1", pane._extra_col_keys["conn"])) == "12"
        assert str(table.get_cell("f2", pane._extra_col_keys["stream"])) == "3"


async def test_metadata_column_from_env(monkeypatch):
    monkeypatch.setenv("TRAFFICDECK_META_COLUMNS", "proxy_provider")
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        pane = app.screen.query_one(SessionPane)
        assert pane._extra_cols == ["meta:proxy_provider"]
        table = pane.query_one("#flows", DataTable)
        assert str(table.get_cell("f2", pane._extra_col_keys["meta:proxy_provider"])) == "brightdata"


async def test_drill_flow_to_detail():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#flows")
        await pilot.press("enter")  # open the first flow (f1, GET)
        await settle(pilot)
        assert isinstance(app.screen, FlowDetailScreen)
        assert app.screen._flow is not None
        assert app.screen._flow.method == "GET"


async def _open_first_flow_detail(pilot):
    """Navigate sessions → flows → detail of the first flow (f1, GET)."""
    await settle(pilot)
    await focus(pilot, "#sessions")
    await pilot.press("enter")
    await settle(pilot)
    await focus(pilot, "#flows")
    await pilot.press("enter")
    await settle(pilot)


async def test_detail_view_shows_connection_and_stream():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_first_flow_detail(pilot)          # f1: conn 12, h2 stream 1
        rendered = app.screen.query_one("#body", Static).render().plain
        assert "conn=12" in rendered
        assert "stream=1" in rendered


async def test_detail_view_omits_stream_for_non_multiplexed_flow():
    # An HTTP/1.1 flow has a connection but no stream id — the stream part is dropped
    # rather than rendered empty.
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        f = _flow("h1", "GET", 200, tcp_stream="7")
        f.protocol = "HTTP/1.1"
        app.push_screen(FlowDetailScreen(SESSION_ID, "h1", f, {}, {}))
        await settle(pilot)
        rendered = app.screen.query_one("#body", Static).render().plain
        assert "conn=7" in rendered
        assert "stream=" not in rendered


async def test_detail_view_request_body_opens_body_screen():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_first_flow_detail(pilot)
        assert isinstance(app.screen, FlowDetailScreen)
        await pilot.press("b")  # view request body
        await settle(pilot)
        assert isinstance(app.screen, BodyScreen)
        assert app.screen._label == "request"
        assert app.screen._data == b'{"k":1}'


async def test_export_client_hellos_writes_hex_lines(tmp_path):
    app = make_app()
    async with app.run_test() as pilot:
        await _open_first_flow_detail(pilot)  # f1 has two captured ClientHellos + HRR
        assert isinstance(app.screen, FlowDetailScreen)
        await pilot.press("H")  # export ClientHellos
        await settle(pilot)
        out = tmp_path / "hellos.hex"
        app.screen.query_one("#prompt-input", Input).value = str(out)
        await pilot.press("enter")
        await settle(pilot)
        # One hex line per ClientHello, in wire order.
        assert out.read_text() == "010000020303\n0100000103\n"


async def test_export_client_hellos_noop_without_hellos(tmp_path):
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#flows")
        await pilot.press("down")  # move to f2 (no ClientHellos)
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, FlowDetailScreen)
        await pilot.press("H")  # should notify + no prompt
        await settle(pilot)
        # No TextPrompt was pushed (still on the detail screen).
        assert isinstance(app.screen, FlowDetailScreen)


def _stub_wireshark(monkeypatch, app, tmp_path, keylog=True):
    """Point the hand-off at a fake Wireshark and a real (temp) session bundle, and
    capture the argv instead of launching anything. Returns the list it records into."""
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
    app.client.artifacts = {"pcap_path": str(pcap), "pcap_bytes": 4}
    if keylog:
        klog = tmp_path / "key.log"
        klog.write_text("CLIENT_RANDOM aa bb\n")
        app.client.artifacts |= {"keylog_path": str(klog), "keylog_bytes": klog.stat().st_size}

    launched: list[list[str]] = []

    async def fake_exec(*cmd, **kw):
        launched.append(list(cmd))

    monkeypatch.setattr(screens, "find_wireshark", lambda: "/usr/bin/wireshark")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    return launched


async def test_flow_list_opens_wireshark_on_the_focused_flow(monkeypatch, tmp_path):
    app = make_app()
    async with app.run_test() as pilot:
        launched = _stub_wireshark(monkeypatch, app, tmp_path)
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#flows")
        await pilot.press("W")            # f1: HTTP/2, conn 12, stream 1
        await settle(pilot)
        assert len(launched) == 1
        cmd = launched[0]
        assert cmd[0] == "/usr/bin/wireshark"
        assert cmd[1:3] == ["-r", str(tmp_path / "capture.pcap")]
        assert f"tls.keylog_file:{tmp_path / 'key.log'}" in cmd
        assert cmd[cmd.index("-Y") + 1] == (
            "ip.addr eq 192.168.1.5 and tcp.port eq 51002 and "
            "ip.addr eq 93.184.216.34 and tcp.port eq 443 and "
            "(http2.streamid eq 1 or not http2)")
        assert cmd[cmd.index("-g") + 1] == "204"   # cursor parked on the request's frame


async def test_flow_detail_opens_wireshark(monkeypatch, tmp_path):
    app = make_app()
    async with app.run_test() as pilot:
        launched = _stub_wireshark(monkeypatch, app, tmp_path, keylog=False)
        await _open_first_flow_detail(pilot)
        assert isinstance(app.screen, FlowDetailScreen)
        await pilot.press("W")
        await settle(pilot)
        assert len(launched) == 1
        # No key.log in this bundle (a pcapng with embedded secrets): no override option.
        assert "-o" not in launched[0]


async def test_wireshark_skipped_when_the_pcap_is_on_another_host(monkeypatch, tmp_path):
    """A remote gateway's pcap path means nothing locally — say so instead of launching
    Wireshark on a path that doesn't exist here."""
    app = make_app()
    async with app.run_test() as pilot:
        launched = _stub_wireshark(monkeypatch, app, tmp_path)
        app.client.artifacts["pcap_path"] = str(tmp_path / "elsewhere" / "capture.pcap")
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#flows")
        await pilot.press("W")
        await settle(pilot)
        assert launched == []


async def test_wireshark_skipped_for_a_session_without_a_pcap(monkeypatch, tmp_path):
    app = make_app()
    async with app.run_test() as pilot:
        launched = _stub_wireshark(monkeypatch, app, tmp_path)
        app.client.artifacts = {}   # proxy-captured session: no pcap at all
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#flows")
        await pilot.press("W")
        await settle(pilot)
        assert launched == []


async def test_body_view_renders_small_body_inline():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(BodyScreen(SESSION_ID, "f1", "application/json", False, "f1"))
        await settle(pilot)
        assert isinstance(app.screen, BodyScreen)
        rendered = app.screen.query_one("#pbody", Static).render()
        assert '"k"' in rendered.plain  # JSON pretty-printed inline, not handed off


async def test_body_view_flags_a_live_preview():
    """A body the live decode only kept the start of must say so on screen — otherwise a
    prefix reads as the whole body (and the JSON below it looks merely malformed)."""
    app = make_app()
    app.client.partial_bodies = True
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(BodyScreen(SESSION_ID, "f1", "application/json", False, "f1"))
        await settle(pilot)
        meta = app.screen.query_one("#pmeta", Static)
        assert meta.display
        assert "live preview" in meta.render().plain
        assert "session closes" in meta.render().plain


async def test_body_view_has_no_preview_notice_for_a_whole_body():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(BodyScreen(SESSION_ID, "f1", "application/json", False, "f1"))
        await settle(pilot)
        assert not app.screen.query_one("#pmeta", Static).display


async def test_body_view_opens_editor_for_large_body(monkeypatch):
    opened = []
    monkeypatch.setattr(BodyScreen, "_open_external", lambda self: opened.append(self._label))
    big = b"x" * (BodyScreen._VIEW_LIMIT + 10)

    async def big_body(session_id, flow_id, response):
        return big, False

    app = make_app()
    app.client.get_body = big_body
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(BodyScreen(SESSION_ID, "f1", "text/plain", False, "f1"))
        await settle(pilot)
        assert opened == ["request"]  # auto-handed off to the editor


async def test_ws_payload_formats_json_inline():
    app = make_app()

    async def json_body(session_id, message_id):
        return b'{"a":1,"b":2}'

    app.client.get_message_body = json_body
    msg = _ws_messages()[0]
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(WsPayloadScreen(SESSION_ID, msg))
        await settle(pilot)
        assert isinstance(app.screen, WsPayloadScreen)
        rendered = app.screen.query_one("#pbody", Static).render()
        assert '"a"' in rendered.plain and "\n" in rendered.plain  # reindented JSON
        # No annotations on this frame → the meta block stays hidden.
        assert app.screen.query_one("#pmeta", Static).display is False


async def test_ws_payload_shows_comment():
    app = make_app()
    msg = _ws_messages()[0]
    msg.comments.append(cp.Comment(id="c1", record_id=msg.id, body="look here"))
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(WsPayloadScreen(SESSION_ID, msg))
        await settle(pilot)
        meta = app.screen.query_one("#pmeta", Static)
        assert meta.display is True
        assert "look here" in meta.render().plain  # comment shown above the payload


async def test_ws_payload_opens_editor_for_large_body(monkeypatch):
    opened = []
    monkeypatch.setattr(WsPayloadScreen, "_open_external", lambda self: opened.append(self._what))
    big = b"y" * (WsPayloadScreen._VIEW_LIMIT + 10)

    async def big_msg_body(session_id, message_id):
        return big

    app = make_app()
    app.client.get_message_body = big_msg_body
    msg = _ws_messages()[0]
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(WsPayloadScreen(SESSION_ID, msg))
        await settle(pilot)
        assert opened == ["payload"]  # large payload handed off to the editor


async def test_open_ws_message_timeline():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#flows")
        await pilot.press("down", "down", "M")  # move to the ws flow (f3), open timeline
        await settle(pilot)
        assert isinstance(app.screen, WsMessagesScreen)
        assert app.screen.query_one("#msgs", DataTable).row_count == len(_ws_messages())


async def _open_ws_timeline(pilot):
    """Navigate sessions → flows → the WebSocket flow (f3) → its message timeline."""
    await settle(pilot)
    await focus(pilot, "#sessions")
    await pilot.press("enter")
    await settle(pilot)
    await focus(pilot, "#flows")
    await pilot.press("down", "down", "M")
    await settle(pilot)


async def test_ws_message_mark():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_ws_timeline(pilot)
        assert isinstance(app.screen, WsMessagesScreen)
        await focus(pilot, "#msgs")
        await pilot.press("m")        # mark → opens the color SelectPrompt
        await settle(pilot)
        await pilot.press("enter")    # pick the first color
        await settle(pilot)
        # The mark reached the gateway keyed on the focused message id (m1).
        assert app.client.marks and app.client.marks[0][0] == ("m1",)
        assert app.client.marks[0][1] is not None  # a color, not a clear


async def test_ws_message_comment():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_ws_timeline(pilot)
        assert isinstance(app.screen, WsMessagesScreen)
        await focus(pilot, "#msgs")
        await pilot.press("n")        # comment → opens the text prompt
        await settle(pilot)
        app.screen.query_one("#prompt-input", Input).value = "look here"
        await pilot.press("enter")
        await settle(pilot)
        assert app.client.comments == [("m1", "look here")]


async def test_ws_messages_filter_by_opcode_and_payload():
    """A chatty connection is tens of thousands of frames, so the timeline filters like
    the flow table does — by opcode, by payload, and by direction."""
    app = make_app()
    async with app.run_test() as pilot:
        await _open_ws_timeline(pilot)
        screen = app.screen
        assert isinstance(screen, WsMessagesScreen)
        table = screen.query_one("#msgs", DataTable)
        assert table.row_count == 2

        for expr, want in [("~op text", 1), ("~b subscribe", 1), ("subscribe", 1),
                           ("~from server", 1), ("~op text ~from server", 0), ("", 2)]:
            await focus(pilot, "#filter")
            screen.query_one("#filter", Input).value = expr
            await pilot.press("enter")
            await settle(pilot)
            assert table.row_count == want, f"{expr!r} kept {table.row_count} frames"
            # The status line counts what matched, not what the flow has.
            assert f"{want} matching" in screen.sub_title if expr else \
                f"{want} frames" in screen.sub_title


async def test_ws_messages_filter_help_shown_only_while_focused():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_ws_timeline(pilot)
        help_ = app.screen.query_one("#filter-help", Static)
        assert help_.display is False
        await pilot.press("f")             # focus the filter input
        await settle(pilot)
        assert help_.display is True
        # Escape leaves the filter for the table — it does not leave the screen.
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, WsMessagesScreen)
        assert help_.display is False


async def test_ws_messages_filter_error_is_reported():
    """A flow term is not a message term. The gateway refuses it, and the timeline says so
    rather than showing an empty table that reads as "no frames"."""
    app = make_app()
    notes = []
    async with app.run_test() as pilot:
        await _open_ws_timeline(pilot)
        screen = app.screen
        screen.notify = lambda msg, **kw: notes.append((str(msg), kw.get("severity")))
        await focus(pilot, "#filter")
        screen.query_one("#filter", Input).value = "~m GET"
        await pilot.press("enter")
        await settle(pilot)
        assert any("~m" in m and sev == "error" for m, sev in notes), notes


async def test_ws_messages_filter_hints_are_surfaced():
    """`&` parses as a payload regex rather than failing, so the gateway's advisory hint is
    the only thing that says the filter does not mean what it looks like."""
    app = make_app()
    notes = []
    async with app.run_test() as pilot:
        await _open_ws_timeline(pilot)
        screen = app.screen
        screen.notify = lambda msg, **kw: notes.append((str(msg), kw.get("severity")))
        await focus(pilot, "#filter")
        screen.query_one("#filter", Input).value = "~op text & subscribe"
        await pilot.press("enter")
        await settle(pilot)
        assert any("not an operator" in m and sev == "warning" for m, sev in notes), notes


async def test_ws_messages_annotating_under_a_filter_requeries():
    """The viewer no longer holds the predicate, so an annotation that could move a frame
    out of a filtered view is answered by re-running the query (ADR-0012 §7)."""
    app = make_app()
    async with app.run_test() as pilot:
        await _open_ws_timeline(pilot)
        screen = app.screen
        await focus(pilot, "#filter")
        screen.query_one("#filter", Input).value = "~op text"
        await pilot.press("enter")
        await settle(pilot)
        before = app.client.msg_streams

        await focus(pilot, "#msgs")
        await pilot.press("m")        # mark → color prompt
        await settle(pilot)
        await pilot.press("enter")
        await settle(pilot)
        assert app.client.msg_streams > before, "the filtered timeline was not re-queried"


async def test_quit_asks_for_confirmation():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        # `q` opens the confirm dialog instead of quitting outright.
        await pilot.press("q")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        # Declining returns to the app, still running.
        await pilot.press("n")
        await pilot.pause()
        assert isinstance(app.screen, SessionsScreen)
        assert app.is_running
        # Confirming actually exits.
        await pilot.press("q")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
    assert app.return_code == 0


async def _open_flows(pilot):
    await settle(pilot)
    await focus(pilot, "#sessions")
    await pilot.press("enter")
    await settle(pilot)
    await focus(pilot, "#flows")
    return pilot.app.screen.query_one("#flows", DataTable)


async def test_flow_list_jump_and_page_keys():
    app = make_app()
    async with app.run_test() as pilot:
        table = await _open_flows(pilot)
        assert table.row_count == 3 and table.cursor_coordinate.row == 0

        assert isinstance(table, screens.NavDataTable)

        for key, want in [("end", 2), ("home", 0), ("ctrl+down", 2), ("ctrl+up", 0)]:
            await pilot.press(key)
            await pilot.pause()
            assert table.cursor_coordinate.row == want, f"{key} -> {table.cursor_coordinate.row}, want {want}"

        # page down/up move the cursor (inherited) and still work under the subclass
        await pilot.press("pagedown")
        await pilot.pause()
        assert table.cursor_coordinate.row > 0
        await pilot.press("pageup")
        await pilot.pause()
        assert table.cursor_coordinate.row == 0


class _NavTableApp(App):
    """Bare host for a NavDataTable, so paging can be asserted against a viewport small
    enough that one page is short of the whole list."""

    def compose(self) -> ComposeResult:
        table = screens.NavDataTable(id="rows", cursor_type="row")
        table.add_column("n")
        for i in range(50):
            table.add_row(str(i))
        yield table


async def test_nav_table_cmd_arrows_page():
    """Cmd+Up/Down page the cursor, matching PageUp/PageDown — a Mac keyboard has no
    PageUp/PageDown key of its own. They must page, not jump to the first/last row."""
    app = _NavTableApp()
    async with app.run_test(size=(40, 12)) as pilot:
        table = app.query_one("#rows", screens.NavDataTable)
        await pilot.pause()

        await pilot.press("pagedown")
        await pilot.pause()
        want = table.cursor_coordinate.row
        assert 0 < want < 49, f"pagedown landed on row {want}; the list should be longer than a page"

        # ctrl+home/ctrl+end is what a macOS-style remapper (Toshy, or macOS itself)
        # substitutes for Cmd+↑/↓ before the app ever sees the chord.
        for down, up in [("cmd+down", "cmd+up"), ("super+down", "super+up"),
                         ("ctrl+end", "ctrl+home")]:
            table.move_cursor(row=0)
            await pilot.pause()
            await pilot.press(down)
            await pilot.pause()
            assert table.cursor_coordinate.row == want, (
                f"{down} -> row {table.cursor_coordinate.row}, want {want} (same as pagedown)")
            await pilot.press(up)
            await pilot.pause()
            assert table.cursor_coordinate.row == 0, f"{up} -> row {table.cursor_coordinate.row}, want 0"


async def test_nav_table_jump_keys_reach_first_and_last_row():
    """The list start/end jump, on every key that should reach it: Home/End (what most
    macOS terminals translate Cmd+←/→ into), Ctrl+↑/↓, and Cmd+←/→ delivered as real
    super+… keys by a kitty-protocol terminal."""
    app = _NavTableApp()
    async with app.run_test(size=(40, 12)) as pilot:
        table = app.query_one("#rows", screens.NavDataTable)
        await pilot.pause()
        for last, first in [("end", "home"), ("ctrl+down", "ctrl+up"),
                            ("cmd+right", "cmd+left"), ("super+right", "super+left")]:
            await pilot.press(last)
            await pilot.pause()
            assert table.cursor_coordinate.row == 49, f"{last} -> row {table.cursor_coordinate.row}, want 49"
            await pilot.press(first)
            await pilot.pause()
            assert table.cursor_coordinate.row == 0, f"{first} -> row {table.cursor_coordinate.row}, want 0"


async def test_ws_messages_jump_keys():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        # f3 (last row) is the websocket flow; select it, then open its message timeline
        await pilot.press("end")
        await pilot.pause()
        await pilot.press("M")
        await settle(pilot)
        table = pilot.app.screen.query_one("#msgs", DataTable)
        assert table.row_count == 2
        await pilot.press("end")
        await pilot.pause()
        assert table.cursor_coordinate.row == 1
        await pilot.press("home")
        await pilot.pause()
        assert table.cursor_coordinate.row == 0


async def test_flow_list_follow_mode():
    app = make_app()
    async with app.run_test() as pilot:
        table = await _open_flows(pilot)
        pane = pilot.app.screen.query_one(SessionPane)
        assert table.cursor_coordinate.row == 0

        # Arrivals come off the stream: _ingest folds them in, the flush draws them.
        def arrive(f):
            pane._ingest(f, added=True)
            pane._flush()

        # follow off (default): a new flow doesn't move the cursor
        arrive(_flow("f4", "GET", 200))
        await pilot.pause()
        assert table.cursor_coordinate.row == 0

        # Enabling follow re-reads the tail from the gateway — flows that arrived while it
        # was off were counted but deliberately not shown — then tracks arrivals.
        await pilot.press("l")
        await settle(pilot)
        assert table.follow and table.cursor_coordinate.row == table.row_count - 1
        before = table.row_count
        arrive(_flow("f5", "PUT", 200))
        await pilot.pause()
        assert table.row_count == before + 1
        assert table.cursor_coordinate.row == table.row_count - 1
        # an update to an existing row doesn't count as an arrival
        await pilot.press("home")
        await pilot.pause()
        pane._upsert(_flow("f5", "PUT", 500))
        await pilot.pause()
        assert table.cursor_coordinate.row == 0

        # toggling off stops the tracking
        await pilot.press("l")
        arrive(_flow("f6", "GET", 200))
        await pilot.pause()
        assert not table.follow and table.cursor_coordinate.row == 0


# --- paged flow table -----------------------------------------------------
#
# A big session is held whole in memory but rendered a page at a time (rendering every row
# made a 6000-flow session take minutes to open). These pin down that only a page is
# drawn, that navigation crosses page boundaries as if it were one list, and — the part
# paging must not break — that filtering still runs over every flow in the session.

BIG_SESSION_ID = "sess-big"
_BIG_FLOWS = [_flow(f"b{i:04d}", "POST" if i % 10 == 0 else "GET",
                    403 if i % 4 == 0 else 200, frame=i + 1) for i in range(420)]
_BY_SESSION[BIG_SESSION_ID] = _BIG_FLOWS


def _status(pane) -> str:
    """The pane's status line (flow counts, filter matches, page position) as text."""
    return pane.query_one("#pane-status", Label).render().plain


async def _open_big(pilot, page_size=100):
    """Open the 420-flow session in a workspace tab, with a small page size."""
    os.environ["TRAFFICDECK_PAGE_SIZE"] = str(page_size)
    try:
        pilot.app.push_screen(WorkspaceScreen(BIG_SESSION_ID, "big"))
        await settle(pilot)
    finally:
        del os.environ["TRAFFICDECK_PAGE_SIZE"]
    pane = pilot.app.screen.query_one(SessionPane)
    await focus(pilot, "#flows")
    return pane, pane.query_one("#flows", DataTable)


def test_page_size_env_is_clamped(monkeypatch):
    monkeypatch.delenv("TRAFFICDECK_PAGE_SIZE", raising=False)
    assert screens._page_size() == screens._PAGE_SIZE
    monkeypatch.setenv("TRAFFICDECK_PAGE_SIZE", "300")
    assert screens._page_size() == 300
    monkeypatch.setenv("TRAFFICDECK_PAGE_SIZE", "5")       # too small to fill a viewport
    assert screens._page_size() == 50
    monkeypatch.setenv("TRAFFICDECK_PAGE_SIZE", "999999")  # back to a repaintable size
    assert screens._page_size() == 2000
    monkeypatch.setenv("TRAFFICDECK_PAGE_SIZE", "lots")    # nonsense -> the default
    assert screens._page_size() == screens._PAGE_SIZE


async def test_big_session_holds_only_a_window():
    """The point of ADR-0012: the pane holds the rows on screen, not the session. What
    used to be 420 flows in memory is now one window, with the total coming from the
    gateway's match count."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        assert len(pane.flows) == 100          # the window, not the session
        assert table.row_count == 100
        assert pane._matched == 420            # the total is the gateway's, not len()
        assert pane._next is not None and pane._prev is None   # at the start of the list
        assert _status(pane) == "420 flows · showing 100"
        assert table.get_row_at(0)[7] == "/b0000"
        assert table.get_row_at(99)[7] == "/b0099"


async def test_cursor_walks_off_a_window_onto_the_next():
    """Paging is invisible to the cursor: ↓ past the last row fetches the next window and
    lands on its first row; ↑ past the first goes back to the previous window's last."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        table.move_cursor(row=99)
        await pilot.press("down")
        await settle(pilot)
        assert table.get_row_at(0)[7] == "/b0100"
        assert table.cursor_coordinate.row == 0

        await pilot.press("up")
        await settle(pilot)
        assert table.get_row_at(table.cursor_coordinate.row)[7] == "/b0099"


async def test_home_and_end_jump_to_the_ends_of_the_list():
    """End is a query from the end of the list rather than an index derived from a total —
    which is what lets the match count stay approximate."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await pilot.press("end")
        await settle(pilot)
        assert pane._next is None              # nothing after: this is the end
        assert table.get_row_at(table.row_count - 1)[7] == "/b0419"
        assert table.cursor_coordinate.row == table.row_count - 1

        await pilot.press("home")
        await settle(pilot)
        assert pane._prev is None
        assert table.get_row_at(0)[7] == "/b0000"
        assert table.cursor_coordinate.row == 0


async def test_page_down_turns_the_window_at_its_end():
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await pilot.press("pagedown")          # moves within the window first
        await settle(pilot)
        assert table.get_row_at(0)[7] == "/b0000" and table.cursor_coordinate.row > 0
        table.move_cursor(row=table.row_count - 1)
        await pilot.press("pagedown")          # already at the end -> next window
        await settle(pilot)
        assert table.get_row_at(0)[7] == "/b0100"
        assert table.cursor_coordinate.row == 0


async def test_filter_is_evaluated_by_the_gateway():
    """The filter matches flows that were never sent to the viewer, because it is applied
    where the session lives rather than over what happens to be in memory."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        assert table.row_count == 100          # one window of 420

        await focus(pilot, "#filter")
        pane.query_one("#filter", Input).value = "~m POST"
        await pilot.press("enter")
        await settle(pilot)

        # 42 of 420 are POSTs, spread across the session — including b0410, which was
        # never on screen. They all match and fit in one window.
        assert pane._matched == 42
        assert table.row_count == 42
        assert table.get_row_at(41)[7] == "/b0410"
        assert "42 matching" in _status(pane)

        # A filter matching more than a window still pages.
        await focus(pilot, "#filter")
        pane.query_one("#filter", Input).value = "~c 403"
        await pilot.press("enter")
        await settle(pilot)
        assert pane._matched == 105 and table.row_count == 100
        assert pane._next is not None

        # Clearing it restores the full list, back at the start.
        await focus(pilot, "#filter")
        pane.query_one("#filter", Input).value = ""
        await pilot.press("enter")
        await settle(pilot)
        assert pane._matched == 420 and pane._prev is None


async def test_paging_within_a_filtered_list():
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await focus(pilot, "#filter")
        pane.query_one("#filter", Input).value = "~c 403"
        await pilot.press("enter")
        await settle(pilot)
        await focus(pilot, "#flows")
        await pilot.press("end")               # the end of the *filtered* list
        await settle(pilot)
        # A window, not a page: the end of a 105-match list is the *last* 100 rows, not
        # the 5-row remainder page arithmetic would have produced.
        assert pane._next is None and table.row_count == 100
        assert pane._prev is not None                        # there are 5 more before it
        # Every rendered row still satisfies the filter.
        assert all(pane.flows[fid].status == 403 for fid in pane._rendered)


async def test_a_flow_from_a_later_page_opens_its_detail():
    """Row keys stay flow ids across pages, and the detail screen reads the cached flow —
    so drilling into a flow that isn't on page 1 works."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await pilot.press("end")
        await settle(pilot)
        assert pane._focused_flow_id() == "b0419"
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, FlowDetailScreen)
        assert app.screen.flow_id == "b0419"


async def test_follow_mode_tails_the_end_of_the_list():
    """Follow means "show me what's arriving". Following and jumping to the end are the
    same operation now — both are the tail of the matching set."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        assert pane._next is not None          # starting at the head of the list
        await pilot.press("l")                 # follow on
        await settle(pilot)
        assert table.follow
        assert pane._next is None              # jumped to the end
        assert table.cursor_coordinate.row == table.row_count - 1

        pane._ingest(_flow("b9999", "GET", 200), added=True)
        pane._flush()
        await settle(pilot)
        assert pane._focused_flow_id() == "b9999"


async def test_flows_arriving_off_window_do_not_repaint_it():
    """An arrival while the window sits mid-list changes the count, not the screen — and
    is not held in memory either, which is what keeps the viewer bounded."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        rendered = list(pane._rendered)
        assert not pane._at_end                # showing the head of a 420-flow session

        for i in range(50):
            pane._ingest(_flow(f"z{i:04d}", "GET", 200))
        pane._flush()
        await settle(pilot)

        assert pane._matched == 470            # counted…
        assert len(pane.flows) == 100          # …but not retained
        assert pane._rendered == rendered      # …and the window is untouched
        assert table.row_count == 100


async def test_closed_session_shows_no_phantom_stopwatch():
    """Opening a *closed* session must not paint a duration stopwatch on its response-less
    flows. The pane used to assume live until the flow stream ended, so backfill rendered a
    ⏱ counter that ticked for ~0.5s and then vanished. f3 is the response-less flow."""
    app = make_app()
    async with app.run_test() as pilot:
        table = await _open_flows(pilot)
        pane = pilot.app.screen.query_one(SessionPane)
        assert not pane._live and pane._dur_timer is None
        assert table.get_cell("f3", pane._dur_col).plain == ""


async def test_open_session_still_ticks_in_flight_requests():
    """The converse: a session the catalog reports as open does get the live stopwatch."""
    app = make_app()
    app.client._sessions[0].status = 1  # SESSION_STATUS_OPEN
    app.client.hold_flows = True        # ...and its flow stream stays open
    async with app.run_test() as pilot:
        table = await _open_flows(pilot)
        pane = pilot.app.screen.query_one(SessionPane)
        assert pane._live and pane._dur_timer is not None
        assert table.get_cell("f3", pane._dur_col).plain.startswith("⏱")


async def test_flags_column_widens_when_a_row_is_annotated():
    """Annotating an already-listed flow must widen the flags column. Column widths are
    measured when rows are added, so in a session that opens with nothing annotated — as
    every live session does — the column sits at width 0 under its empty header and an
    in-place update that doesn't resize leaves the ★/●/#N invisible. (The _FLOWS fixture
    has a WebSocket flow whose ⇅2 already gives the column width 3, so this asserts growth
    from a baseline rather than from 0; the WS test below covers the true zero-width case.)"""
    app = make_app()
    async with app.run_test() as pilot:
        table = await _open_flows(pilot)
        pane = pilot.app.screen.query_one(SessionPane)
        flags_col = table.columns[pane._cols[0]]

        # A row already in the window, with an empty flags cell. Not a newly arrived flow:
        # with follow off, arrivals are counted but deliberately not added to the window.
        f = _flow("f1", "GET", 200)
        pane._upsert(f)
        await pilot.pause()
        before = flags_col.content_width

        f.favorite = True                # ...then annotated in place
        f.mark_color = "red"
        f.comments.append(cp.Comment(id="c1", body="hi"))
        pane._upsert(f)
        await pilot.pause()
        assert flags_col.content_width > before


async def test_ws_flags_column_widens_when_a_message_is_annotated():
    """Same for the message timeline — it was only visible after leaving and re-entering
    the screen, which rebuilds the rows and so re-measures the column."""
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        await pilot.press("end")   # f3 (last row) is the websocket flow
        await pilot.pause()
        await pilot.press("M")
        await settle(pilot)
        screen = pilot.app.screen
        table = screen.query_one("#msgs", DataTable)
        flags_col = table.columns[screen._cols[0]]
        assert flags_col.content_width == 0

        m = screen._msgs["m1"]
        m.mark_color = "red"
        screen._upsert_msg(m)
        await pilot.pause()
        assert flags_col.content_width > 0


async def test_ws_messages_follow_mode():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        await pilot.press("end")   # f3 (last row) is the websocket flow
        await pilot.pause()
        await pilot.press("M")
        await settle(pilot)
        screen = pilot.app.screen
        assert isinstance(screen, WsMessagesScreen)
        table = screen.query_one("#msgs", DataTable)
        assert table.cursor_coordinate.row == 0

        await pilot.press("l")     # enable follow: jump to the newest frame
        await pilot.pause()
        assert table.follow and table.cursor_coordinate.row == 1
        screen._upsert_msg(cp.WsMessage(
            id="m3", flow_id="f3", from_client=True, opcode="text", ts_unix_micros=4))
        await pilot.pause()
        assert table.cursor_coordinate.row == 2

        await pilot.press("l")     # disable: new frames no longer move the cursor
        await pilot.pause()
        screen._upsert_msg(cp.WsMessage(
            id="m4", flow_id="f3", from_client=False, opcode="text", ts_unix_micros=5))
        await pilot.pause()
        assert table.cursor_coordinate.row == 2


async def _open_workspace(pilot):
    await settle(pilot)
    await focus(pilot, "#sessions")
    await pilot.press("enter")          # open sess-1 in the workspace
    await settle(pilot)
    return pilot.app.screen             # WorkspaceScreen


async def test_open_multiple_session_tabs():
    app = make_app()
    async with app.run_test() as pilot:
        ws = await _open_workspace(pilot)
        assert isinstance(ws, WorkspaceScreen)
        assert len(ws.query(TabPane)) == 1

        await pilot.press("o")           # open-session picker (lists both sessions)
        await settle(pilot)
        await pilot.press("down")        # highlight sess-2
        await pilot.press("enter")       # open it as a second tab
        await settle(pilot)

        assert len(ws.query(SessionPane)) == 2
        assert ws._active_pane().session_id == SESSION_ID2  # new tab is active

        await pilot.press("[")  # switch to the first tab
        await settle(pilot)
        assert ws._active_pane().session_id == SESSION_ID

        await pilot.press("w")            # close the focused tab
        await settle(pilot)
        assert len(ws.query(SessionPane)) == 1


async def test_compare_requests_across_tabs():
    app = make_app()
    async with app.run_test() as pilot:
        ws = await _open_workspace(pilot)
        await pilot.press("o")
        await settle(pilot)
        await pilot.press("down")
        await pilot.press("enter")        # second tab (sess-2), active + focused
        await settle(pilot)

        await pilot.press("c")            # mark request A in sess-2 (its first flow)
        assert app.compare_a == (SESSION_ID2, "g1")

        await pilot.press("[")  # back to sess-1
        await settle(pilot)
        await pilot.press("c")            # compare against sess-1's focused flow
        await settle(pilot)
        assert isinstance(app.screen, CompareScreen)
        assert app.compare_a is None      # consumed by the compare


async def test_capture_reaches_wizard_through_source_picker():
    """With more than one source, starting a capture shows the source picker, then the
    wizard. Closing the picker briefly re-shows the sessions list, which auto-refreshes
    (on_screen_resume); that refresh must not cancel the in-flight capture worker — if it
    shares its worker group, the wizard never appears (the reported "nothing happens")."""
    app = make_app()
    app.client.capture_sources = [
        cp2.CaptureSourceInfo(name="chrome", label="Chrome"),
        cp2.CaptureSourceInfo(name="android", label="Android"),
    ]
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("a")            # new capture → the source picker (2 sources)
        await settle(pilot)
        assert isinstance(app.screen, SelectPrompt)

        await pilot.press("enter")        # pick the highlighted source (chrome)
        await settle(pilot)
        # The picker closed → sessions list resumed + refreshed; the capture must survive it.
        assert isinstance(app.screen, CaptureWizardScreen)


async def test_new_capture_wizard_walks_steps_and_starts():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("a")            # new capture; single source → straight to the wizard
        await settle(pilot)
        assert isinstance(app.screen, CaptureWizardScreen)
        wiz = app.screen
        assert app.client.describe_calls[0] == ("chrome", {})   # step 1 describes empty params
        # Step 1 is the "mode" choice (an OptionList of its options); "profile" isn't asked yet.
        assert wiz._current.key == "mode"
        assert app.screen.query_one("#wizard-choice", OptionList) is not None

        await pilot.press("enter")        # pick the highlighted mode (fast) → re-describe
        await settle(pilot)
        # The cascade: choosing mode makes the dependent "profile" step appear next.
        assert ("chrome", {"mode": "fast"}) in app.client.describe_calls
        assert wiz._current.key == "profile"

        await pilot.press("enter")        # accept the profile input default ("p1")
        await settle(pilot)
        # No params left → the final label step (an Input, not a param).
        assert wiz._current is None
        assert app.screen.query_one("#wizard-label", Input) is not None

        await pilot.press("enter")        # accept the label default and start
        await settle(pilot)
        assert app.client.started == [("chrome", "chrome", {"mode": "fast", "profile": "p1"})]


async def test_capture_wizard_back_re_asks_previous_step():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("a")
        await settle(pilot)
        wiz = app.screen
        await pilot.press("enter")        # answer mode → advance to profile
        await settle(pilot)
        assert wiz._current.key == "profile"

        await pilot.press("ctrl+b")       # back → mode is re-asked, its answer dropped
        await settle(pilot)
        assert wiz._current.key == "mode"
        assert "mode" not in wiz._params


async def test_new_capture_multiple_sources_prompts_first():
    app = make_app()
    app.client.capture_sources = [
        cp2.CaptureSourceInfo(name="chrome", label="Chrome"),
        cp2.CaptureSourceInfo(name="android", label="Android"),
    ]
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("a")
        await settle(pilot)
        # Two sources → a source picker first (not straight to the wizard).
        assert not isinstance(app.screen, CaptureWizardScreen)
        assert app.screen.query_one(OptionList) is not None


async def test_capture_wizard_provision_step_then_continues():
    # A persistent source (android): the wizard shows the provision step under
    # PROVISION_REQUIRED, and consenting re-describes into the real options.
    app = make_app()
    app.client.capture_sources = [cp2.CaptureSourceInfo(name="android", label="Android")]
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("a")
        await settle(pilot)
        wiz = app.screen
        assert isinstance(wiz, CaptureWizardScreen)
        assert wiz._current.key == "provision"            # provision consent first
        assert "set up the device" in app.screen.query_one("#wizard-msg", Static).render().plain

        await pilot.press("enter")                        # consent → provisioning starts
        await settle(pilot)
        assert ("android", {"provision": "start"}) in app.client.describe_calls
        # While provisioning the wizard is on no param step (showing progress), not frozen —
        # the 2s poll hasn't fired yet.
        assert wiz._current is None

        # The poll re-checks and, once provisioning finishes, advances to the package step.
        wiz._advance()                                    # simulate the poll firing
        await settle(pilot, n=15)
        assert wiz._current is not None and wiz._current.key == "package"


async def test_capture_wizard_cancel_starts_nothing():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("a")
        await settle(pilot)
        await pilot.press("escape")       # cancel the wizard
        await settle(pilot)
        assert app.client.started == []
        assert isinstance(app.screen, SessionsScreen)


async def test_stop_capture_calls_client():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("s")            # stop the focused (first) session
        await settle(pilot)
        assert app.client.stopped == [SESSION_ID]


async def test_toggle_mcp_starts_then_stops():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        assert app.client.mcp_running is False
        await pilot.press("X")            # start MCP
        await settle(pilot)
        assert app.client.mcp_running is True
        await pilot.press("X")            # stop it
        await settle(pilot)
        assert app.client.mcp_running is False


async def test_following_appends_rows_without_rebuilding_the_table():
    """Following slides the window by one flow at a time. Rebuilding it — clear plus
    re-add every row — resets the scroll to the top on each arrival, so the table jumps to
    the first row and is then dragged back to the last. Only the changed rows may move."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await focus(pilot, "#flows")
        await pilot.press("l")                 # follow on -> jump to the end
        await settle(pilot)
        assert table.follow and pane._at_end

        cleared = []
        original = table.clear
        table.clear = lambda *a, **k: (cleared.append(1), original(*a, **k))[1]

        before = table.row_count
        for i in range(5):
            pane._ingest(_flow(f"live{i}", "GET", 200, frame=9000 + i))
        pane._flush()
        await settle(pilot)

        assert not cleared, "the table was rebuilt; following must only add and remove rows"
        assert table.row_count == before        # window slid: 5 in, 5 out
        # The newest flow is the last row, and the cursor is on it.
        assert pane._order[-1] == "live4"
        assert table.cursor_coordinate.row == table.row_count - 1


async def test_disabling_follow_stops_the_window_moving():
    """Follow is what makes the window move. With it off the window is a fixed place the
    user is reading, and arrivals must not pull rows out from under the cursor."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await focus(pilot, "#flows")
        await pilot.press("l")                  # follow on
        await settle(pilot)
        assert table.follow

        await pilot.press("l")                  # follow off again
        await settle(pilot)
        assert not table.follow

        table.move_cursor(row=10)
        focused = pane._focused_flow_id()
        rendered = list(pane._rendered)
        matched = pane._matched

        for i in range(5):
            pane._ingest(_flow(f"late{i}", "GET", 200, frame=9500 + i))
        pane._flush()
        await settle(pilot)

        assert pane._rendered == rendered, "the window moved while follow was off"
        assert pane._focused_flow_id() == focused, "the cursor was pulled off its row"
        assert pane._matched == matched + 5, "arrivals should still be counted"


async def test_updates_to_flows_off_the_window_are_not_counted_as_arrivals():
    """The count follows arrivals, and the pane holds only the window — so a flow that
    slid off it is absent from pane.flows while still being in the count. Reading that
    absence as "new" counted every later update to an off-window flow again, and a live
    WebSocket flow republishes once per frame: the total on top of the table ran away
    from the real one until the pane was closed and reopened."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await focus(pilot, "#flows")
        await pilot.press("l")                       # follow on -> tail the list
        await settle(pilot)

        for i in range(5):
            pane._ingest(_flow(f"ws{i}", "GET", 200, frame=9000 + i), added=True)
        pane._flush()
        await settle(pilot)
        matched, rendered = pane._matched, list(pane._rendered)
        assert matched == 425

        gone = _BIG_FLOWS[0].id            # dropped off the front of the window long ago
        assert gone not in pane.flows
        for _ in range(20):                # both keep publishing: frames, a late response
            pane._ingest(_flow(gone, "GET", 200, frame=1), added=False)
            pane._ingest(_flow("ws0", "GET", 200, websocket=True, frame=9000), added=False)
        pane._flush()
        await settle(pilot)

        assert pane._matched == matched, "updates were counted as new flows"
        assert pane._rendered == rendered, "an off-window update was put in the window"
        assert _status(pane).startswith("425 flows")


async def test_an_arrival_behind_the_window_is_counted_exactly_once():
    """The same flow seen as an arrival and then updated, while the window sits somewhere
    else in the list: one flow, one increment, however many times it republishes."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)   # window at the start of a 420-flow list
        assert not pane._at_end
        matched, rendered = pane._matched, list(pane._rendered)

        pane._ingest(_flow("new1", "GET", 0, frame=9000), added=True)   # request published
        for _ in range(3):                     # the response lands, then WebSocket frames
            pane._ingest(_flow("new1", "GET", 200, websocket=True, frame=9000), added=False)
        pane._flush()
        await settle(pilot)

        assert pane._matched == matched + 1
        assert "new1" not in pane.flows        # off-window: it waits to be paged to
        assert pane._rendered == rendered


async def test_a_response_arriving_updates_the_row_in_place():
    """A live flow is published request-first and updated when its response lands. The
    window does not change, so the row has to be redrawn explicitly — otherwise the table
    keeps showing an empty status for a flow that has one."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await focus(pilot, "#flows")
        await pilot.press("l")                       # follow on
        await settle(pilot)

        pending = _flow("live1", "GET", 0, frame=9800)   # no response yet
        pane._ingest(pending)
        pane._flush()
        await settle(pilot)
        assert "live1" in pane._rows
        assert "200" not in str(table.get_row("live1")[3])

        answered = _flow("live1", "GET", 200, frame=9800)  # same flow, now answered
        pane._ingest(answered)
        pane._flush()
        await settle(pilot)
        assert "200" in str(table.get_row("live1")[3]), (
            "the row still shows no status after its response arrived"
        )


# A capture opened before it has recorded anything — the normal way a live session is
# watched: start the capture, open it, wait for traffic.
EMPTY_SESSION_ID = "sess-empty"
_BY_SESSION[EMPTY_SESSION_ID] = []

# A session with exactly the smallest page size worth of flows, so it can be opened both
# as a window with room left (a bigger page) and as a full one (a page its own size).
FULL_SESSION_ID = "sess-full"
_PAGE_MIN = 50
_BY_SESSION[FULL_SESSION_ID] = [_flow(f"p{i:03d}", "GET", 200, frame=i + 1)
                                for i in range(_PAGE_MIN)]


async def _open_live(pilot, session_id, page_size=100):
    """Open a still-capturing session in a workspace tab, with a small page size."""
    pilot.app.client.hold_flows = True   # the stream stays open, as a live session's does
    os.environ["TRAFFICDECK_PAGE_SIZE"] = str(page_size)
    try:
        pilot.app.push_screen(WorkspaceScreen(session_id, "live", live=True))
        await settle(pilot)
    finally:
        del os.environ["TRAFFICDECK_PAGE_SIZE"]
    pane = pilot.app.screen.query_one(SessionPane)
    await focus(pilot, "#flows")
    return pane, pane.query_one("#flows", DataTable)


async def test_flows_arriving_into_an_empty_window_are_shown():
    """A session opened while it still has nothing in it must start filling as flows
    arrive. Follow is off by default and only the follow path moved the window, so the
    first flows of a live capture were counted and never drawn — the pane sat empty until
    it was closed and reopened."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_live(pilot, EMPTY_SESSION_ID)
        assert table.row_count == 0 and not table.follow

        for i in range(3):
            pane._ingest(_flow(f"new{i}", "GET", 200, frame=100 + i))
        pane._flush()
        await settle(pilot)

        assert pane._rendered == ["new0", "new1", "new2"], "arrivals never reached the table"
        assert table.row_count == 3
        assert "3 flows" in _status(pane)


async def test_a_partly_filled_window_keeps_growing_without_follow():
    """Appending below the last row takes nothing away from the reader, so a window with
    room grows whether or not follow is on — and the cursor stays where it was put."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_live(pilot, FULL_SESSION_ID, page_size=100)
        assert table.row_count == _PAGE_MIN and len(pane._order) < pane._window
        table.move_cursor(row=5)
        focused = pane._focused_flow_id()

        pane._ingest(_flow("late1", "GET", 200, frame=900))
        pane._flush()
        await settle(pilot)

        assert pane._rendered[-1] == "late1"
        assert pane._focused_flow_id() == focused, "the cursor moved on an arrival"
        assert not table.follow


async def test_arrivals_past_a_full_window_stay_reachable():
    """Once the window is full, an arrival would push a row off the front — so with follow
    off it is only counted. The window then no longer holds the end of the list, and End
    must be able to jump to the new tail; it used to report the window as the end already
    and leave the flow unreachable."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_live(pilot, FULL_SESSION_ID, page_size=_PAGE_MIN)
        assert table.row_count == _PAGE_MIN and pane._at_end
        rendered = list(pane._rendered)

        arrival = _flow("tail1", "GET", 200, frame=900)
        _BY_SESSION[FULL_SESSION_ID].append(arrival)  # ...as the gateway now has it
        try:
            pane._ingest(arrival)
            pane._flush()
            await settle(pilot)
            assert pane._rendered == rendered, "a full window moved under the reader"
            assert not pane._at_end and pane._next is not None

            await pilot.press("end")   # jump to the end of the list
            await settle(pilot)
            assert "tail1" in pane._rows, "the new tail could not be paged to"
            assert table.cursor_coordinate.row == table.row_count - 1
        finally:
            _BY_SESSION[FULL_SESSION_ID].remove(arrival)


async def until(cond, timeout=3.0):
    """Wait for a condition the pane reaches on its own clock (a reconnect backoff, a
    worker's turn), rather than on a fixed number of pilot pauses."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if cond():
            return True
        await asyncio.sleep(0.01)
    return False


async def test_paging_away_from_the_end_turns_follow_off():
    """Follow needs both the flag and a window on the end of the list, so paging away from
    the tail stops arrivals reaching the view. Leaving the flag set left the ⇣ badge on a
    pane that silently ignored every new flow — which read as a dead capture."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await focus(pilot, "#flows")
        await pilot.press("l")                  # follow on -> pinned to the tail
        await settle(pilot)
        assert table.follow and pane._at_end

        await pilot.press("home")               # ...and away to the first page
        await settle(pilot)
        assert not pane._at_end
        assert not table.follow, "follow survived a jump off the end of the list"
        assert "follow" not in _status(pane), "the badge outlived the following"


async def test_filtering_while_following_lands_on_the_new_tail():
    """A filter applied while tailing has to tail what it matches. Loading the head of the
    new list instead left follow pinned there — and the stream's own re-query pinned it
    again on every reconnect, so the pane never moved with the capture."""
    app = make_app()
    async with app.run_test() as pilot:
        pane, table = await _open_big(pilot)
        await focus(pilot, "#flows")
        await pilot.press("l")
        await settle(pilot)
        assert table.follow

        await focus(pilot, "#filter")
        pane.query_one("#filter", Input).value = "~m GET"
        await pilot.press("enter")
        await settle(pilot)

        assert table.follow, "following did not survive the filter"
        assert pane._at_end, "the filtered window is not on the end of the list"
        assert pane._last_query[3] is True, "the stream would re-query the head on reconnect"
        # ...and it is still following: a matching arrival lands on screen.
        pane._ingest(_flow("newest", "GET", 200, frame=9999))
        pane._flush()
        await settle(pilot)
        assert pane._rendered[-1] == "newest"


async def test_a_dropped_subscription_is_reconnected():
    """A subscription can end without the capture ending — the gateway hangs up on a viewer
    that asked to follow before the source registered, and a restart or a dropped
    connection does the same. The pane used to treat that as the session closing: rows
    still loaded on demand, so paging and reopening worked while the live view was deaf
    for good. It reconnects now, and the re-query on reconnect brings in what it missed."""
    app = make_app()
    app.client.drop_streams = 50         # every subscription ends on its own, for now
    old_min, old_max = screens._RECONNECT_MIN, screens._RECONNECT_MAX
    screens._RECONNECT_MIN = screens._RECONNECT_MAX = 0.05
    try:
        async with app.run_test() as pilot:
            pane, table = await _open_live(pilot, EMPTY_SESSION_ID)
            assert await until(lambda: app.client.stream_attempts >= 2), "the pane never resubscribed"

            # A flow the gateway learned about while the pane was between subscriptions:
            # the re-query that follows a reconnect is what finds it.
            late = _flow("late1", "GET", 200, frame=500)
            _BY_SESSION[EMPTY_SESSION_ID].append(late)
            try:
                assert await until(lambda: "late1" in pane._rows), "the reconnect did not re-query"
            finally:
                _BY_SESSION[EMPTY_SESSION_ID].remove(late)

            app.client.drop_streams = 0   # ...and one of them finally sticks
            assert await until(lambda: not pane._reconnecting), "the pane never settled"
            assert pane._live and not pane._session_closed
            assert "reconnecting" not in _status(pane)
    finally:
        screens._RECONNECT_MIN, screens._RECONNECT_MAX = old_min, old_max


async def test_a_closed_session_stops_the_reconnecting():
    """The other half of reconnecting: a capture the gateway reports as over must not be
    resubscribed to, or the pane would poll a dead session for as long as it is open."""
    app = make_app()
    app.client.close_session = True
    old_min, old_max = screens._RECONNECT_MIN, screens._RECONNECT_MAX
    screens._RECONNECT_MIN = screens._RECONNECT_MAX = 0.01
    try:
        async with app.run_test() as pilot:
            pane, _ = await _open_live(pilot, EMPTY_SESSION_ID)
            assert await until(lambda: pane._session_closed)
            assert not pane._live, "the pane kept a stopwatch running on a closed capture"
            await asyncio.sleep(0.1)   # ...long enough for several reconnects
            assert app.client.stream_attempts == 1, "it resubscribed to a closed session"
    finally:
        screens._RECONNECT_MIN, screens._RECONNECT_MAX = old_min, old_max


async def test_a_pane_with_no_live_stream_says_so():
    """While it is between subscriptions the pane has no live view, and a live pane that
    says nothing about that looks exactly like a capture with no traffic — the one thing
    the user cannot tell it apart from."""
    app = make_app()
    app.client.drop_streams = 1
    old_min, old_max = screens._RECONNECT_MIN, screens._RECONNECT_MAX
    screens._RECONNECT_MIN = screens._RECONNECT_MAX = 30   # long enough to look at
    try:
        async with app.run_test() as pilot:
            pane, _ = await _open_live(pilot, EMPTY_SESSION_ID)
            assert await until(lambda: pane._reconnecting)
            assert "reconnecting" in _status(pane)
    finally:
        screens._RECONNECT_MIN, screens._RECONNECT_MAX = old_min, old_max
