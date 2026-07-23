"""UI tests driving the Textual app headlessly via App.run_test()/Pilot, with an
in-memory fake gateway client so screens get deterministic data (real proto objects)
without a live gateway. They exercise navigation + data wiring; rendering/DSL logic is
covered by test_render.py / test_filters.py."""

from __future__ import annotations

import asyncio

from textual.widgets import DataTable, Input, OptionList, Static, TabPane

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


def _flow(fid, method, status, websocket=False, tcp_stream="", h2_stream_id=""):
    f = cp.Flow(id=fid, method=method, scheme="https", authority="api.example.com",
                path="/" + fid, protocol="HTTP/2", status=status, ts_unix_micros=1,
                tcp_stream=tcp_stream, h2_stream_id=h2_stream_id, frame_number=204,
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
        cp.WsMessage(id="m1", flow_id="f3", from_client=True, opcode="text", ts_unix_micros=2),
        cp.WsMessage(id="m2", flow_id="f3", from_client=False, opcode="binary", ts_unix_micros=3),
    ]


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

    async def stream_flows(self, session_id, follow=False):
        for f in _BY_SESSION.get(session_id, _FLOWS):
            yield vp.FlowEvent(flow_added=f)
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

    async def stream_messages(self, session_id, flow_id, follow=True):
        for m in _ws_messages():
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

        for key, want in [("end", 2), ("home", 0), ("ctrl+down", 2), ("ctrl+up", 0),
                          ("cmd+down", 2), ("cmd+up", 0)]:
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

        # follow off (default): a new flow doesn't move the cursor
        pane._upsert(_flow("f4", "GET", 200))
        await pilot.pause()
        assert table.cursor_coordinate.row == 0

        # enabling follow jumps to the newest row and tracks arrivals
        await pilot.press("l")
        await pilot.pause()
        assert table.follow and table.cursor_coordinate.row == 3
        pane._upsert(_flow("f5", "PUT", 200))
        await pilot.pause()
        assert table.cursor_coordinate.row == 4
        # an update to an existing row doesn't count as an arrival
        await pilot.press("home")
        await pilot.pause()
        pane._upsert(_flow("f5", "PUT", 500))
        await pilot.pause()
        assert table.cursor_coordinate.row == 0

        # toggling off stops the tracking
        await pilot.press("l")
        pane._upsert(_flow("f6", "GET", 200))
        await pilot.pause()
        assert not table.follow and table.cursor_coordinate.row == 0


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

        f = _flow("f4", "GET", 200)      # listed with an empty flags cell
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
