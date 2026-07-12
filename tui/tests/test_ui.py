"""UI tests driving the Textual app headlessly via App.run_test()/Pilot, with an
in-memory fake gateway client so screens get deterministic data (real proto objects)
without a live gateway. They exercise navigation + data wiring; rendering/DSL logic is
covered by test_render.py / test_filters.py."""

from __future__ import annotations

from textual.widgets import DataTable, Input, OptionList, Static, TabPane

import traffic_viewer.client  # noqa: F401 — puts the generated stubs on sys.path
from traffic.v1 import common_pb2 as cp
from traffic.v1 import viewer_pb2 as vp
from traffic_viewer.app import TrafficViewerApp
from traffic_viewer.screens import (
    BodyScreen,
    ConfirmScreen,
    QuitConfirmScreen,
    FlowDetailScreen,
    SessionPane,
    WorkspaceScreen,
    SessionsScreen,
    CompareScreen,
    WsMessagesScreen,
    WsPayloadScreen,
)


# --- fixtures: canned data + fake client ----------------------------------

SESSION_ID = "sess-1"


def _session():
    return cp.Session(id=SESSION_ID, label="demo", status=3, flow_count=3,
                      pcap_bytes=1024, created_at_unix_ms=1_700_000_000_000)


def _flow(fid, method, status, websocket=False):
    f = cp.Flow(id=fid, method=method, scheme="https", authority="api.example.com",
                path="/" + fid, protocol="HTTP/2", status=status, ts_unix_micros=1)
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


_FLOWS = [_flow("f1", "GET", 200), _flow("f2", "POST", 201), _flow("f3", "", 0, websocket=True)]

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

    async def stream_flows(self, session_id, follow=False):
        for f in _BY_SESSION.get(session_id, _FLOWS):
            yield vp.FlowEvent(flow_added=f)

    async def get_flow(self, session_id, flow_id):
        for f in _BY_SESSION.get(session_id, _FLOWS):
            if f.id == flow_id:
                return f
        raise KeyError(flow_id)

    async def get_body(self, session_id, flow_id, response):
        return b'{"k":1}'

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


async def test_metadata_column_picker_toggles_column():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        pane = app.screen.query_one(SessionPane)
        table = pane.query_one("#flows", DataTable)
        base_cols = len(table.ordered_columns)
        assert pane._meta_cols == []            # nothing shown by default

        await focus(pilot, "#flows")
        await pilot.press("C")                  # open the column picker
        await settle(pilot)
        # Options are the discovered metadata keys, sorted: proxy_provider, scrape_group.
        app.screen.query_one(OptionList).highlighted = 0
        await pilot.press("enter")              # toggle proxy_provider on
        await settle(pilot)

        assert pane._meta_cols == ["proxy_provider"]
        assert len(table.ordered_columns) == base_cols + 1
        # f2 carries proxy_provider=brightdata; its row shows it in the new column.
        assert str(table.get_cell("f2", pane._meta_col_keys["proxy_provider"])) == "brightdata"

        # Toggling the same key again removes the column.
        await pilot.press("C")
        await settle(pilot)
        app.screen.query_one(OptionList).highlighted = 0
        await pilot.press("enter")
        await settle(pilot)
        assert pane._meta_cols == []
        assert len(table.ordered_columns) == base_cols


async def test_source_declared_columns_seed_table():
    # A capture source declaring viewer.columns seeds the pane's default columns.
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(WorkspaceScreen(SESSION_ID, "demo", source_columns=["proxy_provider"]))
        await settle(pilot)
        pane = app.screen.query_one(SessionPane)
        assert pane._meta_cols == ["proxy_provider"]
        table = pane.query_one("#flows", DataTable)
        assert str(table.get_cell("f2", pane._meta_col_keys["proxy_provider"])) == "brightdata"


def test_resolve_meta_columns_unions_env_and_source(monkeypatch):
    from traffic_viewer.screens import _resolve_meta_columns, _session_view_columns

    monkeypatch.setenv("TRAFFICDECK_META_COLUMNS", "region, proxy_provider")
    # env first, then source-declared, de-duplicated and order-preserving.
    assert _resolve_meta_columns(["proxy_provider", "scrape_group"]) == \
        ["region", "proxy_provider", "scrape_group"]

    s = cp.Session(id="s1")
    s.metadata["viewer.columns"] = "scrape_group, proxy_provider"
    assert _session_view_columns(s) == ["scrape_group", "proxy_provider"]
    assert _session_view_columns(cp.Session(id="s2")) == []


async def test_metadata_column_from_env(monkeypatch):
    monkeypatch.setenv("TRAFFICDECK_META_COLUMNS", "proxy_provider")
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        pane = app.screen.query_one(SessionPane)
        assert pane._meta_cols == ["proxy_provider"]
        table = pane.query_one("#flows", DataTable)
        assert str(table.get_cell("f2", pane._meta_col_keys["proxy_provider"])) == "brightdata"


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


async def test_body_view_renders_small_body_inline():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        app.push_screen(BodyScreen(SESSION_ID, "f1", "application/json", False, "f1"))
        await settle(pilot)
        assert isinstance(app.screen, BodyScreen)
        rendered = app.screen.query_one("#pbody", Static).render()
        assert '"k"' in rendered.plain  # JSON pretty-printed inline, not handed off


async def test_body_view_opens_editor_for_large_body(monkeypatch):
    opened = []
    monkeypatch.setattr(BodyScreen, "_open_external", lambda self: opened.append(self._label))
    big = b"x" * (BodyScreen._VIEW_LIMIT + 10)

    async def big_body(session_id, flow_id, response):
        return big

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
