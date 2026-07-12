"""UI tests driving the Textual app headlessly via App.run_test()/Pilot, with an
in-memory fake gateway client so screens get deterministic data (real proto objects)
without a live gateway. They exercise navigation + data wiring; rendering/DSL logic is
covered by test_render.py / test_filters.py."""

from __future__ import annotations

from textual.widgets import DataTable, Input, Static, TabPane

import traffic_viewer.client  # noqa: F401 — puts the generated stubs on sys.path
from traffic.v1 import common_pb2 as cp
from traffic.v1 import viewer_pb2 as vp
from traffic_viewer.app import TrafficViewerApp
from traffic_viewer.screens import (
    BodyScreen,
    ConfirmScreen,
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

    async def list_sessions(self, limit=200):
        return list(self._sessions)

    async def delete_session(self, session_id):
        self._sessions = [s for s in self._sessions if s.id != session_id]

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

    async def get_message_body(self, session_id, message_id):
        return b"hello"

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
        screen._add_message(cp.WsMessage(
            id="m3", flow_id="f3", from_client=True, opcode="text", ts_unix_micros=4))
        await pilot.pause()
        assert table.cursor_coordinate.row == 2

        await pilot.press("l")     # disable: new frames no longer move the cursor
        await pilot.pause()
        screen._add_message(cp.WsMessage(
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
