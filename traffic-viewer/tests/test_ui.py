"""UI tests driving the Textual app headlessly via App.run_test()/Pilot, with an
in-memory fake gateway client so screens get deterministic data (real proto objects)
without a live gateway. They exercise navigation + data wiring; rendering/DSL logic is
covered by test_render.py / test_filters.py."""

from __future__ import annotations

from textual.widgets import DataTable, Input

import traffic_viewer.client  # noqa: F401 — puts the generated stubs on sys.path
from traffic.v1 import common_pb2 as cp
from traffic.v1 import viewer_pb2 as vp
from traffic_viewer.app import TrafficViewerApp
from traffic_viewer.screens import (
    FlowDetailScreen,
    FlowsScreen,
    SessionsScreen,
    WsMessagesScreen,
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


def _ws_messages():
    return [
        cp.WsMessage(id="m1", flow_id="f3", from_client=True, opcode="text", ts_unix_micros=2),
        cp.WsMessage(id="m2", flow_id="f3", from_client=False, opcode="binary", ts_unix_micros=3),
    ]


class FakeClient:
    """Implements the async surface the screens call, served from memory."""

    async def list_sessions(self, limit=200):
        return [_session()]

    async def stream_flows(self, session_id, follow=False):
        for f in _FLOWS:
            yield vp.FlowEvent(flow_added=f)

    async def get_flow(self, session_id, flow_id):
        for f in _FLOWS:
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
        assert table.row_count == 1


async def test_drill_session_to_flows():
    app = make_app()
    async with app.run_test() as pilot:
        await settle(pilot)
        await focus(pilot, "#sessions")
        await pilot.press("enter")  # open the focused session
        await settle(pilot)
        assert isinstance(app.screen, FlowsScreen)
        assert app.screen.session_id == SESSION_ID
        assert app.screen.query_one("#flows", DataTable).row_count == len(_FLOWS)


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
