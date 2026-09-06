"""A live pane must fold a flow that arrives on the stream (flow_added) into the table
without the user reopening the session — the incremental-live path the FakeClient's other
tests never exercise (they only cover the re-query-on-OPEN path).

This complements the gateway-side fix in query.go (mergeUnflushed no longer hands back a
Next cursor when the merged tail already reaches the end of the list): that spurious cursor
made the pane believe it was off the end and drop every live arrival, which is the
"table doesn't update until I reopen" bug.
"""

from __future__ import annotations

import asyncio

from textual.widgets import DataTable

import traffic_viewer.client  # noqa: F401 — puts the generated stubs on sys.path
from traffic.v1 import common_pb2 as cp
from traffic.v1 import viewer_pb2 as vp
from traffic_viewer.screens import SessionPane, WorkspaceScreen

from test_ui import FakeClient, make_app, settle, _flow, _BY_SESSION

LIVE_ID = "live-append-sess"


class LiveFakeClient(FakeClient):
    """A follow subscription that stays open and lets the test inject flow_added events
    after it has marked the subscription live — the real gateway's incremental path.

    Its query_flows honours the cursor contract (a Next only when rows remain that way),
    so a full-fit page leaves the pane at the end and eligible to fold in live arrivals."""

    def __init__(self):
        super().__init__()
        self._rows = [_flow("a1", "GET", 200, frame=1)]
        self._sessions = [cp.Session(id=LIVE_ID, label="live", status=1, flow_count=1,
                                     pcap_bytes=0, created_at_unix_ms=1_700_000_000_000)]
        self._inject: asyncio.Queue = asyncio.Queue()

    async def query_flows(self, session_id, filter_expr="", limit=250,
                          after=None, before=None, last=False):
        # The whole (tiny) session fits one page: no cursors, so the pane is at the end.
        return vp.FlowPage(flows=list(self._rows), matched=len(self._rows))

    async def stream_flows(self, session_id, follow=False, filter_expr=""):
        if not follow:
            for f in self._rows:
                yield vp.FlowEvent(flow_added=f)
            return
        yield vp.FlowEvent(session_event=vp.SessionEvent(session_id=session_id, status=1))
        while True:
            f = await self._inject.get()
            yield vp.FlowEvent(flow_added=f)


async def test_live_flow_added_renders_without_reopen():
    app = make_app()
    app.client = LiveFakeClient()
    try:
        async with app.run_test() as pilot:
            await settle(pilot)
            app.push_screen(WorkspaceScreen(LIVE_ID, "live", live=True))
            await settle(pilot, 12)

            pane = app.screen.query_one(SessionPane)
            table = pane.query_one("#flows", DataTable)
            assert table.row_count == 1, "the initial flow should be shown"

            # A new request is captured while the pane is open (follow off).
            new = _flow("a2", "GET", 200, frame=2)
            app.client._rows.append(new)          # a re-query would find it too
            await app.client._inject.put(new)     # deliver it live via the stream
            await settle(pilot, 12)

            assert table.row_count == 2, "a live-arriving flow must appear without reopening"
    finally:
        _BY_SESSION.pop(LIVE_ID, None)
