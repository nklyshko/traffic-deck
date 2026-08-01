"""Unit tests for the MCP server's pure (non-RPC) logic: structured-search matching,
timeline rows, and body/payload serialization. Real protobuf Flow/Body messages are
built from the generated stubs, so these exercise the same objects the tools see."""

from __future__ import annotations

# Importing the server wires the generated `gen/` tree onto sys.path (via client.py),
# so `traffic.v1.*` resolves afterwards.
import grpc
import pytest
import traffic_mcp.server as S
from traffic.v1 import common_pb2 as cp
from traffic.v1 import viewer_pb2 as vp


def _flow(**kw):
    return cp.Flow(**kw)


# --- read-only mode -------------------------------------------------------

def test_env_flag_defaults_and_off_values(monkeypatch):
    monkeypatch.delenv("MCP_READONLY", raising=False)
    assert S._env_flag("MCP_READONLY", True) is True     # unset -> default
    assert S._env_flag("MCP_READONLY", False) is False
    for off in ("0", "false", "FALSE", "no", "off", "", "  Off "):
        monkeypatch.setenv("MCP_READONLY", off)
        assert S._env_flag("MCP_READONLY", True) is False
    for on in ("1", "true", "yes", "on"):
        monkeypatch.setenv("MCP_READONLY", on)
        assert S._env_flag("MCP_READONLY", False) is True


def test_write_tools_hidden_in_readonly_mode():
    # Read-only is the default, so the mutating tools are not registered while the
    # read-only inspection tools are. (Registration happens at import against S.READONLY.)
    import asyncio

    names = {t.name for t in asyncio.run(S.mcp.list_tools())}
    assert S.READONLY is True
    assert "list_sessions" in names and "get_flow" in names
    assert "rename_session" not in names
    assert "set_session_group" not in names


# --- argument validation --------------------------------------------------

def test_unknown_tool_argument_is_rejected_not_ignored():
    # An invented parameter must not be dropped: `status_code=403` used to sail through as
    # an *unfiltered* search, so the caller got 200s back while believing they had asked
    # for 403s. It has to fail, and the failure has to name the real parameters.
    import asyncio

    with pytest.raises(Exception) as e:
        asyncio.run(S.mcp.call_tool("search", {"session_id": "abc", "status_code": 403}))
    msg = str(e.value)
    assert "status_code" in msg and "status_in" in msg

    # Every tool's published schema closes the door too, so a strict client catches it
    # before the call.
    tools = asyncio.run(S.mcp.list_tools())
    assert all(t.inputSchema.get("additionalProperties") is False for t in tools)


# --- search matching ------------------------------------------------------

CRIT0 = dict(domain="", method="", content_type="", status=0, path_contains="",
             url_contains="", websocket=None, has_response=None)


def crit(**over):
    return {**CRIT0, **over}


def test_search_combined_domain_method_content_type():
    f = _flow(method="POST", authority="api.oneme.ru", path="/x", scheme="https",
              status=200, content_type="application/json; charset=utf-8")
    # All three criteria match (domain/content-type substring, method exact-ci).
    assert S._matches(f, **crit(domain="oneme.ru", method="post", content_type="json"))
    # One mismatch fails the AND.
    assert not S._matches(f, **crit(domain="oneme.ru", method="GET"))
    assert not S._matches(f, **crit(content_type="xml"))


def test_search_status_and_tristate():
    f = _flow(authority="h", status=0, websocket=True)
    assert S._matches(f, **crit(status=0))            # 0 == any
    assert not S._matches(f, **crit(status=200))
    assert S._matches(f, **crit(websocket=True))
    assert not S._matches(f, **crit(websocket=False))
    assert S._matches(f, **crit(has_response=False))  # no status => no response
    assert not S._matches(f, **crit(has_response=True))


def test_search_path_and_url_substring():
    f = _flow(scheme="https", authority="api.oneme.ru", path="/v3/items", query="a=1")
    assert S._matches(f, **crit(path_contains="/v3"))
    assert S._matches(f, **crit(url_contains="oneme.ru/v3/items?a=1"))
    assert not S._matches(f, **crit(path_contains="/v4"))


# --- status sets ----------------------------------------------------------

def test_parse_status_set_codes_ranges_classes():
    assert S._parse_status_set("") is None
    assert S._parse_status_set("   ") is None
    assert S._parse_status_set("403") == {403}
    assert S._parse_status_set("401,403") == {401, 403}
    assert S._parse_status_set("401 403") == {401, 403}
    assert S._parse_status_set("4xx") == set(range(400, 500))
    assert S._parse_status_set("40x") == set(range(400, 410))
    assert S._parse_status_set("400-404") == {400, 401, 402, 403, 404}
    # Parts are unioned into one criterion.
    assert S._parse_status_set("4xx,500-503") == set(range(400, 500)) | {500, 501, 502, 503}


def test_parse_status_set_rejects_nonsense():
    for bad in ("4x", "xx", "40", "abc", "499-400", "4xxx"):
        try:
            S._parse_status_set(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} should not parse")


def test_search_matches_status_set():
    f403 = _flow(authority="h", status=403)
    f200 = _flow(authority="h", status=200)
    fnone = _flow(authority="h")
    codes = S._parse_status_set("401,403")
    assert S._matches(f403, **crit(status_set=codes))
    assert not S._matches(f200, **crit(status_set=codes))
    assert not S._matches(fnone, **crit(status_set=codes))  # no response, no code
    assert S._matches(f200, **crit(status_set=S._parse_status_set("2xx")))


# --- time window ----------------------------------------------------------

def test_parse_time_epoch_scales_and_empty():
    assert S._parse_time("") is None
    secs = 1_774_000_000
    assert S._parse_time(str(secs)) == secs * 1_000_000
    assert S._parse_time(str(secs * 1_000)) == secs * 1_000_000
    assert S._parse_time(str(secs * 1_000_000)) == secs * 1_000_000


def test_parse_time_iso_clock_and_relative():
    from datetime import datetime, timezone

    # An offset-bearing ISO stamp is absolute.
    assert S._parse_time("2026-07-27T06:08:00Z") == int(
        datetime(2026, 7, 27, 6, 8, tzinfo=timezone.utc).timestamp() * 1_000_000)
    # A naive stamp is local time.
    assert S._parse_time("2026-07-27T06:08") == int(
        datetime(2026, 7, 27, 6, 8).astimezone().timestamp() * 1_000_000)
    # A bare clock time means today, local.
    today = datetime.now().replace(hour=6, minute=8, second=0, microsecond=0)
    assert S._parse_time("06:08") == int(today.astimezone().timestamp() * 1_000_000)
    # A relative offset counts back from now.
    import time as _t
    now = int(_t.time() * 1_000_000)
    assert abs(S._parse_time("-15m") - (now - 15 * 60 * 1_000_000)) < 2_000_000


def test_parse_time_rejects_garbage():
    for bad in ("yesterday", "2026-13-45", "6pm"):
        try:
            S._parse_time(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} should not parse")


def test_search_time_window_bounds_are_inclusive():
    f = _flow(authority="h", ts_unix_micros=1_000_000)
    assert S._matches(f, **crit(since=1_000_000, until=1_000_000))
    assert not S._matches(f, **crit(since=1_000_001))
    assert not S._matches(f, **crit(until=999_999))
    # An unstamped flow can't be placed in time, so a window excludes it.
    unstamped = _flow(authority="h")
    assert S._matches(unstamped, **crit())
    assert not S._matches(unstamped, **crit(since=1))


# --- match previews -------------------------------------------------------

def test_snippet_context_and_miss():
    hay = "x" * 100 + "Set-Cookie: spid=abc123; Path=/" + "y" * 100
    s = S._snippet(hay, "spid=")
    assert "spid=abc123" in s
    assert s.startswith("…") and s.endswith("…")   # both ends elided
    assert len(s) < len(hay)
    assert S._snippet(hay, "nope") is None
    # Whitespace is collapsed so a preview stays one line.
    assert S._snippet("a\n\n  b needle c", "needle") == "a b needle c"


def test_url_previews_only_for_matching_criteria():
    f = _flow(scheme="https", authority="api.oneme.ru", path="/v3/items", query="a=1")
    prev = S._url_previews(f, crit(url_contains="v3/items", path_contains="/v3"))
    assert prev == {"url": "https://api.oneme.ru/v3/items?a=1", "path": "/v3/items"}
    assert S._url_previews(f, crit()) == {}


# --- timeline -------------------------------------------------------------

def test_timeline_row_relative_time():
    t0 = 1_000_000  # micros
    f = _flow(id="x", method="GET", authority="h", path="/p", query="q=1",
              status=200, content_type="text/html", protocol="HTTP/2",
              ts_unix_micros=1_500_000)
    row = S._timeline_row(3, f, t0)
    assert row["seq"] == 3
    assert row["t_ms"] == 500.0          # (1.5s - 1.0s) -> 500ms
    assert row["path"] == "/p?q=1"
    assert row["type"] == "html"


def test_timeline_row_unstamped_flow_has_null_time():
    f = _flow(id="ws", authority="h", websocket=True, ws_message_count=70,
              protocol="MAX", ts_unix_micros=0)
    row = S._timeline_row(0, f, 0)
    assert row["t_ms"] is None
    assert row["method"] == "WS"         # falls back to WS marker
    assert row["ws"] is True


# --- serialization helpers ------------------------------------------------

def test_short_type():
    assert S._short_type("application/json; charset=utf-8") == "json"
    assert S._short_type("text/html") == "html"
    assert S._short_type("") == ""


def test_body_ref_metadata_only():
    body = cp.Body(size=342, content_type="application/json", inline=b'{"a":1}')
    ref = S._body_ref(body)
    assert ref == {"content_type": "application/json", "size": 342}
    assert "inline" not in ref and "text" not in ref  # no body bytes
    assert S._body_ref(cp.Body(size=0)) is None


def test_bytes_payload_text_and_binary():
    text = S._bytes_payload(b'{"success":true}')
    assert text["encoding"] == "utf-8" and text["text"] == '{"success":true}'
    assert text["truncated"] is False
    binary = S._bytes_payload(b"\xff\xfe\x00\x01")
    assert binary["encoding"] == "base64" and "base64" in binary


def test_bytes_payload_hex_and_offset():
    data = b"\x0a\x00\x01\x02\x03\x04\x05"
    h = S._bytes_payload(data, as_hex=True)
    assert h["encoding"] == "hex" and h["hex"] == "0a000102030405"
    assert h["size"] == 7 and h["offset"] == 0 and h["returned"] == 7
    # windowed hex from an offset
    w = S._bytes_payload(data, as_hex=True, start=2)
    assert w["hex"] == "0102030405" and w["offset"] == 2 and w["size"] == 7


# --- message annotations --------------------------------------------------

def test_annotations_shared_by_flows_and_messages():
    tagnames = {"t1": "auth"}
    groupnames = {"g1": "login"}
    # A message carries the same annotation fields as a flow (record_id-keyed store).
    m = cp.WsMessage(id="m1", mark_color="red", favorite=True, tag_ids=["t1"], group_ids=["g1"])
    m.comments.append(cp.Comment(id="c1", record_id="m1", body="look"))
    a = S._annotations(m, tagnames, groupnames)
    assert a == {
        "favorite": True,
        "mark_color": "red",
        "tags": ["auth"],
        "groups": ["login"],
        "comments": ["look"],
    }
    # Same helper resolves a flow identically.
    f = _flow(id="f1", mark_color="blue", tag_ids=["t1"])
    assert S._annotations(f, tagnames, groupnames)["mark_color"] == "blue"
    assert S._annotations(f, tagnames, groupnames)["tags"] == ["auth"]


def test_list_ws_messages_includes_annotations(monkeypatch):
    import asyncio

    m = cp.WsMessage(id="m1", from_client=True, opcode="text", ts_unix_micros=5,
                     mark_color="red", tag_ids=["t1"])
    m.comments.append(cp.Comment(id="c1", record_id="m1", body="note"))
    m.payload.CopyFrom(cp.Body(size=2, inline=b"hi"))

    class FakeClient:
        async def list_messages(self, sid, fid):
            return [m]

    async def _resolve(sid):
        return sid

    async def _names():
        return {"t1": "auth"}, {}

    monkeypatch.setattr(S, "client", lambda: FakeClient())
    monkeypatch.setattr(S, "_resolve_session", _resolve)
    monkeypatch.setattr(S, "_name_maps", _names)

    out = asyncio.run(S.list_ws_messages("s", "f"))
    item = out["messages"][0]
    assert item["mark_color"] == "red"
    assert item["tags"] == ["auth"]
    assert item["comments"] == ["note"]


# --- ClientHello export ---------------------------------------------------

def test_flow_detail_notes_client_hellos_and_hrr():
    f = _flow(id="f1", tls_hrr=True)
    f.client_hellos.extend([b"\x01\x00\x00\x02\x03\x03", b"\x01\x00\x00\x01\x03"])
    d = S._flow_detail(f, {}, {})
    assert d["client_hello_count"] == 2
    assert d["tls_hrr"] is True

    # A plaintext flow carries neither key (kept lean).
    plain = S._flow_detail(_flow(id="f2"), {}, {})
    assert "client_hello_count" not in plain and "tls_hrr" not in plain


def test_export_client_hellos_tool(monkeypatch):
    import asyncio

    f = _flow(id="f1", tls_hrr=True)
    f.client_hellos.extend([b"\x01\x00\x00\x02\x03\x03", b"\x01\x00\x00\x01\x03"])

    class FakeClient:
        async def get_flow(self, sid, fid):
            assert (sid, fid) == ("s1", "f1")
            return f

    async def _resolve(sid):
        return "s1"

    monkeypatch.setattr(S, "client", lambda: FakeClient())
    monkeypatch.setattr(S, "_resolve_session", _resolve)

    out = asyncio.run(S.export_client_hellos("s1", "f1"))
    assert out == {
        "flow_id": "f1",
        "tls_hrr": True,
        "client_hellos": ["010000020303", "0100000103"],
    }


def test_export_client_hellos_empty_for_plaintext(monkeypatch):
    import asyncio

    class FakeClient:
        async def get_flow(self, sid, fid):
            return _flow(id="p")

    async def _resolve(sid):
        return sid

    monkeypatch.setattr(S, "client", lambda: FakeClient())
    monkeypatch.setattr(S, "_resolve_session", _resolve)

    out = asyncio.run(S.export_client_hellos("s", "p"))
    assert out == {"flow_id": "p", "tls_hrr": False, "client_hellos": []}


# --- body fetch -----------------------------------------------------------

def _rpc_error(code, details):
    import grpc
    return grpc.aio.AioRpcError(code, grpc.aio.Metadata(), grpc.aio.Metadata(), details=details)


def _with_body(monkeypatch, result):
    """Point the tools at a client whose get_body returns (bytes, partial) — or raises."""
    class FakeClient:
        async def get_body(self, sid, fid, response):
            if isinstance(result, Exception):
                raise result
            return result

    async def _resolve(sid):
        return sid

    monkeypatch.setattr(S, "client", lambda: FakeClient())
    monkeypatch.setattr(S, "_resolve_session", _resolve)


def test_get_body_marks_a_live_preview_as_partial(monkeypatch):
    """A whole body reads as itself; the leading bytes of one still being captured must
    carry `partial` + a note, or the model reads a prefix as the entire body."""
    import asyncio

    _with_body(monkeypatch, (b'{"k":1}', False))
    whole = asyncio.run(S.get_body("s", "f"))
    assert whole["text"] == '{"k":1}' and whole["size"] == 7
    assert "partial" not in whole and "note" not in whole

    _with_body(monkeypatch, (b'{"k":1', True))
    part = asyncio.run(S.get_body("s", "f"))
    assert part["text"] == '{"k":1' and part["partial"] is True
    assert "once the session closes" in part["note"]


def test_get_body_error_mapping(monkeypatch):
    """A body-less flow reads as "no body"; a bundle the gateway refuses to read reports
    its reason rather than looking body-less; real faults propagate."""
    import asyncio

    import grpc

    _with_body(monkeypatch, _rpc_error(grpc.StatusCode.NOT_FOUND, "body not found"))
    assert asyncio.run(S.get_body("s", "f")) == {"size": 0, "note": "no body"}

    msg = "session bundle schema is outdated — re-import this session"
    _with_body(monkeypatch, _rpc_error(grpc.StatusCode.FAILED_PRECONDITION, msg))
    assert asyncio.run(S.get_body("s", "f")) == {"size": 0, "note": msg}

    _with_body(monkeypatch, _rpc_error(grpc.StatusCode.INTERNAL, "boom"))
    try:
        asyncio.run(S.get_body("s", "f"))
    except grpc.aio.AioRpcError:
        pass
    else:
        raise AssertionError("INTERNAL should propagate")


def test_flow_detail_marks_a_partial_body(monkeypatch):
    """The flow detail's body metadata carries the same signal, so `size` there isn't
    mistaken for the body's own length."""
    f = _flow(id="f1")
    f.response_body.CopyFrom(cp.Body(size=6, content_type="application/json",
                                     inline=b'{"k":1', truncated=True))
    d = S._flow_detail(f, {}, {})
    assert d["response_body"]["partial"] is True
    assert d["response_body"]["text"] == '{"k":1'


# --- search tool: paging + content search ---------------------------------

class _Sess:
    def __init__(self, sid, label):
        self.id, self.label = sid, label


class _SearchClient:
    """Serves flow summaries per session, plus details for the content-search fetches.
    `details` maps flow id -> a Flow with headers/bodies; `bodies` maps
    (flow_id, response) -> bytes for out-of-line bodies fetched via get_body."""

    def __init__(self, flows, details=None, bodies=None):
        self.flows, self.details, self.bodies = flows, details or {}, bodies or {}
        self.get_flow_calls, self.get_body_calls = [], []

    async def list_sessions(self):
        return [_Sess(sid, f"label-{sid}") for sid in self.flows]

    async def list_flows(self, sid):
        return list(self.flows[sid])

    async def query_flows(self, sid, filter_expr="", limit=100, after=None,
                          before=None, last=False, since_micros=0, until_micros=0):
        """Stands in for the gateway's filtering and paging with the handful of terms
        these tests exercise, so search_flows is driven the way the server drives it:
        cursors rather than offsets, and hints supplied by whoever owns the language."""
        import re as _re
        rows = sorted(self.flows[sid], key=lambda f: (f.ts_unix_micros, f.frame_number))
        if since_micros:
            rows = [f for f in rows if f.ts_unix_micros >= since_micros]
        if until_micros:
            rows = [f for f in rows if f.ts_unix_micros <= until_micros]

        def matches(f):
            toks = filter_expr.split()
            i = 0
            while i < len(toks):
                t = toks[i]
                if t in ("~h", "~hq", "~hs", "~b", "~bq", "~bs") and i + 1 < len(toks):
                    # Header and body terms are the gateway's job; the fake reads the same
                    # detail/body fixtures the old client-side search used.
                    det = self.details.get(f.id)
                    hays = []
                    if t in ("~h", "~hq") and det is not None:
                        hays.append("\n".join(f"{h.name}: {h.value}"
                                               for h in det.request_headers))
                    if t in ("~h", "~hs") and det is not None:
                        hays.append("\n".join(f"{h.name}: {h.value}"
                                               for h in det.response_headers))
                    if t in ("~b", "~bq"):
                        hays.append(self._body_text(f.id, False))
                    if t in ("~b", "~bs"):
                        hays.append(self._body_text(f.id, True))
                    if not any(_re.search(toks[i + 1], h or "", _re.I) for h in hays):
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
                elif t in ("~m", "~d", "~c", "~u") and i + 1 < len(toks):
                    hay = {"~m": f.method, "~d": f.authority,
                           "~c": str(f.status or ""),
                           "~u": f"https://{f.authority}{f.path}"
                                 + (f"?{f.query}" if f.query else "")}[t]
                    if not _re.search(toks[i + 1], hay or "", _re.I):
                        return False
                    i += 2
                else:
                    url = (f"https://{f.authority}{f.path}"
                           + (f"?{f.query}" if f.query else ""))
                    if not _re.search(t, url, _re.I):
                        return False
                    i += 1
            return True

        toks = filter_expr.split()
        for i, t in enumerate(toks):
            if t in ("~m", "~d", "~c", "~u", "~t") and i + 1 >= len(toks):
                raise grpc.aio.AioRpcError(
                    grpc.StatusCode.INVALID_ARGUMENT, None, None,
                    details=f"{t} needs an argument")
        examined = len(rows)
        rows = [f for f in rows if matches(f)] if filter_expr else rows
        key = lambda f: (f.ts_unix_micros, f.frame_number)
        if after is not None:
            rows = [f for f in rows if key(f) > (after.ts_micros, after.frame_number)]
        matched = len(rows)
        window = rows[:limit]
        page = vp.FlowPage(flows=window, matched=matched, scanned=examined)
        if len(rows) > limit:
            last_row = window[-1]
            page.next.ts_micros = last_row.ts_unix_micros
            page.next.frame_number = last_row.frame_number
        # The gateway computes these; the shapes the tests assert on are what matter.
        # Only *bare* tokens draw hints — the argument of `~c 200` is not a stray status.
        bare, toks2, k = [], filter_expr.split(), 0
        while k < len(toks2):
            t2 = toks2[k].lstrip("!")
            if t2 in ("~m", "~d", "~c", "~u", "~t"):
                k += 2
            elif t2 in ("~s", "~q", "~fav"):
                k += 1
            else:
                bare.append(t2)
                k += 1
        for tok in bare:
            if _re.fullmatch(r"\d{3}", tok):
                page.hints.append(f"a bare `{tok}` matches the URL, not the status — "
                                  f"use `~c {tok}`. (~s/~q take no argument.)")
        if "&" in bare:
            page.hints.append("`&` is not an operator — terms are ANDed automatically, "
                              "so it was matched as a regex against the URL. Just drop it.")
        for tok in filter_expr.split():
            if len(tok) > 1 and tok[0] == tok[-1] and tok[0] in "\'\"":
                page.hints.append(f"{tok} is quoted — arguments are not quote-parsed, so "
                                  f"the quotes match literally.")
        return page

    def _body_text(self, fid, response):
        """Body bytes as text, from the inline copy or the out-of-line fixture."""
        det = self.details.get(fid)
        if det is not None:
            body = det.response_body if response else det.request_body
            if body.inline:
                return body.inline.decode("utf-8", "replace")
        raw = self.bodies.get((fid, response))
        return raw.decode("utf-8", "replace") if raw else ""

    async def get_flow(self, sid, fid):
        self.get_flow_calls.append(fid)
        return self.details.get(fid, _flow(id=fid))

    async def get_body(self, sid, fid, response):
        self.get_body_calls.append((fid, response))
        return self.bodies.get((fid, response), b""), False


def _run_search(monkeypatch, fake, **kw):
    import asyncio

    async def _names():
        return {}, {}

    async def _resolve(sid):
        return sid

    monkeypatch.setattr(S, "client", lambda: fake)
    monkeypatch.setattr(S, "_name_maps", _names)
    monkeypatch.setattr(S, "_resolve_session", _resolve)
    return asyncio.run(S.search(**kw))


def _seq(n, **kw):
    return [_flow(id=f"f{i}", authority="h", path=f"/{i}", scheme="https",
                  ts_unix_micros=(i + 1) * 1_000_000, **kw) for i in range(n)]


def test_search_pages_by_cursor(monkeypatch):
    """Paging is by cursor now: an offset over a growing session shifts rows under the
    caller, and computing one still meant fetching everything before it."""
    fake = _SearchClient({"s1": _seq(5, status=200)})

    first = _run_search(monkeypatch, fake, limit=2)
    # `total` is what has matched *so far*: search stops once it can fill the page rather
    # than walking the session for an exact count, and `complete` says looking stopped.
    assert first["count"] == 2 and first["total"] >= 2
    assert [f["id"] for f in first["flows"]] == ["f0", "f1"]
    assert first["next_cursor"]

    seen = [f["id"] for f in first["flows"]]
    cursor = first["next_cursor"]
    while cursor:
        page = _run_search(monkeypatch, fake, limit=2, cursor=cursor)
        seen += [f["id"] for f in page["flows"]]
        cursor = page.get("next_cursor")
    # The walk covers the session exactly once.
    assert seen == ["f0", "f1", "f2", "f3", "f4"]


def test_search_status_set_and_time_window(monkeypatch):
    flows = [_flow(id="a", authority="h", status=403, ts_unix_micros=1_000_000),
             _flow(id="b", authority="h", status=401, ts_unix_micros=2_000_000),
             _flow(id="c", authority="h", status=200, ts_unix_micros=3_000_000)]
    fake = _SearchClient({"s1": flows})

    out = _run_search(monkeypatch, fake, status_in="4xx")
    assert [f["id"] for f in out["flows"]] == ["a", "b"] and out["total"] == 2

    # ANDed with a time window (epoch micros bounds).
    out = _run_search(monkeypatch, fake, status_in="401,403", since="2", until="3")
    assert [f["id"] for f in out["flows"]] == ["b"]


def test_search_across_sessions_labels_each_hit(monkeypatch):
    fake = _SearchClient({"s1": [_flow(id="a", authority="h", status=200)],
                          "s2": [_flow(id="b", authority="h", status=200)]})
    out = _run_search(monkeypatch, fake)
    assert {(f["session_id"], f["session_label"]) for f in out["flows"]} == {
        ("s1", "label-s1"), ("s2", "label-s2")}


def _detail(fid, *, resp_headers=(), body=None, body_ref=False):
    f = _flow(id=fid)
    for name, value in resp_headers:
        f.response_headers.append(cp.Header(name=name, value=value))
    if body is not None:
        b = cp.Body(size=len(body), content_type="text/html")
        if body_ref:
            b.object_ref = "sha"        # stored out of line -> needs a get_body fetch
        else:
            b.inline = body
        f.response_body.CopyFrom(b)
    return f


def test_search_response_body_contains_returns_preview(monkeypatch):
    summaries = _seq(3, status=200)
    details = {
        "f0": _detail("f0", body=b"<html>nothing here</html>"),
        "f1": _detail("f1", body=b"<html>" + b"x" * 200 + b'{"__NUXT_DATA__":1}</html>'),
        "f2": _detail("f2", body=b"<html>also nothing</html>"),
    }
    fake = _SearchClient({"s1": summaries}, details)

    out = _run_search(monkeypatch, fake, response_body_contains="__NUXT_DATA__")
    assert [f["id"] for f in out["flows"]] == ["f1"]
    assert "__NUXT_DATA__" in out["flows"][0]["match_preview"]["response_body"]
    assert out["scanned"] == 3 and out["scan_limited"] is False and out["complete"] is True


def test_search_response_header_contains_skips_body_fetch(monkeypatch):
    summaries = _seq(2, status=403)
    details = {
        "f0": _detail("f0", resp_headers=[("server", "nginx")],
                      body=b"body", body_ref=True),
        "f1": _detail("f1", resp_headers=[("set-cookie", "spid=abc123; Path=/")],
                      body=b"body", body_ref=True),
    }
    fake = _SearchClient({"s1": summaries}, details)

    out = _run_search(monkeypatch, fake, response_header_contains="spid=")
    assert [f["id"] for f in out["flows"]] == ["f1"]
    assert out["flows"][0]["match_preview"]["response_header"] == "set-cookie: spid=abc123; Path=/"
    # Headers come with the flow detail — no body was pulled over the wire.
    assert fake.get_body_calls == []


def test_search_fetches_an_out_of_line_body_to_match_it(monkeypatch):
    fake = _SearchClient({"s1": _seq(1, status=200)},
                         {"f0": _detail("f0", body=b"placeholder", body_ref=True)},
                         {("f0", True): b"...servicepipe.tech/script.js..."})
    out = _run_search(monkeypatch, fake, response_body_contains="servicepipe.tech")
    assert [f["id"] for f in out["flows"]] == ["f0"]
    assert fake.get_body_calls == [("f0", True)]


def test_search_content_scan_is_bounded_by_max_scan(monkeypatch):
    """max_scan now bounds how much the search asks for, not how much it fetches itself:
    content matching happens in the gateway, so `scanned` is rows the gateway examined and
    the budget stops further pages being requested."""
    fake = _SearchClient({"s1": _seq(20, status=403)},
                         {f"f{i}": _detail(f"f{i}", body=b"no match") for i in range(20)})
    out = _run_search(monkeypatch, fake, response_body_contains="BanShadow", max_scan=8)
    # Nothing matched, and the search genuinely looked at the whole (small) session rather
    # than stopping early — so it must not claim it was truncated. Telling "found nothing"
    # apart from "stopped looking" is the point of reporting these at all.
    assert out["flows"] == []
    assert out["complete"] is True and out["scan_limited"] is False
    assert out["scanned"] >= len(fake.flows["s1"])


def test_search_stops_once_the_page_is_full(monkeypatch):
    """A search must not walk a whole session to fill a small page — it stops once it has
    the page and says the result is incomplete, so `total` reads as a floor."""
    fake = _SearchClient({"s1": _seq(40, status=200)},
                         {f"f{i}": _detail(f"f{i}", body=b"hit: BanShadow") for i in range(40)})
    out = _run_search(monkeypatch, fake, response_body_contains="banshadow", limit=2)
    assert [f["id"] for f in out["flows"]] == ["f0", "f1"]
    assert out["complete"] is False and out["next_cursor"]
    assert out["total"] < 40                      # stopped, rather than counting them all


def test_search_unreadable_flow_is_not_a_match_and_does_not_abort(monkeypatch):
    import grpc

    class Flaky(_SearchClient):
        async def get_flow(self, sid, fid):
            if fid == "f0":
                raise _rpc_error(grpc.StatusCode.NOT_FOUND, "flow not found")
            return await super().get_flow(sid, fid)

    fake = Flaky({"s1": _seq(2, status=200)},
                 {"f1": _detail("f1", body=b"BanShadow")})
    out = _run_search(monkeypatch, fake, response_body_contains="BanShadow")
    assert [f["id"] for f in out["flows"]] == ["f1"]


def test_search_limit_is_clamped(monkeypatch):
    fake = _SearchClient({"s1": _seq(3, status=200)})
    out = _run_search(monkeypatch, fake, limit=10_000)
    assert out["count"] == 3          # clamped to _LIMIT_MAX, still under it here
    assert _run_search(monkeypatch, fake, limit=0)["count"] == 1


def test_search_rejects_a_bad_status_spec(monkeypatch):
    fake = _SearchClient({"s1": _seq(1)})
    try:
        _run_search(monkeypatch, fake, status_in="4x")
    except ValueError as e:
        assert "status" in str(e)
    else:
        raise AssertionError("a bad status spec should raise")


def test_search_flows_pages_and_reports_total(monkeypatch):
    import asyncio

    fake = _SearchClient({"s1": _seq(5, status=200)})

    async def _names():
        return {}, {}

    async def _resolve(sid):
        return sid

    monkeypatch.setattr(S, "client", lambda: fake)
    monkeypatch.setattr(S, "_name_maps", _names)
    monkeypatch.setattr(S, "_resolve_session", _resolve)

    out = asyncio.run(S.search_flows("s1", "~c 200", limit=2))
    assert out["total"] == 5 and out["count"] == 2 and out["next_cursor"]
    assert [f["id"] for f in out["flows"]] == ["f0", "f1"]
    # Walk to the end by cursor rather than jumping to an offset — a live session grows
    # while it is read, so an offset would shift rows under the caller.
    page, cursor = out, out["next_cursor"]
    while cursor:
        page = asyncio.run(S.search_flows("s1", "~c 200", limit=2, cursor=cursor))
        cursor = page.get("next_cursor")
    assert page["count"] == 1 and "next_cursor" not in page
    # A filter that matched carries no recovery payload.
    assert "filter_syntax" not in out and "hints" not in out


# --- filter syntax diagnostics -------------------------------------------

def _run_search_flows(monkeypatch, flows, expr):
    import asyncio

    fake = _SearchClient({"s1": flows})

    async def _names():
        return {}, {}

    async def _resolve(sid):
        return sid

    monkeypatch.setattr(S, "client", lambda: fake)
    monkeypatch.setattr(S, "_name_maps", _names)
    monkeypatch.setattr(S, "_resolve_session", _resolve)
    return asyncio.run(S.search_flows("s1", expr))


def test_search_flows_empty_result_returns_the_syntax_reference(monkeypatch):
    out = _run_search_flows(monkeypatch, _seq(5, status=200), "~d nosuchhost\\.example")
    assert out["total"] == 0
    assert out["session_flow_count"] == 5          # the session itself wasn't empty
    assert "no boolean operators" in " ".join(out["filter_syntax"].lower().split())
    assert out["hints"]                            # a nudge on how to narrow down


def test_search_flows_empty_session_says_so_rather_than_blaming_the_filter(monkeypatch):
    out = _run_search_flows(monkeypatch, [], "~c 200")
    assert out["session_flow_count"] == 0
    assert "no flows at all" in out["hints"][0]


def test_search_flows_flags_ampersand_as_a_non_operator(monkeypatch):
    """The mistake that motivated this: `&` parses fine (as a URL regex), so without a
    hint the caller just sees an empty result and retries the same shape."""
    out = _run_search_flows(monkeypatch, _seq(3, status=200), "~d h & ~s 200")
    joined = " ".join(out["hints"])
    assert "`&` is not an operator" in joined
    assert "~c 200" in joined                      # the bare 200 is called out too


def test_search_flows_hints_fire_even_when_the_filter_matched(monkeypatch):
    """`&` degrades into a URL regex, so a query string containing "&" still matches —
    a silently wrong result, which is exactly when the hint matters most."""
    flows = [_flow(id="f0", authority="h", path="/p", query="a=1&b=2", scheme="https")]
    out = _run_search_flows(monkeypatch, flows, "~d h & ~q")
    assert out["total"] == 1                       # matched, wrongly
    assert any("not an operator" in h for h in out["hints"])
    assert "filter_syntax" not in out              # only attached on an empty result


def test_search_flows_flags_quoted_arguments(monkeypatch):
    out = _run_search_flows(monkeypatch, _seq(3, status=200), "~d 'h'")
    assert any("quoted" in h for h in out["hints"])


def test_search_flows_bad_expression_error_carries_the_syntax(monkeypatch):
    try:
        _run_search_flows(monkeypatch, _seq(1, status=200), "~d")
    except ValueError as e:
        assert "~d needs an argument" in str(e)
        assert "Terms taking NO argument" in str(e)
    else:
        raise AssertionError("a term missing its argument should raise")


# --- compare_flows --------------------------------------------------------

def _hdr(name, value):
    return cp.Header(name=name, value=value)


def test_compare_flows_diff_and_identical():
    a = _flow(method="GET", scheme="https", authority="ex.com", path="/", status=200,
              ja4="t13d1516h2_abc_def", http2_fingerprint="1:65536|0|0|m,a,s,p",
              user_agent="UA/1",
              request_headers=[_hdr("user-agent", "UA/1"), _hdr("accept", "*/*")])
    b = _flow(method="GET", scheme="https", authority="ex.com", path="/", status=200,
              ja4="t13d1517h2_xyz_ghi", http2_fingerprint="1:65536|0|0|m,a,s,p",
              user_agent="UA/2",
              request_headers=[_hdr("accept", "*/*"), _hdr("user-agent", "UA/2")])

    d = S._compare_flows(a, b)
    assert d["params"]["ja4"]["equal"] is False
    assert d["params"]["http2_fingerprint"]["equal"] is True
    assert d["params"]["user_agent"]["equal"] is False
    # Header name order differs (ua/accept swapped).
    assert d["request_header_order"]["equal"] is False
    assert set(d["differences"]) == {"ja4", "user_agent", "request_header_order"}
    assert d["identical"] is False

    # A flow compared with itself is identical.
    same = S._compare_flows(a, a)
    assert same["identical"] is True and same["differences"] == []
