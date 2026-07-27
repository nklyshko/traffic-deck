"""trafficdeck-mcp: an MCP server exposing recorded traffic sessions to LLM/agent
clients. Backed by the gateway's ViewerService over gRPC — it does not
touch SQLite directly, so it works locally or against a remote gateway.

Run (stdio transport):  GATEWAY_ADDR=127.0.0.1:7331 uv run trafficdeck-mcp
"""

from __future__ import annotations

import asyncio
import base64
import itertools
import os
import re
import time
from datetime import datetime

import grpc
from mcp.server.fastmcp import FastMCP

from traffic_mcp.client import GatewayClient
from traffic_mcp.filter import compile_filter, flow_url

mcp = FastMCP("trafficdeck-mcp", host=os.environ.get("MCP_HOST", "127.0.0.1"),
              port=int(os.environ.get("MCP_PORT", "8765")))

_SOURCE_KIND = {0: "unspecified", 1: "chrome", 2: "mitmproxy",
                3: "android_emulator", 4: "android_device", 5: "generic"}
_STATUS = {0: "unspecified", 1: "open", 2: "decoding", 3: "closed", 4: "error"}


def _env_flag(name: str, default: bool) -> bool:
    """Parse a boolean env var; unset -> default. Off values: 0/false/no/off/"" (any case)."""
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off", "")


# Read-only by default: the mutating tools (rename_session, set_session_group) are only
# exposed when MCP_READONLY is explicitly disabled (e.g. MCP_READONLY=0), so an agent
# can inspect recorded traffic but can't rename or regroup sessions unless the operator
# opts in.
READONLY = _env_flag("MCP_READONLY", True)


def _write_tool():
    """Like @mcp.tool(), but registers the tool only when the server is writable — in the
    default read-only mode the decorated function is left unregistered (a no-op decorator)
    so it never appears in the tool list."""
    return (lambda fn: fn) if READONLY else mcp.tool()

# Cap inline text returned to the model so a huge body can't blow the context.
_PREVIEW_MAX = 4096
_BODY_MAX = 256 * 1024

_client: GatewayClient | None = None


def client() -> GatewayClient:
    global _client
    if _client is None:
        _client = GatewayClient(os.environ.get("GATEWAY_ADDR", "127.0.0.1:7331"))
    return _client


async def _resolve_session(session_id: str) -> str:
    """Resolve a full or prefix session id to the full id, with a clear error — so a
    mistyped/short id fails loudly instead of silently returning an empty result."""
    ids = [s.id for s in await client().list_sessions()]
    if session_id in ids:
        return session_id
    matches = [i for i in ids if i.startswith(session_id)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError(f"no session matching {session_id!r} ({len(ids)} sessions — call list_sessions)")
    raise ValueError(f"ambiguous session prefix {session_id!r}: matches {len(matches)} ({matches[:5]})")


async def _name_maps() -> tuple[dict, dict]:
    """tag-id→name and group-id→name, for resolving annotation filters/labels."""
    try:
        tags = await client().list_tags()
        groups = await client().list_groups()
    except Exception:  # noqa: BLE001 (older gateway without ControlService reads)
        return {}, {}
    return ({t.id: t.name for t in tags}, {g.id: g.name for g in groups})


# --- serialization -------------------------------------------------------

def _session_dict(s) -> dict:
    return {
        "id": s.id,
        "label": s.label,
        "group": s.group or None,
        "source_kind": _SOURCE_KIND.get(s.source_kind, "?"),
        "status": _STATUS.get(s.status, "?"),
        "created_at_unix_ms": s.created_at_unix_ms,
        "closed_at_unix_ms": s.closed_at_unix_ms or None,
        "flow_count": s.flow_count,
        "pcap_bytes": s.pcap_bytes,
        "keylog_bytes": s.keylog_bytes,
    }


def _annotations(rec, tagnames: dict, groupnames: dict) -> dict:
    """Annotation fields shared by flows and messages (both are record_id-keyed records):
    favorite, color mark, tag/group names, and comment bodies."""
    return {
        "favorite": rec.favorite,
        "mark_color": rec.mark_color or None,
        "tags": [tagnames.get(t, t) for t in rec.tag_ids],
        "groups": [groupnames.get(g, g) for g in rec.group_ids],
        "comments": [c.body for c in rec.comments],
    }


def _flow_summary(f, tagnames: dict, groupnames: dict) -> dict:
    return {
        "id": f.id,
        "ts_unix_micros": f.ts_unix_micros,
        "method": f.method,
        "url": flow_url(f),
        "status": f.status or None,
        "error": f.error or None,
        "duration_ms": round(f.duration_micros / 1000, 1) if f.duration_micros else None,
        "protocol": f.protocol,
        "content_type": f.content_type or None,
        "request_bytes": f.request_bytes,
        "tls_decrypted": f.tls_decrypted,
        "websocket": f.websocket,
        "ws_message_count": f.ws_message_count,
        **_annotations(f, tagnames, groupnames),
        "http2_fingerprint": f.http2_fingerprint or None,
        "ja3": f.ja3 or None,
        "ja4": f.ja4 or None,
        "tls_client_hello": f.tls_client_hello or None,
        "redirect_location": f.redirect_location or None,
        "redirected_from_id": f.redirected_from_id or None,
    }


def _headers(hs) -> list[dict]:
    return [{"name": h.name, "value": h.value} for h in hs]


def _set_cookie(c) -> dict:
    """A response cookie with its Set-Cookie attributes (only the ones present)."""
    d = {"name": c.name, "value": c.value}
    if c.domain:
        d["domain"] = c.domain
    if c.path:
        d["path"] = c.path
    if c.expires:
        d["expires"] = c.expires
    if c.max_age:
        d["max_age"] = c.max_age
    if c.secure:
        d["secure"] = True
    if c.http_only:
        d["http_only"] = True
    if c.same_site:
        d["same_site"] = c.same_site
    return d


def _short_type(ct: str) -> str:
    """Compact content-type for timeline rows: 'application/json; charset=…' → 'json'."""
    if not ct:
        return ""
    main = ct.split(";")[0].strip()
    return main.split("/")[-1] or main


def _body_ref(body) -> dict | None:
    """Body metadata only (content-type + size) — no bytes. Fetch bytes via get_body."""
    if body is None or body.size == 0:
        return None
    d = {"content_type": body.content_type or None, "size": body.size}
    if body.truncated:
        d |= _PARTIAL
    return d


# What a live decode reports for a body it only kept the start of: `size` counts the bytes
# it has, not the body's own length, and the rest arrives when the session is decoded on
# close. Only sessions captured with record-live off can produce this.
_PARTIAL = {"partial": True,
            "note": "live preview — only the start of the body was kept while capturing; "
                    "the whole body is readable once the session closes"}


def _body_meta(body) -> dict | None:
    """Body metadata + an inline text/preview (full bytes via get_body)."""
    if body is None or body.size == 0:
        return None
    meta = {"content_type": body.content_type or None, "size": body.size}
    if body.truncated:
        meta |= _PARTIAL
    if body.WhichOneof("content") != "inline":
        meta["note"] = "large body — fetch with get_body"
        return meta
    data = body.inline
    try:
        text = data.decode("utf-8")
        meta["text"] = text[:_PREVIEW_MAX]
        meta["truncated"] = len(text) > _PREVIEW_MAX
    except UnicodeDecodeError:
        meta["binary"] = True
        meta["hex_preview"] = data[:64].hex()
    return meta


def _flow_detail(f, tagnames: dict, groupnames: dict) -> dict:
    d = _flow_summary(f, tagnames, groupnames)
    # Connection-level params (kept out of the list summary to keep it lean).
    d["src_addr"] = f.src_addr or None
    d["dst_addr"] = f.dst_addr or None
    d["user_agent"] = f.user_agent or None
    d["tcp_stream"] = f.tcp_stream or None
    d["h2_stream_id"] = f.h2_stream_id or None
    if f.proxy.addr:
        d["proxy"] = {"addr": f.proxy.addr, "type": f.proxy.type,
                      "username": f.proxy.username or None, "password": f.proxy.password or None}
    d["request_headers"] = _headers(f.request_headers)
    d["response_headers"] = _headers(f.response_headers)
    d["request_cookies"] = [{"name": c.name, "value": c.value} for c in f.request_cookies]
    d["response_cookies"] = [_set_cookie(c) for c in f.response_cookies]
    d["request_body"] = _body_meta(f.request_body)
    d["response_body"] = _body_meta(f.response_body)
    # Raw ClientHello(s): note their presence + the HelloRetryRequest flag here; fetch the
    # bytes (hex) with export_client_hellos. More than one only after a HelloRetryRequest.
    if f.client_hellos:
        d["client_hello_count"] = len(f.client_hellos)
    if f.tls_hrr:
        d["tls_hrr"] = True
    return d


def _bytes_payload(data: bytes, *, as_hex: bool = False, start: int = 0) -> dict:
    """Encode fetched body/payload bytes for the model. A window of up to _BODY_MAX bytes
    starting at `start` is returned as UTF-8 text when decodable, else base64; pass
    `as_hex` for a hex dump (for protocol/byte inspection). `offset`+`returned` vs `size`
    show where the window sits, so large payloads can be paged."""
    total = len(data)
    start = max(0, start)
    window = data[start:start + _BODY_MAX]
    out: dict = {"size": total, "offset": start, "returned": len(window),
                 "truncated": start + len(window) < total}
    if as_hex:
        out["encoding"] = "hex"
        out["hex"] = window.hex()
        return out
    try:
        out["encoding"] = "utf-8"
        out["text"] = window.decode("utf-8")
    except UnicodeDecodeError:
        out["encoding"] = "base64"
        out["base64"] = base64.b64encode(window).decode("ascii")
    return out


# --- search criteria -----------------------------------------------------

def _parse_status_set(spec: str) -> set[int] | None:
    """Parse a status-code *set* — "401,403" (codes), "400-499" (range), "4xx"/"40x"
    (wildcard class) — into the codes it covers, or None for an empty spec. Parts are
    separated by commas and/or spaces and unioned, so "4xx,500-503" is one criterion."""
    if not (spec or "").strip():
        return None
    out: set[int] = set()
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        if m := re.fullmatch(r"(\d{3})-(\d{3})", part):
            lo, hi = int(m[1]), int(m[2])
            if lo > hi:
                raise ValueError(f"bad status range {part!r}: {lo} > {hi}")
            out |= set(range(lo, hi + 1))
        elif m := re.fullmatch(r"(\d{1,2})(x{1,2})", part, re.IGNORECASE):
            if len(m[1]) + len(m[2]) != 3:
                raise ValueError(f"bad status class {part!r} — 3 characters, e.g. 4xx or 40x")
            lo = int(m[1].ljust(3, "0"))
            out |= set(range(lo, lo + 10 ** len(m[2])))
        elif re.fullmatch(r"\d{3}", part):
            out.add(int(part))
        else:
            raise ValueError(f"bad status spec {part!r} — use a code (403), a set (401,403), "
                             f"a range (400-499) or a class (4xx)")
    return out


def _parse_time(v: str) -> int | None:
    """Parse a time bound to unix micros; "" -> None (unbounded).

    Accepts an ISO-8601 timestamp ("2026-07-27T06:08:00", "2026-07-27T06:08:00Z",
    "2026-07-27"), a bare clock time meaning today ("06:08", "06:08:30"), a relative
    offset back from now ("-15m", "-2h", "-90s", "-1d"), or a unix epoch number in
    seconds / milliseconds / microseconds (told apart by magnitude). Clock times and
    ISO timestamps without an offset are read as *local* time — the same wall clock as
    an application log you are correlating against.
    """
    s = (v or "").strip()
    if not s:
        return None
    if m := re.fullmatch(r"-\s*(\d+)\s*([smhd])", s, re.IGNORECASE):
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2].lower()]
        return int((time.time() - int(m[1]) * mult) * 1_000_000)
    if re.fullmatch(r"\d+(\.\d+)?", s):
        n = float(s)
        if n < 1e11:        # plausible only as seconds (1e11 s is the year 5138)
            n *= 1e6
        elif n < 1e14:      # milliseconds
            n *= 1e3
        return int(n)       # already microseconds
    if m := re.fullmatch(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", s):
        now = datetime.now()
        dt = now.replace(hour=int(m[1]), minute=int(m[2]), second=int(m[3] or 0), microsecond=0)
    else:
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"bad time {s!r} — use ISO-8601 (2026-07-27T06:08), a clock time "
                             f"today (06:08), a relative offset (-15m) or a unix epoch number")
    if dt.tzinfo is None:
        dt = dt.astimezone()  # naive -> local time
    return int(dt.timestamp() * 1_000_000)


def _snippet(hay: str, needle: str, ctx: int = 60) -> str | None:
    """The first case-insensitive occurrence of `needle` in `hay` with up to `ctx`
    characters of surrounding context (whitespace collapsed, elided ends marked "…"),
    or None when it doesn't occur — the match preview carried by a search hit."""
    i = hay.lower().find(needle.lower())
    if i < 0:
        return None
    start, end = max(0, i - ctx), min(len(hay), i + len(needle) + ctx)
    text = re.sub(r"\s+", " ", hay[start:end]).strip()
    return ("…" if start else "") + text + ("…" if end < len(hay) else "")


def _matches(f, *, domain: str, method: str, content_type: str, status: int,
             path_contains: str, url_contains: str, websocket, has_response,
             status_set: set[int] | None = None,
             since: int | None = None, until: int | None = None) -> bool:
    """Predicate for `search` over a flow *summary*: all given criteria ANDed. Substring
    fields are case-insensitive; method/status are exact; `status_set` matches any code in
    it; `since`/`until` bound ts_unix_micros (inclusive); websocket/has_response are
    tri-state. Content criteria (headers/bodies) need a second fetch — see _deep_match."""
    if domain and domain.lower() not in (f.authority or "").lower():
        return False
    if method and method.upper() != (f.method or "").upper():
        return False
    if content_type and content_type.lower() not in (f.content_type or "").lower():
        return False
    if status and f.status != status:
        return False
    if status_set is not None and f.status not in status_set:
        return False
    if path_contains and path_contains.lower() not in (f.path or "").lower():
        return False
    if url_contains and url_contains.lower() not in flow_url(f).lower():
        return False
    if websocket is not None and bool(f.websocket) != websocket:
        return False
    if has_response is not None and bool(f.status) != has_response:
        return False
    # An unstamped flow (ts 0) can't be placed in time, so a time window excludes it.
    if (since is not None or until is not None) and not f.ts_unix_micros:
        return False
    if since is not None and f.ts_unix_micros < since:
        return False
    if until is not None and f.ts_unix_micros > until:
        return False
    return True


# Content search (headers/bodies) is a second fetch per candidate flow, so it is bounded:
# only `max_scan` candidates are examined, each body is matched over its first
# _SCAN_BYTES, and a stored body bigger than _SCAN_FETCH_MAX is skipped rather than pulled
# over the wire. _SCAN_CONCURRENCY fetches are in flight at once.
_SCAN_BYTES = 128 * 1024
_SCAN_FETCH_MAX = 2 * 1024 * 1024
_SCAN_CONCURRENCY = 8
_LIMIT_MAX = 500


def _header_text(hs) -> str:
    """Headers as "name: value" lines — the haystack for *_header_contains."""
    return "\n".join(f"{h.name}: {h.value}" for h in hs)


async def _body_text(sid: str, flow_id: str, body, response: bool) -> str:
    """Up to _SCAN_BYTES of a body as text, for content matching. Uses the bytes GetFlow
    inlined; falls back to a GetBody fetch for a body stored out of line (unless it is
    over _SCAN_FETCH_MAX). Undecodable bytes are replaced, not an error — a substring
    search over a binary body should just not match."""
    if body is None or not body.size:
        return ""
    if body.WhichOneof("content") == "inline":
        data = body.inline
    elif body.size > _SCAN_FETCH_MAX:
        return ""
    else:
        try:
            data, _ = await client().get_body(sid, flow_id, response)
        except grpc.aio.AioRpcError:
            return ""
    return data[:_SCAN_BYTES].decode("utf-8", "replace")


async def _deep_match(sid: str, flow_id: str, crit: dict) -> dict | None:
    """Match a candidate flow's headers/bodies against the content criteria in `crit`.

    Returns the match previews ({field: snippet}) when every content criterion matches,
    or None when one doesn't — or when the flow can't be read (a bundle the gateway
    refuses, a flow that vanished): unreadable is treated as no match, never as a fault
    that aborts the whole search. Headers come free with the flow detail and are checked
    first, so a body is only fetched once the header criteria have passed.
    """
    try:
        f = await client().get_flow(sid, flow_id)
    except grpc.aio.AioRpcError:
        return None
    prev: dict[str, str] = {}
    for field, hay in (("request_header", _header_text(f.request_headers)),
                       ("response_header", _header_text(f.response_headers))):
        if needle := crit[f"{field}_contains"]:
            if (hit := _snippet(hay, needle)) is None:
                return None
            prev[field] = hit
    for field, body, response in (("request_body", f.request_body, False),
                                  ("response_body", f.response_body, True)):
        if needle := crit[f"{field}_contains"]:
            hit = _snippet(await _body_text(sid, flow_id, body, response), needle)
            if hit is None:
                return None
            prev[field] = hit
    return prev


def _url_previews(f, crit: dict) -> dict:
    """Match previews for the substring criteria that match a flow summary — so a hit
    from a loose url/path filter shows *what* matched without a get_flow round trip."""
    prev = {}
    for field, hay in (("url", flow_url(f)), ("path", f.path or "")):
        if needle := crit[f"{field}_contains"]:
            if (hit := _snippet(hay, needle)) is not None:
                prev[field] = hit
    return prev


def _timeline_row(seq: int, f, t0: int) -> dict:
    """One compact DevTools-Network-style row (ordered by time)."""
    path = (f.path or "") + (f"?{f.query}" if f.query else "")
    # Relative ms from the first timestamped request; null when a flow has no
    # timestamp (e.g. a decoder that didn't stamp the Upgrade flow).
    t_ms = round((f.ts_unix_micros - t0) / 1000, 1) if f.ts_unix_micros > 0 else None
    return {
        "seq": seq,
        "id": f.id,
        "t_ms": t_ms,  # ms since first request
        "method": f.method or ("WS" if f.websocket else ""),
        "status": f.status or None,
        "error": f.error or None,
        "domain": f.authority,
        "path": path[:120],
        "type": _short_type(f.content_type),
        "request_bytes": f.request_bytes,
        "protocol": f.protocol,
        "ws": f.websocket or None,
        "ws_messages": f.ws_message_count or None,
    }


# --- tools ---------------------------------------------------------------

@mcp.tool()
async def list_sessions() -> list[dict]:
    """List all recorded capture sessions (id, label, group, status, flow count, sizes)."""
    return [_session_dict(s) for s in await client().list_sessions()]


@mcp.tool()
async def list_session_groups() -> dict:
    """Sessions organized by their group label. Returns {"groups": [{group, sessions:[…]}]}
    with grouped sessions first (alphabetical) and ungrouped last (group=null)."""
    sessions = [_session_dict(s) for s in await client().list_sessions()]
    by_group: dict = {}
    for s in sessions:
        by_group.setdefault(s["group"], []).append(s)
    ordered = sorted(by_group.keys(), key=lambda g: (g is None, (g or "").lower()))
    return {"groups": [{"group": g, "sessions": by_group[g]} for g in ordered]}


@_write_tool()
async def set_session_group(session_id: str, group: str) -> dict:
    """Assign a session to a free-text group (organize the session list); "" clears it."""
    sid = await _resolve_session(session_id)
    await client().set_session_group(sid, group)
    return {"session_id": sid, "group": group or None}


@_write_tool()
async def rename_session(session_id: str, label: str) -> dict:
    """Rename a session (set its label)."""
    sid = await _resolve_session(session_id)
    await client().set_session_label(sid, label)
    return {"session_id": sid, "label": label}


@mcp.tool()
async def network_timeline(session_id: str, limit: int = 200, offset: int = 0) -> dict:
    """The request sequence for a session, like the Chrome DevTools Network tab.

    One compact row per flow ordered by time: relative start (t_ms = ms from the first
    request), method, status, domain, path, type (content-type), request bytes, protocol
    and websocket flags. Use `search`/`search_flows` to narrow and `get_flow` for full
    detail. `total` is the session's flow count; page with `offset`/`limit`.
    """
    sid = await _resolve_session(session_id)
    flows = sorted(await client().list_flows(sid), key=lambda f: f.ts_unix_micros)
    stamped = [f.ts_unix_micros for f in flows if f.ts_unix_micros > 0]
    t0 = min(stamped) if stamped else 0
    rows = [_timeline_row(i, f, t0) for i, f in enumerate(flows[offset:offset + limit], start=offset)]
    return {"session_id": sid, "total": len(flows), "count": len(rows), "flows": rows}


async def _session_flows(session_id: str) -> list[tuple[str, str | None, object]]:
    """(session_id, session_label, flow) for every flow to search, time-ordered within a
    session. An empty `session_id` spans every session."""
    if session_id:
        sessions = [(await _resolve_session(session_id), None)]
    else:
        sessions = [(s.id, s.label) for s in await client().list_sessions()]

    out: list[tuple[str, str | None, object]] = []
    for sid, label in sessions:
        try:
            flows = await client().list_flows(sid)
        except grpc.aio.AioRpcError as e:
            # For an explicit session_id, surface the error (incl. FAILED_PRECONDITION
            # "re-import this session"). When scanning every session, skip outdated or
            # missing bundles but still propagate genuine faults.
            if session_id or e.code() not in (
                grpc.StatusCode.FAILED_PRECONDITION, grpc.StatusCode.NOT_FOUND
            ):
                raise
            continue
        flows.sort(key=lambda f: f.ts_unix_micros)
        out += [(sid, label, f) for f in flows]
    return out


@mcp.tool()
async def search(session_id: str = "", domain: str = "", method: str = "",
                 content_type: str = "", status: int = 0, status_in: str = "",
                 path_contains: str = "", url_contains: str = "",
                 request_header_contains: str = "", response_header_contains: str = "",
                 request_body_contains: str = "", response_body_contains: str = "",
                 since: str = "", until: str = "", websocket: bool | None = None,
                 has_response: bool | None = None, limit: int = 100, offset: int = 0,
                 max_scan: int = 400) -> dict:
    """Combined structured search over flows — every criterion you pass is ANDed in
    one query, e.g. domain="api.oneme.ru" + status_in="4xx" + response_body_contains="BanShadow".

    Metadata criteria (matched on the flow summary, no extra fetch):
      `domain`, `content_type`, `path_contains`, `url_contains` — case-insensitive
      substrings; `method` — exact (case-insensitive); `status` — one exact code
      (0 = any); `status_in` — a code *set*: "401,403", "400-499", "4xx", "4xx,500-503";
      `websocket`/`has_response` — tri-state (omit = any).

    Time window: `since`/`until` bound the request timestamp, each an ISO-8601 stamp
    ("2026-07-27T06:08"), a clock time today ("06:08"), a relative offset back from now
    ("-15m", "-2h"), or a unix epoch number (s/ms/µs). Bare clock times and offset-less
    ISO stamps are local time. Flows with no timestamp are excluded by a window.

    Content criteria — `request_header_contains`, `response_header_contains`,
    `request_body_contains`, `response_body_contains` — are case-insensitive substrings
    over the headers ("name: value" lines) and the first 128 KiB of the body, so a
    Set-Cookie name, a script URL in HTML or a JSON key can be found directly instead of
    paging through get_flow/get_body. They cost one fetch per candidate flow, so narrow
    with the metadata criteria first: only `max_scan` candidates (default 400) are
    examined and the result reports `scanned`/`scan_limited`. Scanning stops as soon as
    the requested page is full, so a later page re-scans from the start — prefer one
    query with a bigger `limit` over walking many pages.

    Every hit carries `match_preview` — {field: matched substring in context} for the
    substring criteria — so you can see *why* it matched without a get_flow.

    Leave `session_id` empty to search across every session (each result carries its
    `session_id`/`session_label`). Returns time-ordered flow summaries (no headers/bodies
    — use get_flow / get_body / export_request for those):
    {count, total, complete, offset, next_offset, scanned, scan_limited, flows:[…]}.
    `total` is the number of matches found; `complete` says whether every candidate was
    examined (so `total` is exact and `next_offset` null means the end). Page with
    `offset`/`limit` (limit default 100, max 500) — passing the returned `next_offset`
    walks the whole result set.
    """
    limit = max(1, min(limit, _LIMIT_MAX))
    offset = max(0, offset)
    max_scan = max(1, max_scan)
    tagnames, groupnames = await _name_maps()
    crit = dict(domain=domain, method=method, content_type=content_type, status=status,
                status_set=_parse_status_set(status_in),  # raises ValueError on a bad spec
                path_contains=path_contains, url_contains=url_contains,
                websocket=websocket, has_response=has_response,
                since=_parse_time(since), until=_parse_time(until))
    content = dict(request_header_contains=request_header_contains,
                   response_header_contains=response_header_contains,
                   request_body_contains=request_body_contains,
                   response_body_contains=response_body_contains)
    deep = any(content.values())

    candidates = (c for c in await _session_flows(session_id) if _matches(c[2], **crit))

    # Collect matches up to the page we need. Without content criteria that is the whole
    # candidate list (cheap, in memory); with them, fetches run _SCAN_CONCURRENCY at a
    # time and stop at the page's end or the scan budget, whichever comes first.
    matched: list[tuple[str, str | None, object, dict]] = []
    scanned = 0
    complete = True
    if not deep:
        matched = [(sid, label, f, {}) for sid, label, f in candidates]
    else:
        want = offset + limit
        while len(matched) < want and scanned < max_scan:
            batch = list(itertools.islice(candidates, min(_SCAN_CONCURRENCY, max_scan - scanned)))
            if not batch:
                break
            scanned += len(batch)
            previews = await asyncio.gather(
                *(_deep_match(sid, f.id, content) for sid, _, f in batch))
            matched += [(sid, label, f, p)
                        for (sid, label, f), p in zip(batch, previews) if p is not None]
        # Anything left unexamined (page filled early, or the budget ran out).
        complete = next(candidates, None) is None

    page = matched[offset:offset + limit]
    rows = []
    for sid, label, f, previews in page:
        row = _flow_summary(f, tagnames, groupnames)
        row["session_id"] = sid
        if label is not None:
            row["session_label"] = label
        if preview := _url_previews(f, crit) | previews:
            row["match_preview"] = preview
        rows.append(row)

    more = len(matched) > offset + len(page) or not complete
    out = {"count": len(rows), "total": len(matched), "complete": complete,
           "offset": offset, "next_offset": offset + len(rows) if more and rows else None,
           "flows": rows}
    if deep:
        out["scanned"] = scanned
        out["scan_limited"] = scanned >= max_scan and not complete
        if out["scan_limited"]:
            out["note"] = (f"stopped after scanning {scanned} candidates — narrow the "
                           f"metadata criteria or raise max_scan")
    return out


@mcp.tool()
async def search_flows(session_id: str, filter: str = "", limit: int = 100,
                       offset: int = 0) -> dict:
    """Search a session's flows with a mitmproxy-style filter expression.

    Terms (ANDed, `!` negates): ~m method, ~d host, ~u url, ~c status, ~t content-type,
    ~s/~q has/no response, ~fav, ~mark <color>, ~tag <name>, ~group <name>,
    ~comment <regex>; a naked regex matches the URL. Each term's argument is a regex, so
    ~c 40[13] matches 401 or 403 and ~c 4.. matches any 4xx. Empty filter returns all
    flows.

    Returns {total, count, offset, next_offset, flows:[…]} — flow summaries, no
    headers/bodies (use get_flow for those). `total` is the number of flows matching the
    filter; page with `offset`/`limit` (default 100, max 500). For field matching, status
    sets, time windows and header/body content search prefer the structured `search` tool.
    """
    limit = max(1, min(limit, _LIMIT_MAX))
    offset = max(0, offset)
    flows = await client().list_flows(await _resolve_session(session_id))
    tagnames, groupnames = await _name_maps()
    pred = compile_filter(filter, tagnames, groupnames)  # raises ValueError on bad expr
    if pred is not None:
        flows = [f for f in flows if pred(f)]
    page = flows[offset:offset + limit]
    return {"total": len(flows), "count": len(page), "offset": offset,
            "next_offset": offset + len(page) if offset + len(page) < len(flows) else None,
            "flows": [_flow_summary(f, tagnames, groupnames) for f in page]}


@mcp.tool()
async def get_flow(session_id: str, flow_id: str) -> dict:
    """Full detail for one flow: headers (wire order), body previews, annotations."""
    f = await client().get_flow(await _resolve_session(session_id), flow_id)
    tagnames, groupnames = await _name_maps()
    return _flow_detail(f, tagnames, groupnames)


def _cmp(a, b) -> dict:
    return {"a": a or None, "b": b or None, "equal": (a or "") == (b or "")}


def _compare_flows(fa, fb) -> dict:
    """Diff two flows' request/connection parameters (pure; no RPC). See compare_flows."""
    params = {
        "method": _cmp(fa.method, fb.method),
        "url": _cmp(flow_url(fa), flow_url(fb)),
        "status": {"a": fa.status or None, "b": fb.status or None, "equal": fa.status == fb.status},
        "protocol": _cmp(fa.protocol, fb.protocol),
        "user_agent": _cmp(fa.user_agent, fb.user_agent),
        "ja3": _cmp(fa.ja3, fb.ja3),
        "ja4": _cmp(fa.ja4, fb.ja4),
        "http2_fingerprint": _cmp(fa.http2_fingerprint, fb.http2_fingerprint),
        "tls_client_hello": _cmp(fa.tls_client_hello, fb.tls_client_hello),
    }

    def order(hs):
        return [h.name.lower() for h in hs]

    req_order = {"a": order(fa.request_headers), "b": order(fb.request_headers),
                 "equal": order(fa.request_headers) == order(fb.request_headers)}
    resp_order = {"a": order(fa.response_headers), "b": order(fb.response_headers),
                  "equal": order(fa.response_headers) == order(fb.response_headers)}

    differences = [k for k, v in params.items() if not v["equal"]]
    if not req_order["equal"]:
        differences.append("request_header_order")
    if not resp_order["equal"]:
        differences.append("response_header_order")

    return {
        "params": params,
        "request_header_order": req_order,
        "response_header_order": resp_order,
        "differences": differences,
        "identical": not differences,
    }


@mcp.tool()
async def compare_flows(session_a: str, flow_a: str, session_b: str, flow_b: str) -> dict:
    """Compare two flows' request/connection parameters — across different sessions or
    within one (pass the same session id) — for fingerprint / anti-bot analysis.

    Returns per-parameter {a, b, equal} for the request line and the connection
    fingerprints (JA3, JA4, HTTP/2 fingerprint, ClientHello, user-agent), the request/
    response header name order (an anti-bot signal on its own), and a `differences` list
    naming every parameter that differs (empty ⇒ the two are identical)."""
    sa = await _resolve_session(session_a)
    sb = await _resolve_session(session_b)
    fa = await client().get_flow(sa, flow_a)
    fb = await client().get_flow(sb, flow_b)
    out = _compare_flows(fa, fb)
    out["a"] = {"session_id": sa, "flow_id": flow_a, "url": flow_url(fa)}
    out["b"] = {"session_id": sb, "flow_id": flow_b, "url": flow_url(fb)}
    return out


@mcp.tool()
async def get_body(session_id: str, flow_id: str, response: bool = True,
                   as_hex: bool = False, offset: int = 0) -> dict:
    """Fetch a request or response body. Returns UTF-8 text when decodable, else base64;
    pass `as_hex=True` for a hex dump (byte inspection). A window of up to 256 KiB from
    `offset` is returned (page large bodies with `offset`). Bodies are stored
    decompressed. `response=False` for the request body.

    Works on a session that is still capturing. There a body can come back `partial` —
    its leading bytes, with a `note` — when the capture kept only a preview of it; fetch
    it again once the session closes to get all of it.

    For a custom-protocol flow (a decoded raw-TCP connection), this returns the original
    *undecoded* bytes: `response=False` = the raw client->server stream, `response=True` =
    the raw server->client stream — the bytes that were fed to the decoder."""
    try:
        data, partial = await client().get_body(
            await _resolve_session(session_id), flow_id, response)
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.NOT_FOUND:
            return {"size": 0, "note": "no body"}
        if e.code() == grpc.StatusCode.FAILED_PRECONDITION:
            # The bundle can't be read as it stands (an outdated schema, say): report the
            # gateway's own reason instead of an empty body that reads as "no body".
            return {"size": 0, "note": e.details() or "body not available"}
        raise
    out = _bytes_payload(data, as_hex=as_hex, start=offset)
    return out | _PARTIAL if partial else out


@mcp.tool()
async def list_ws_messages(session_id: str, flow_id: str, limit: int = 100,
                           offset: int = 0) -> dict:
    """WebSocket message timeline for an Upgrade flow: directional frames in order
    (direction, opcode, size, text/hex preview). Paginated — `total` is the frame count;
    page with `offset`/`limit` (default 100) to avoid huge responses. Large payloads
    carry a note; fetch them in full with get_ws_message_body using the message `id`.

    Each frame carries its annotations (favorite, mark_color, tags, groups, comments) —
    messages are annotatable records just like flows.

    When a custom decoder handled the connection, a message's payload is the decoded form
    and `has_raw` is true — fetch the original undecoded bytes with
    get_ws_message_body(message_id, raw=True)."""
    sid = await _resolve_session(session_id)
    tagnames, groupnames = await _name_maps()
    msgs = await client().list_messages(sid, flow_id)
    total = len(msgs)
    out = []
    for m in msgs[offset:offset + limit]:
        size = m.payload.size if m.payload else 0
        item = {
            "id": m.id,
            "ts_unix_micros": m.ts_unix_micros,
            "direction": "client->server" if m.from_client else "server->client",
            "opcode": m.opcode,
            "size": size,
            # Messages are annotatable records, like flows.
            **_annotations(m, tagnames, groupnames),
        }
        if m.raw and m.raw.size:
            item["has_raw"] = True  # original undecoded bytes; fetch with get_ws_message_body(raw=True)
        if m.payload and m.payload.WhichOneof("content") == "inline":
            data = m.payload.inline
            try:
                item["text"] = data.decode("utf-8")[:_PREVIEW_MAX]
            except UnicodeDecodeError:
                item["hex_preview"] = data[:64].hex()
        elif size:
            item["note"] = "large payload — fetch with get_ws_message_body"
        out.append(item)
    return {"session_id": sid, "flow_id": flow_id, "total": total,
            "count": len(out), "messages": out}


@mcp.tool()
async def get_ws_message_body(session_id: str, message_id: str,
                              as_hex: bool = False, offset: int = 0,
                              raw: bool = False) -> dict:
    """Fetch a full WebSocket message payload by message `id` (from list_ws_messages).
    Returns UTF-8 text when decodable, else base64; pass `as_hex=True` for a hex dump
    (byte inspection). Page large payloads with `offset`.

    Pass `raw=True` to fetch the original *undecoded* frame bytes instead of the decoded
    payload — available for messages a custom decoder produced (those have `has_raw` in
    list_ws_messages)."""
    try:
        data = await client().get_message_body(await _resolve_session(session_id), message_id, raw=raw)
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.NOT_FOUND:
            return {"size": 0, "note": "no raw bytes" if raw else "no payload"}
        raise
    return _bytes_payload(data, as_hex=as_hex, start=offset)


@mcp.tool()
async def export_request(session_id: str, flow_id: str) -> dict:
    """Export a flow's request and response *without* bodies.

    Returns the request (method, url, protocol, headers in wire order, cookies) and the
    response (status, protocol, headers), each with body metadata only
    ({content_type, size}) — no body bytes. Fetch actual bytes with get_body.
    """
    f = await client().get_flow(await _resolve_session(session_id), flow_id)
    out = {
        "request": {
            "method": f.method or "GET",
            "url": flow_url(f),
            "protocol": f.protocol,
            "headers": _headers(f.request_headers),
            "cookies": [{"name": c.name, "value": c.value} for c in f.request_cookies],
            "body": _body_ref(f.request_body),
        },
        "response": {
            "status": f.status or None,
            "protocol": f.protocol,
            "headers": _headers(f.response_headers),
            "cookies": [_set_cookie(c) for c in f.response_cookies],
            "body": _body_ref(f.response_body),
        },
    }
    if f.websocket:
        out["websocket"] = {"message_count": f.ws_message_count}
    return out


@mcp.tool()
async def export_client_hellos(session_id: str, flow_id: str) -> dict:
    """Export a flow's raw TLS ClientHello handshake message(s) as hex, in wire order.

    Each entry is one ClientHello (handshake header + body) exactly as captured —
    suitable for replay/fingerprinting. There is more than one entry only when the server
    sent a HelloRetryRequest (`tls_hrr`), which makes the client resend a ClientHello.
    `client_hellos` is empty for plaintext connections and pushed/proxy sources (which
    don't expose the raw handshake).
    """
    f = await client().get_flow(await _resolve_session(session_id), flow_id)
    return {
        "flow_id": f.id,
        "tls_hrr": f.tls_hrr,
        "client_hellos": [ch.hex() for ch in f.client_hellos],
    }


def main() -> None:
    # MCP_TRANSPORT: streamable-http (default), sse, or stdio. The HTTP transports bind
    # MCP_HOST:MCP_PORT (default 127.0.0.1:8765) and serve at /mcp; set stdio to speak
    # the protocol over stdin/stdout instead.
    # MCP_READONLY (default on): expose only read tools; set MCP_READONLY=0 to also allow
    # the mutating rename_session / set_session_group tools.
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
