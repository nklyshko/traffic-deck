"""trafficdeck-mcp: an MCP server exposing recorded traffic sessions to LLM/agent
clients. Backed by the gateway's ViewerService over gRPC — it does not
touch SQLite directly, so it works locally or against a remote gateway.

Run (stdio transport):  GATEWAY_ADDR=127.0.0.1:8080 uv run trafficdeck-mcp
"""

from __future__ import annotations

import base64
import os

import grpc
from mcp.server.fastmcp import FastMCP

from traffic_mcp.client import GatewayClient
from traffic_mcp.filter import compile_filter, flow_url

mcp = FastMCP("trafficdeck-mcp", host=os.environ.get("MCP_HOST", "127.0.0.1"),
              port=int(os.environ.get("MCP_PORT", "8765")))

_SOURCE_KIND = {0: "unspecified", 1: "chrome", 2: "mitmproxy",
                3: "android_emulator", 4: "android_device", 5: "generic"}
_STATUS = {0: "unspecified", 1: "open", 2: "decoding", 3: "closed", 4: "error"}

# Cap inline text returned to the model so a huge body can't blow the context.
_PREVIEW_MAX = 4096
_BODY_MAX = 256 * 1024

_client: GatewayClient | None = None


def client() -> GatewayClient:
    global _client
    if _client is None:
        _client = GatewayClient(os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080"))
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
        "source_kind": _SOURCE_KIND.get(s.source_kind, "?"),
        "status": _STATUS.get(s.status, "?"),
        "created_at_unix_ms": s.created_at_unix_ms,
        "closed_at_unix_ms": s.closed_at_unix_ms or None,
        "flow_count": s.flow_count,
        "pcap_bytes": s.pcap_bytes,
        "keylog_bytes": s.keylog_bytes,
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
        "favorite": f.favorite,
        "mark_color": f.mark_color or None,
        "tags": [tagnames.get(t, t) for t in f.tag_ids],
        "groups": [groupnames.get(g, g) for g in f.group_ids],
        "comments": [c.body for c in f.comments],
    }


def _headers(hs) -> list[dict]:
    return [{"name": h.name, "value": h.value} for h in hs]


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
    return {"content_type": body.content_type or None, "size": body.size}


def _body_meta(body) -> dict | None:
    """Body metadata + an inline text/preview (full bytes via get_body)."""
    if body is None or body.size == 0:
        return None
    meta = {"content_type": body.content_type or None, "size": body.size}
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
    d["request_headers"] = _headers(f.request_headers)
    d["response_headers"] = _headers(f.response_headers)
    d["request_body"] = _body_meta(f.request_body)
    d["response_body"] = _body_meta(f.response_body)
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


def _matches(f, *, domain: str, method: str, content_type: str, status: int,
             path_contains: str, url_contains: str, websocket, has_response) -> bool:
    """Predicate for `search`: all given criteria ANDed. Substring fields are
    case-insensitive; method/status are exact; websocket/has_response are tri-state."""
    if domain and domain.lower() not in (f.authority or "").lower():
        return False
    if method and method.upper() != (f.method or "").upper():
        return False
    if content_type and content_type.lower() not in (f.content_type or "").lower():
        return False
    if status and f.status != status:
        return False
    if path_contains and path_contains.lower() not in (f.path or "").lower():
        return False
    if url_contains and url_contains.lower() not in flow_url(f).lower():
        return False
    if websocket is not None and bool(f.websocket) != websocket:
        return False
    if has_response is not None and bool(f.status) != has_response:
        return False
    return True


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
    """List all recorded capture sessions (id, label, status, flow count, sizes)."""
    return [_session_dict(s) for s in await client().list_sessions()]


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


@mcp.tool()
async def search(session_id: str = "", domain: str = "", method: str = "",
                 content_type: str = "", status: int = 0, path_contains: str = "",
                 url_contains: str = "", websocket: bool | None = None,
                 has_response: bool | None = None, limit: int = 100) -> list[dict]:
    """Combined structured search over flows — every criterion you pass is ANDed in
    one query, e.g. domain="api.oneme.ru" + method="POST" + content_type="json".

    `domain`, `content_type`, `path_contains`, `url_contains` are case-insensitive
    substrings; `method` is exact (case-insensitive); `status` is an exact HTTP code
    (0 = any); `websocket`/`has_response` are tri-state (omit = any). Leave
    `session_id` empty to search across every session (each result carries its
    `session_id`/`session_label`). Returns time-ordered flow summaries (no
    headers/bodies — use get_flow / get_body / export_request for those).
    """
    tagnames, groupnames = await _name_maps()
    crit = dict(domain=domain, method=method, content_type=content_type, status=status,
                path_contains=path_contains, url_contains=url_contains,
                websocket=websocket, has_response=has_response)

    if session_id:
        sessions = [(await _resolve_session(session_id), None)]
    else:
        sessions = [(s.id, s.label) for s in await client().list_sessions()]

    out: list[dict] = []
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
        for f in flows:
            if not _matches(f, **crit):
                continue
            row = _flow_summary(f, tagnames, groupnames)
            row["session_id"] = sid
            if label is not None:
                row["session_label"] = label
            out.append(row)
            if len(out) >= limit:
                return out
    return out


@mcp.tool()
async def search_flows(session_id: str, filter: str = "", limit: int = 100) -> list[dict]:
    """Search a session's flows with a mitmproxy-style filter expression.

    Terms (ANDed, `!` negates): ~m method, ~d host, ~u url, ~c status, ~t content-type,
    ~s/~q has/no response, ~fav, ~mark <color>, ~tag <name>, ~group <name>,
    ~comment <regex>; a naked regex matches the URL. Empty filter returns all flows.
    Returns flow summaries (no headers/bodies — use get_flow for those). For plain
    field matching prefer the structured `search` tool.
    """
    flows = await client().list_flows(await _resolve_session(session_id))
    tagnames, groupnames = await _name_maps()
    pred = compile_filter(filter, tagnames, groupnames)  # raises ValueError on bad expr
    if pred is not None:
        flows = [f for f in flows if pred(f)]
    return [_flow_summary(f, tagnames, groupnames) for f in flows[:limit]]


@mcp.tool()
async def get_flow(session_id: str, flow_id: str) -> dict:
    """Full detail for one flow: headers (wire order), body previews, annotations."""
    f = await client().get_flow(await _resolve_session(session_id), flow_id)
    tagnames, groupnames = await _name_maps()
    return _flow_detail(f, tagnames, groupnames)


@mcp.tool()
async def get_body(session_id: str, flow_id: str, response: bool = True,
                   as_hex: bool = False, offset: int = 0) -> dict:
    """Fetch a request or response body. Returns UTF-8 text when decodable, else base64;
    pass `as_hex=True` for a hex dump (byte inspection). A window of up to 256 KiB from
    `offset` is returned (page large bodies with `offset`). Bodies are stored
    decompressed. `response=False` for the request body.

    For a custom-protocol flow (a decoded raw-TCP connection), this returns the original
    *undecoded* bytes: `response=False` = the raw client->server stream, `response=True` =
    the raw server->client stream — the bytes that were fed to the decoder."""
    try:
        data = await client().get_body(await _resolve_session(session_id), flow_id, response)
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.NOT_FOUND:
            return {"size": 0, "note": "no body"}
        raise
    return _bytes_payload(data, as_hex=as_hex, start=offset)


@mcp.tool()
async def list_ws_messages(session_id: str, flow_id: str, limit: int = 100,
                           offset: int = 0) -> dict:
    """WebSocket message timeline for an Upgrade flow: directional frames in order
    (direction, opcode, size, text/hex preview). Paginated — `total` is the frame count;
    page with `offset`/`limit` (default 100) to avoid huge responses. Large payloads
    carry a note; fetch them in full with get_ws_message_body using the message `id`.

    When a custom decoder handled the connection, a message's payload is the decoded form
    and `has_raw` is true — fetch the original undecoded bytes with
    get_ws_message_body(message_id, raw=True)."""
    sid = await _resolve_session(session_id)
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
            "body": _body_ref(f.response_body),
        },
    }
    if f.websocket:
        out["websocket"] = {"message_count": f.ws_message_count}
    return out


def main() -> None:
    # MCP_TRANSPORT: streamable-http (default), sse, or stdio. The HTTP transports bind
    # MCP_HOST:MCP_PORT (default 127.0.0.1:8765) and serve at /mcp; set stdio to speak
    # the protocol over stdin/stdout instead.
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
