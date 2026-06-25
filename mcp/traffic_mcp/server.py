"""trafficdeck-mcp: an MCP server exposing recorded traffic sessions to LLM/agent
clients. Backed by the gateway's ViewerService over gRPC — it does not
touch SQLite directly, so it works locally or against a remote gateway.

Run (stdio transport):  GATEWAY_ADDR=127.0.0.1:8080 uv run trafficdeck-mcp
"""

from __future__ import annotations

import base64
import os
import shlex

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


def _curl(f, body: bytes) -> str:
    parts = [f"curl -X {f.method or 'GET'} {shlex.quote(flow_url(f))}"]
    if f.protocol == "HTTP/2":
        parts.append("--http2")
    elif f.protocol == "HTTP/1.1":
        parts.append("--http1.1")
    for h in f.request_headers:
        if h.name.startswith(":") or h.name.lower() == "host":
            continue
        parts.append(f"-H {shlex.quote(f'{h.name}: {h.value}')}")
    if body:
        try:
            text = body.decode("utf-8")
            parts.append(f"--data-raw {shlex.quote(text)}")
        except UnicodeDecodeError:
            parts.append(f"# request body: {len(body)} bytes (binary, omitted)")
    return " \\\n  ".join(parts)


# --- tools ---------------------------------------------------------------

@mcp.tool()
async def list_sessions() -> list[dict]:
    """List all recorded capture sessions (id, label, status, flow count, sizes)."""
    return [_session_dict(s) for s in await client().list_sessions()]


@mcp.tool()
async def search_flows(session_id: str, filter: str = "", limit: int = 100) -> list[dict]:
    """Search a session's flows with a mitmproxy-style filter expression.

    Terms (ANDed, `!` negates): ~m method, ~d host, ~u url, ~c status, ~t content-type,
    ~s/~q has/no response, ~fav, ~mark <color>, ~tag <name>, ~group <name>,
    ~comment <regex>; a naked regex matches the URL. Empty filter returns all flows.
    Returns flow summaries (no headers/bodies — use get_flow for those).
    """
    flows = await client().list_flows(session_id)
    tagnames, groupnames = await _name_maps()
    pred = compile_filter(filter, tagnames, groupnames)  # raises ValueError on bad expr
    if pred is not None:
        flows = [f for f in flows if pred(f)]
    return [_flow_summary(f, tagnames, groupnames) for f in flows[:limit]]


@mcp.tool()
async def get_flow(session_id: str, flow_id: str) -> dict:
    """Full detail for one flow: headers (wire order), body previews, annotations."""
    f = await client().get_flow(session_id, flow_id)
    tagnames, groupnames = await _name_maps()
    return _flow_detail(f, tagnames, groupnames)


@mcp.tool()
async def get_body(session_id: str, flow_id: str, response: bool = True) -> dict:
    """Fetch a full request or response body. Returns UTF-8 text when decodable, else
    base64 (both capped). `response=False` for the request body."""
    try:
        data = await client().get_body(session_id, flow_id, response)
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.NOT_FOUND:
            return {"size": 0, "note": "no body"}
        raise
    out: dict = {"size": len(data), "truncated": len(data) > _BODY_MAX}
    data = data[:_BODY_MAX]
    try:
        out["encoding"] = "utf-8"
        out["text"] = data.decode("utf-8")
    except UnicodeDecodeError:
        out["encoding"] = "base64"
        out["base64"] = base64.b64encode(data).decode("ascii")
    return out


@mcp.tool()
async def list_ws_messages(session_id: str, flow_id: str) -> list[dict]:
    """WebSocket message timeline for an Upgrade flow: directional frames in order
    (direction, opcode, size, text/hex preview)."""
    msgs = await client().list_messages(session_id, flow_id)
    out = []
    for m in msgs:
        size = m.payload.size if m.payload else 0
        item = {
            "id": m.id,
            "ts_unix_micros": m.ts_unix_micros,
            "direction": "client->server" if m.from_client else "server->client",
            "opcode": m.opcode,
            "size": size,
        }
        if m.payload and m.payload.WhichOneof("content") == "inline":
            data = m.payload.inline
            try:
                item["text"] = data.decode("utf-8")[:_PREVIEW_MAX]
            except UnicodeDecodeError:
                item["hex_preview"] = data[:64].hex()
        out.append(item)
    return out


@mcp.tool()
async def export_curl(session_id: str, flow_id: str) -> str:
    """Reconstruct a flow's request as a runnable curl command (preserves header
    order; HTTP version pinned). Textual request bodies are inlined as --data-raw."""
    f = await client().get_flow(session_id, flow_id)
    try:
        body = await client().get_body(session_id, flow_id, response=False)
    except Exception:  # noqa: BLE001 (no request body)
        body = b""
    return _curl(f, body)


def main() -> None:
    # MCP_TRANSPORT: stdio (default), streamable-http, or sse. HTTP transports bind
    # MCP_HOST:MCP_PORT (default 127.0.0.1:8765).
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
