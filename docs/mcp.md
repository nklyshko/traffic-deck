# MCP server (for LLM/agent clients)

`trafficdeck-mcp` exposes recorded sessions over the Model Context Protocol, backed by the
gateway's `ViewerService` (it never touches SQLite directly, so it works against a local
or remote gateway).

```sh
mcp/run.sh                                            # GATEWAY_ADDR / MCP_PORT overridable
# or: GATEWAY_ADDR=127.0.0.1:7331 uv run --directory mcp python -m traffic_mcp.server
```

Defaults to the `streamable-http` transport, binding `MCP_HOST:MCP_PORT` =
`127.0.0.1:8765` and serving the MCP endpoint at `/mcp`. For a client that speaks MCP over
stdio instead, set `MCP_TRANSPORT=stdio` (other value: `sse`):

```sh
MCP_TRANSPORT=stdio mcp/run.sh
```

The gateway can also own the server, so it outlives the viewer: `GATEWAY_MCP=true` at
launch, or `X` on the TUI's sessions screen.

## Tools

`list_sessions` + `list_session_groups`, `network_timeline` (the request sequence, like
the DevTools Network tab), `search` (structured, combined domain/method/content-type/
status/… in one query), `search_flows` (the [filter DSL](filters.md)), `get_flow`,
`get_body` (text/base64/`as_hex`), `compare_flows` (diff two requests, across sessions),
`export_request` (request+response headers, no bodies), `export_client_hellos` (a flow's
raw TLS ClientHello bytes), `list_ws_messages` + `get_ws_message_body` (WebSocket frames;
`as_hex` for byte inspection). Session args accept an id prefix.

It runs **read-only by default**: only the inspection tools above are exposed. Set
`MCP_READONLY=0` to additionally expose the mutating tools `rename_session` and
`set_session_group` (relabel / regroup a recorded session).

## Paging

`network_timeline`, `search` and `search_flows` page by **cursor**, not offset: pass the
returned `next_cursor` back to continue, or omit it to start at the beginning. A cursor is
stable while a live session grows under it, which an offset is not.

`total` is how many flows match, and is a **lower bound** when the result says so
(`count_capped` on `search_flows`, `complete: false` / `scan_limited` on `search`) —
counting stops at the gateway's scan budget rather than scanning a whole session to
produce an exact number. See [ADR-0012 §5](adr/0012-server-side-filtering-and-pagination.md).

## `search`

The one to reach for on a large capture. Criteria are ANDed in a single query:

- `status` (one code) or `status_in` (a set — `401,403`, `400-499`, `4xx,500-503`)
- `since`/`until` — ISO-8601, a clock time today like `06:08`, a relative `-15m`, or a
  unix epoch number. Bare times are local, for lining up with an application log.
- `domain` / `method` / `content_type` / `path_contains` / `url_contains`
- `websocket` / `has_response` — tri-state; omit for either
- content search over what was actually sent: `request_header_contains`,
  `response_header_contains`, `request_body_contains`, `response_body_contains` — so a
  `Set-Cookie` name or a marker string in HTML is found without fetching each flow.

Leave `session_id` empty to search **every session** at once; each hit carries its
`session_id`/`session_label`. Every hit also carries a `match_preview` showing the matched
substring in context.

Criteria are compiled into one filter expression and evaluated in the gateway, which orders
the work by cost — columns, then headers, then bodies — so narrowing with the metadata
criteria is what keeps a content search cheap. It examines at most `max_scan` candidates
(default 400) and reports `scanned`/`scan_limited` when it stops early. Scanning restarts
from the beginning on a later page, so prefer one query with a bigger `limit` over walking
many pages.

## Live sessions

Sessions still being captured are readable too: flows, WebSocket frames and bodies are
served from the live decode until the session closes and they are persisted. Under
record-live (the default) bodies come back whole at any size; with `GATEWAY_RECORD_LIVE=off`
the live decode keeps only the first 256 KiB of a body, and `get_body` marks what it
returns `partial` — fetch it again once the session closes for all of it.
