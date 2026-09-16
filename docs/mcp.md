# MCP server (for LLM/agent clients)

`trafficdeck-mcp` exposes recorded sessions over the Model Context Protocol, backed by the
gateway's `ViewerService` (it never touches SQLite directly, so it works against a local
or remote gateway).

The gateway starts it for you and owns it, so it is up the moment `trafficdeck` is and it
outlives the viewer. `X` on the TUI's sessions screen stops and restarts it;
`GATEWAY_MCP=off` keeps it down from the start. If no launcher can be found (no `uv` with
the repo's `mcp/` dir, no `trafficdeck-mcp` on `PATH`, no `TRAFFICDECK_SERVICE_MCP`) the
gateway logs that and starts without it.

To run one yourself instead — against a standalone or remote gateway:

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

## Tools

`gateway_status` (is it up, and how much does it hold), `list_sessions` +
`list_session_groups`, `network_timeline` (the request sequence, like
the DevTools Network tab), `search` (structured, combined domain/method/content-type/
status/… in one query), `search_flows` (the [filter DSL](filters.md)), `get_flow`,
`get_body` (text/base64/`as_hex`), `compare_flows` (diff two requests, across sessions),
`export_request` (request+response headers, no bodies), `export_client_hellos` (a flow's
raw TLS ClientHello bytes), `list_ws_messages` + `get_ws_message_body` (WebSocket frames;
`filter` takes the [message dialect](filters.md#filtering-a-message-timeline), `as_hex`
for byte inspection), `wait_for_flows` (block until a live capture decodes new requests),
and `sqlite_query` + `sqlite_schema` (read-only SQL over a session bundle). Session args
accept an id prefix.

It runs **read-only by default**: only the inspection tools above are exposed. Set
`MCP_READONLY=0` to additionally expose the mutating tools `rename_session` and
`set_session_group` (relabel / regroup a recorded session).

## Driving a capture

`wait_for_flows` blocks until new flows are decoded, so an agent can act and then read
what its action produced instead of polling `network_timeline`: fire the traffic, call it,
read the summaries. Only flows decoded *after* the call count, and `count`/`timeout_seconds`
bound the wait (`1` / `30` by default, `timed_out` says which ended it).

`session_id` is required — only a session still capturing has anything to wait for, and
`gateway_status` lists those under `capturing`. Naming one that isn't capturing returns
immediately rather than spending the timeout: `status` says which state it is in, and the
`note` separates a capture that is **over** (`closed`/`error` — read it with
`network_timeline`) from a pcap import still **decoding** (not live, readable shortly).

One case only waiting can resolve: a session that is `open` but has no live decode behind
it — an upload-on-close capture, or `GATEWAY_LIVE_DECODE=off` — looks exactly like a
capture that is merely idle. That one times out, and the `note` names all three reasons
(idle capture, filter matches nothing, no live decode) instead of reporting a bare zero.

Pass a `filter` to wait for a *particular* request rather than the next one — the same
[DSL](filters.md), and a flow that only starts matching once its response arrives counts
then, so `~c 200` waits for a success and `~u /api/login ~s` for that endpoint to answer.

`session_closed` means the capture ended while waiting. `missed_events` means the gateway
had to drop events to keep up, so the result is incomplete — re-read the tail with
`network_timeline` rather than trusting `count`.

## SQL over a bundle

`sqlite_query` runs one **read-only** statement against a session's `flows.sqlite`, for
the questions the other tools don't ask — aggregates, joins, distributions:

```sql
SELECT authority, COUNT(*) n, SUM(status >= 400) errs FROM flows GROUP BY authority
SELECT name, COUNT(*) FROM flow_headers WHERE direction = 0 GROUP BY name ORDER BY 2 DESC
```

`sqlite_schema` lists the tables and their `CREATE` statements; an empty `session_id`
addresses the global catalog (`sessions`, `tags`, `groups`) instead of a bundle. Values
belong in `params`, bound to `?` placeholders. At most `limit` rows come back (200 by
default, 2000 max, `truncated` when more matched) and the query is abandoned after
`timeout_seconds`.

Writes are refused by SQLite itself — the gateway opens the file `mode=ro` with
`query_only` and no attachable databases, so a `DELETE` errors rather than touching the
capture, and nothing in the statement is pattern-matched to decide that.

Two caveats, both from reading the bundle as it sits on disk: a session still **capturing**
is missing its unflushed tail (flows are persisted incrementally, so a count here runs
slightly behind `search`), and a body is only inline in `blobs` when it was small — a NULL
`blobs.bytes` means it spilled to a file, so bodies come from `get_body`. Prefer
`search`/`search_flows` for "which flows match": they page by cursor and return bodies,
annotations and the live tail.

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

## Compressed bodies

Bodies are stored decoded, whatever the protocol carried them: a body that was gzipped on
the wire is searchable as text and `get_body` returns it readable. What it arrived as is
kept alongside it as `content_encoding` on the body metadata (`get_flow`,
`export_request`), so a readable body still says where it came from. Only the encodings
the gateway can undo are undone — a brotli (`br`) body is stored as it was sent, and its
`content_encoding` is what tells you that the bytes are compressed rather than binary
content. Body search sees the stored bytes, so it can't match inside one.

## Live sessions

Sessions still being captured are readable too: flows, WebSocket frames and bodies are
served from the live decode until the session closes and they are persisted. Under
record-live (the default) bodies come back whole at any size; with `GATEWAY_RECORD_LIVE=off`
the live decode keeps only the first 256 KiB of a body, and `get_body` marks what it
returns `partial` — fetch it again once the session closes for all of it.
