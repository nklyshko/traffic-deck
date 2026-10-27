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
`get_body` (text/base64/`as_hex`), `grep_bodies` (a regex over the bodies a filter
selects: per-flow counts, hits with byte offsets, and which flows have none),
`save_body` (a whole body to a fresh temp file, for another program), `compare_flows` (diff two requests, across sessions),
`export_request` (request+response headers, no bodies), `export_client_hellos` (a flow's
raw TLS ClientHello bytes), `list_ws_messages` + `get_ws_message_body` (WebSocket frames;
`filter` takes the [message dialect](filters.md#filtering-a-message-timeline), `as_hex`
for byte inspection), `wait_for_flows` (block until a live capture decodes new requests),
and `sqlite_query` + `sqlite_schema` (read-only SQL over a session bundle). Session args
accept an id prefix.

It runs **read-only by default**: only the inspection tools above are exposed. Set
`MCP_READONLY=0` to additionally expose the mutating tools — `rename_session` and
`set_session_group` (relabel / regroup a recorded session), and the four capture-control
tools below, which start real processes on this machine. In read-only mode they are not
registered at all, so they never appear in the tool list.

## Driving a capture

With `MCP_READONLY=0` an agent runs the whole loop itself:

```
list_capture_sources → start_capture → (produce the traffic) → wait_for_flows
                                     → stop_capture → network_timeline / search
```

`list_capture_sources` is what will actually work, not what is configured: a source the
user has to start by hand (macOS per-process capture) is left out while its daemon is not
running — see [modules.md](modules.md). `keep_warm` marks a source holding a resource
across captures (an Android emulator), whose first start is slow. Two sources can share one
such resource — `android` and `android-browser` are one emulator, booted once — so having
used either, the other is already warm.

`start_capture(source)` needs nothing else. Every source defaults every option — a browser
source opens a fresh temporary profile — so the parameters are for choosing something
specific, and `describe_capture_source` enumerates them: `{key, label, type, required,
default, choices}`, values always strings (`"true"`/`""` for a bool). That form
**cascades** — answering one option changes which options come back next — so pass the
answers so far and call again until nothing new appears.

The response reports `params_sent`: what actually reached the source, including anything
the server added, rather than an echo of the request.

**An agent cannot drive the browser the gateway launched** — there is no debugging port to
attach to, and the profile is a throwaway. Two things do work: a browser source takes a
`url`, which is the simplest way to make a capture produce traffic from this server alone;
or use the `mitmproxy` source and point the agent's own browser at the proxy, accepting
that a terminating proxy costs the real client fingerprint and the `conn`/`stream` columns.
The `android-browser` source is the same bargain aimed at a phone or emulator, and is the
only way to read a Chromium browser's traffic there at all.
See [ADR-0015](adr/0015-agents-drive-capture-over-mcp.md).

```python
# a self-contained capture: open a page, wait for it to decode, read it back
started = start_capture("chrome", label="checkout", params={"url": "https://example.com"})
wait_for_flows(started["session_id"], filter="~u /api ~s", count=5)
done = stop_capture(started["session_id"])      # flow_count/pcap_bytes are final here
network_timeline(done["id"])
```

`start_capture` **auto-stops after five minutes by default**: nothing in the gateway closes
an abandoned session, so a capture whose caller stops calling would hold a browser open
indefinitely. It applies only when the source offers that option — a proxy source does not
— and `auto_stop_seconds` on the response says which happened, with a `note` when there is
none. `duration_seconds=0` opts out; stopping early is always allowed.

`stop_capture` returns the finished session, so `flow_count` and `pcap_bytes` are final on
return and there is no second round trip to learn what was recorded. Only captures this
gateway started can be stopped — one launched from a command line has to be stopped there.

The first describe or start of a source *starts* it, which on a cold environment can take a
minute (the built-ins launch through `uv`, which builds their dependencies first). The
calls allow for that; a client with its own short tool timeout may not.

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
`blobs.bytes` means it spilled to a file, so bodies come from `get_body`. A statement
that reads `bytes` gets `bodies_stored_as_files` with the count it could not see — a
`LIKE` over `bytes` misses precisely the large pages, and zero rows must not read as
"absent". For content questions use `search`, `search_flows` or `grep_bodies`. Prefer
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
substring in context; a body hit adds `<field>_at`, its byte offset, for
`get_body(offset=…)`. Body criteria read the whole body, however large.

`search` only says "contains". For "lacks" use `search_flows` with a negated term
(`!~bs marker`), or `grep_bodies`, which lists every selected flow with its hit count —
zero included — so "which of these page loads lack the marker" is one call.

Criteria are compiled into one filter expression and evaluated in the gateway, which orders
the work by cost — columns, then headers, then bodies — so narrowing with the metadata
criteria is what keeps a content search cheap. It examines at most `max_scan` candidates
(default 400) and reports `scanned`/`scan_limited` when it stops early. Scanning restarts
from the beginning on a later page, so prefer one query with a bigger `limit` over walking
many pages.

## Compressed bodies

Bodies are stored decoded, whatever the protocol carried them: a body sent `gzip`, `br`,
`deflate` or `zstd` is searchable as text and `get_body` returns it readable. What it
arrived as is kept alongside it as `content_encoding` on the body metadata (`get_flow`,
`export_request`), so a readable body still says where it came from — the field is
provenance, not a statement about the bytes you are holding.

Two cases are left compressed, both of them deliberate. A **chain** (`gzip, br`) is
recorded verbatim and never unwrapped. An encoding **newer than the gateway build** is
unknown to it. And one case is left compressed on purpose even though we could try: a body
whose label and bytes disagree. `br` and raw `deflate` carry no header to check, so a
decode of a mislabelled body is kept only if it comes back clean — garbage in the body
would be worse than a body that is merely unsearchable.

Body search reads the stored bytes, so it cannot match inside what stayed compressed. That
used to be silent: a `response_body_contains` over a brotli page reported *no match* for
text that was sitting right there. `search` and `search_flows` now report it when the
criteria read a body:

```json
"unsearchable_bodies": {"gzip, br": 3},
"unsearchable_bodies_note": "3 body/bodies … a miss on those is 'unknown', not 'absent' …"
```

Match on headers or the URL for those, or re-capture. Decoding happens when a body is
stored, so a session recorded by an older gateway keeps whatever it kept. If it still has
its pcap, `trafficdeck import --pcap … --keylog …` decodes it again into a new session;
`redecode` will not, as it replaces only custom-protocol flows.

## Live sessions

Sessions still being captured are readable too: flows, WebSocket frames and bodies are
served from the live decode until they are persisted, and bodies come back whole at any
size.

A body search on a live session reads the same bodies, whether a flow is still only in
memory or already written with its body held back for a flush cycle — a page searched for
right after it loaded is found.
