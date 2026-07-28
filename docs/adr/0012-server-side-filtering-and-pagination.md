# 0012 — Filtering and pagination happen in the gateway

Status: proposed. Depends on [0011](0011-incremental-flow-persistence.md), which is what
makes this possible for a session that is still open.

## Context

The filter DSL is evaluated in the viewer, against a complete in-memory copy of the
session. `FlowsScreen` says so plainly — `flow id -> cached Flow (the whole session)` —
and `_rebuild_view` re-runs the predicate over every flow in the session, not just the
rendered page. The pagination added in `770ce4f` bounds how many rows Textual *renders*,
which is a real win for redraw cost, but it is render-only: the model behind it still
holds everything.

Measured with the real generated protos, at ~22 headers per flow:

| Viewer holds | Per flow | At 273k flows |
|---|---|---|
| flow + headers | 3.1 KB | ~850 MB |
| plus a 4 KB inline body | 10.3 KB | ~2.8 GB |

The live path inlines bodies up to `InlineBlobMax` (1 MiB) into every flow event, so the
second row is a mild case, not a worst case. [0011](0011-incremental-flow-persistence.md)
bounds what the *gateway* retains and does nothing about this: the viewer's copy arrives
over the wire and is a second, independent accumulation.

The MCP server has the same shape in a different form. `list_flows` accumulates every
`flow_added` into a list, and `network_timeline` fetches the whole session before slicing
`flows[offset:offset+limit]` — an `offset`/`limit` API that reduces no work and
re-materializes the session on every page.

Two more things push the same way. The DSL is implemented **twice**, independently, in
`tui/traffic_viewer/filters.py` and `mcp/traffic_mcp/filter.py`, and the two have already
drifted: MCP's term list is missing `~conn`, `~stream` and `~meta`. And a third-party
viewer ([0008](0008-independent-capture-apps.md)) would have to write a third.

Until now none of this could move server-side, for a reason that had nothing to do with
filtering: an open session's flows lived only in the live hub, so there was nothing to
query. [0011](0011-incremental-flow-persistence.md) puts them in the bundle while capture
runs, and thereby makes this decision available.

## Decision

The gateway owns the filter language and serves pages; viewers hold a page, not a session.

**1. One evaluator, in Go, applied to a scan — not a translation to SQL.** The obvious
design is to compile the DSL into a `WHERE` clause, and it is the wrong one here. Live
event fan-out has to filter per subscriber before sending, and the unflushed tail is not
in SQLite, so a SQL translation still needs a Go predicate beside it — and the project is
back to two implementations of one language, differing in the subtle direction (SQL
`LIKE`/collation semantics versus a regex engine). A single Go predicate, applied to rows
as they stream out of SQLite and stopping when the page fills, keeps stored rows, the
live tail and the event stream provably identical.

The scan is affordable, which is what makes this choice available rather than merely
principled. Measured over 100k stored flows, matching a regex against a URL composed in Go
from `scheme`/`authority`/`path`/`query`: **143 ms for a full scan** (1.43 µs/row), and
110 ms to fill a 250-row page. A worst-case filter over a 273k-flow session — one matching
nothing, scanning everything — lands near 390 ms. For comparison that is roughly 20×
cheaper per row than `ListFlows` is today (~31 µs/row), because a lean column scan skips
proto construction and the annotation/metadata/ws-count attach passes. Filtering this way
costs less than what a session open already costs.

Terms backed by side tables (`~tag`, `~mark`, `~comment`, `~meta`) are loaded into maps
before the scan rather than joined per row — the pattern `attachAnnotations` already uses,
where each side table is read with one whole-table query.

**2. Cheap terms still narrow in SQL.** The predicate is the semantics; indexes are an
optimization under it. Terms that map directly to an indexed column — `~d` (authority),
`~c` (status), `~s`/`~q` — are pushed into the `WHERE` as a coarse pre-filter, with the
full predicate applied to what comes back. Correctness never depends on that push, so it
can be extended term by term without risk.

**2a. Body content becomes a first-class term, evaluated last.** The DSL has never been
able to match a body, and not by oversight: filtering ran in the viewer, which holds only
the bodies it happened to be sent, so the term was unimplementable. Evaluating in the
gateway puts the predicate in the same process as the bundle that stores them, and the
term becomes ordinary. Following the mitmproxy naming the rest of the DSL already tracks:
`~b <re>` matches either direction, `~bq` the request body, `~bs` the response.

It is the one term that cannot be cheap — no index can serve it, and it reads a blob per
candidate row — so it is ordered last: a body is fetched only for a row that has already
passed every other term. It is bounded the way MCP's content search is bounded today, and
for the same reasons: a per-query scan cap, a per-body ceiling above which a body is
skipped rather than read, and a result that says when either applied.

This retires the parallel mechanism rather than sitting beside it. MCP's `_body_text` /
`_deep_match` are deleted, and with them the coupling
[0011](0011-incremental-flow-persistence.md) §3a had to record and could not enforce —
that `InlineBlobMax` stays below `_SCAN_FETCH_MAX`, or content search silently stops
matching. Nothing outside the gateway reads `inline` to match a body any more, so the
hazard stops existing rather than being documented.

**3. Regexes are RE2, and incompatible ones are rejected, not silently re-interpreted.**
The viewers compile with Python's backtracking `re`; the gateway has Go's RE2. Lookarounds
and backreferences are accepted today and cannot be. They are refused at compile time with
an error naming the construct — never accepted-and-behaving-differently. The viewers'
case-insensitive matching (`re.IGNORECASE`) must be preserved explicitly on the Go side;
losing it would change the meaning of every filter already in use.

**4. Two RPCs: paging is a request, liveness is a stream — and a filter applies to both.**
`QueryFlows(session, filter, cursor, limit) → FlowPage` serves a page;
`StreamFlows(session, filter, follow)` serves events. **Filtering and following compose:**
a viewer sets a filter and follows at the same time, and the stream carries only events
for flows matching that filter. The split is about paging leaving the stream, not about
filtering leaving it.

A viewer therefore does both: `QueryFlows` for the rows to display, `StreamFlows` to stay
current. Follow mode pins the viewer to the tail of the *matching* set, which is what the
existing follow behaviour already means (it jumps to the last page and stays there).

Overloading today's single `StreamFlows` with cursor and limit was rejected: it already
does backfill and follow, and a `limit` on a stream that also follows has no coherent
meaning. A bidi page-request stream was rejected for the reason
[0010](0010-supervisor-and-capture-modules.md) already gave when it chose unary calls over
a command stream — a unary call is far easier to debug than correlating responses.

`StreamFlowsRequest.include_backfill` goes at the same time. It is already dead — both
clients set it and the server has never read it, always backfilling — and with backfill
becoming `QueryFlows`' job there is nothing left for it to have meant. Removing it is
part of the same breaking change rather than a field carried forward for compatibility
with behaviour that never existed.

**5. Pagination is keyset; totals are capped and honest.** A live session grows while it
is read, so `OFFSET` shifts rows under the cursor. Paging on `(ts_micros, frame_number)`
against the existing `flows_ts_idx` is stable under append and matches the order the table
already displays.

An exact "N matching" needs a full scan of the matching set on every query, so the count is
reported against the scan cap instead: a total, plus whether the cap was reached. A viewer
shows `500+ matching` rather than a precise number it cannot cheaply have — and never a
number that is quietly wrong. This is MCP's existing `scanned`/`scan_limited` convention
rather than a new one.

**Navigation never consults that total.** "Last" means the end of the list, not the Nth
page of a count: it is a query in descending key order from the end, reversed for display.
First is the same query ascending from the start, and next/prev step the cursor. Every
movement is therefore answerable without knowing how many rows match, which is what lets
the total stay approximate without making the UI lie. It also makes "jump to last" and
follow mode the same operation — both are the tail of the matching set.

The consequence is that *page numbers* stop being meaningful, and the viewer should stop
implying them. A window into a list has a position ("showing 250 of 500+"), not an index
("page 3 of 12"), because the denominator is exactly the thing that is unknowable cheaply.

**6. Membership changes are explicit: a flow that stops matching is retracted.** Once the
viewer no longer holds the predicate it cannot know that an update pushed a row out of its
view — only the gateway can, having evaluated the filter before and after. `FlowEvent`
gains a variant carrying just an id:

    string flow_unmatched = 5;   // no longer matches *this subscription's* filter

The name is deliberate. This means "stopped matching your filter", **not** "was deleted":
the flow still exists and a subscriber with a different filter still sees it. The opposite
direction needs nothing new — a flow that starts matching is a `flow_added` the viewer has
not seen before.

**7. An annotation edit re-queries the current page.** Tags, marks, favourites and
comments are filterable and mutable, so tagging a flow under `~tag auth` changes the
matching set. The viewer re-runs its current `QueryFlows` after a mutating annotation call.
Pushing the change over the follow stream was rejected as insufficient rather than wrong:
**annotations are editable on closed sessions**, where no live stream exists at all, so a
stream-based mechanism could never be the whole answer. Annotation edits are user-paced, so
a round trip is affordable.

**8. An open session is served as stored page + unflushed tail.** The gateway queries the
bundle, applies the predicate to the tail the flusher has not yet written, and merges in
timeline order. [0011](0011-incremental-flow-persistence.md) is what makes the tail small
enough for this to be uninteresting; without it the "tail" is the whole session.

**9. The DSL's definition moves to the gateway; viewers stop implementing it.** Viewers
send the expression as typed and render what comes back, including the parse errors and
the advisory hints (`filter_hints`) — which are part of the language and belong with it.
This is a breaking change for clients, and is accepted as one: the client-side
implementations are deleted rather than kept as a compatibility path.

## Consequences

- Viewer memory stops scaling with session size. This is the point; the ~850 MB above
  becomes a page.
- **One implementation of the filter language, for every client.** The TUI, MCP and any
  third-party viewer get identical results by construction, and the existing drift
  (`~conn`/`~stream`/`~meta` missing from MCP) is fixed by deletion rather than by
  porting. This is arguably the stronger reason to do this — the memory saving is what
  forced the question, not what makes it right.
- MCP's `network_timeline` `offset`/`limit` becomes real pagination instead of a slice of
  a fully-materialized session, and `search` gains the same page semantics — its content
  criteria becoming DSL terms (§2a) rather than a second search path.
- **The viewer gains body filtering it has never had.** That is a new capability falling
  out of the move, not a stated goal of it, and it is the clearest user-visible reason
  this is worth doing beyond the memory ceiling.
- **The RE2 restriction is user-visible and cannot be hidden.** A filter using a lookahead
  works today and will be refused. That is acceptable only because it is refused loudly;
  the failure mode to avoid is a filter that quietly matches a different set than it used
  to.
- **Running a user-supplied regex on the gateway is a new exposure, and RE2 is what makes
  it safe.** Python's engine backtracks catastrophically on a crafted pattern; RE2 does
  not. This matters more than it looks, because MCP listens on a port
  ([0010](0010-supervisor-and-capture-modules.md)) — a filter expression becomes remote
  input to the gateway's CPU.
- **Filtering becomes an RPC, so the interaction model matters.** Per-keystroke filtering
  would put a round-trip in the typing loop. The TUI already applies on Enter rather than
  per keystroke, so it fits as-is — but that ceases to be a UI preference and becomes a
  constraint the design depends on.
- A filter matching very little costs a scan of the session. Bounded by a scan cap, with
  the result reporting that it was capped — the pattern MCP's content search already uses
  (`max_scan`, `scanned`/`scan_limited`) rather than a new one.
- **No schema change is needed, including for `~u`.** The URL is not a stored column, but
  it does not need to be: the predicate composes it in Go from columns already selected,
  and no index could serve a regex anyway. SQLite here (3.53.2) does support `VIRTUAL`
  generated columns, which could be added even to existing bundles by `ALTER TABLE`
  (`STORED` ones cannot) — that option was checked and found unnecessary. Filtering
  therefore works against bundles written before this change.
- **This breaks clients, deliberately.** Viewers that filter locally stop working against
  a gateway that no longer serves whole sessions, and third-party viewers
  ([0008](0008-independent-capture-apps.md)) must adopt the new calls. Accepted: keeping
  the unfiltered whole-session read as a compatibility path would preserve exactly the
  behaviour this decision exists to remove.
- Annotation names (`~tag`, `~group`) resolve locally: tags and groups are mirrored into
  each bundle so it stays self-contained, so no cross-database join is required.
- The viewer keeps only the flows of the current page, so actions that assumed a
  whole-session model in memory — select-all, cross-page compare — need explicit page or
  server semantics rather than inheriting them.
- **The flow table stops being paginated and becomes a window.** `_page_count`,
  `_goto_page` and the `X–Y of Z` subtitle are built on a known total; under a capped
  count they would have to invent a denominator. They are replaced by cursor movement
  (first / last / next / prev) and a position, which is both honest and simpler than what
  they replace — the render-only pagination in `770ce4f` was already a window in
  everything but its arithmetic.
- **`FlowEvent` gains a variant, so every event consumer must handle an unknown one.** A
  client that ignores `flow_unmatched` silently shows rows that no longer match — the
  failure is a stale view, not an error, which makes it worth an explicit check in each
  viewer rather than a default case.
- **The gateway now evaluates a filter per subscriber on every published flow.** With many
  followers on a busy session that is real work on the publish path, where today the
  fan-out is a channel send. Predicates are compiled once per subscription, and the same
  RE2 linear-time guarantee that makes a remote filter safe also bounds this — but the
  cost sits in the decoder's path, not in a reader's.
