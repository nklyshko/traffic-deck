# 0011 — Live-decoded flows persist incrementally, not on close

Status: proposed. Amends [0009](0009-native-live-decode-default.md), which made
record-live authoritative but left *when* it writes unstated.

## Context

[0009](0009-native-live-decode-default.md) made the native live decoder authoritative and
said its flows are "persisted on close". That phrasing hid a design choice nobody
decided: for the whole life of a capture, an open session exists **only in memory**. The
live hub (`internal/server/live.go`) holds, per session, the full `decode.Flow` for every
flow (`dflows`), a second proto copy of each (`flows`), and every WebSocket frame with
both its decoded payload and its raw bytes inline. Nothing is evicted, and nothing
reaches SQLite until `CloseSession` runs `persistLive` — one transaction over the entire
session.

Record-live also lifts the live body cap (`SetUnlimitedLiveBodies`, `server.go:360-363`),
because the live decode *is* the record and a 256 KiB preview would lose data. Correct in
itself, but combined with retain-everything it means the gateway holds every
fully-decompressed request and response body of the entire capture.

A real session made the consequences concrete: 273k flows from a 6.2 GB pcap, ~20 GB
resident, and a close that took several minutes.

Measuring the parts separated two problems that looked like one:

- `InsertFlows` costs roughly 200 µs/flow, and scales **linearly** — about 60 s at 273k
  flows. Preparing each distinct statement once per transaction and batching header
  inserts (commit `553afc8`) cut that to ~145 µs/flow. Worth having, but it means
  statement overhead was never the dominant term.
- What is left — the multi-minute close and the 20 GB — is **body volume and memory
  pressure**: a sha256 over every uncapped body, a separate file per body above
  `InlineBlobMax`, several full copies of the flow set live at once, and a GC working set
  far past what the machine can hold comfortably.

So the fix is not a faster write path. It is to stop accumulating.

One obstacle shapes everything below: **the live decoders never signal that a flow is
complete.** `onFlow(f, isNew)` fires when the request is seen, again on the response,
again on an error, and once per WebSocket frame — and it mutates one `decode.Flow` in
place across those calls. The `reqBodyFinal`/`respBodyFinal` fields look like the signal
but are set only by the batch stitcher (`internal/decode/stitch.go`); the live path never
touches them. Incremental persistence therefore cannot be "write each flow once when it
finishes."

## Decision

Persist an open session's flows continuously during capture, and hold in memory only what
has not been written yet.

**1. A dirty set, flushed on a threshold.** `onFlow` marks a flow id dirty rather than
merely accumulating it. A flusher goroutine wakes on whichever comes first — **128 dirty
flows, or 2 s** — snapshots the dirty ids and their flows under the session lock,
**releases the lock**, and writes them with `InsertFlows`. Coalescing by id is what keeps
a chatty WebSocket flow from writing once per frame. The lock must never be held across
SQLite I/O: the decoder publishes through that same mutex, so holding it would stall
decode behind disk.

128 is a starting value, chosen small deliberately: it keeps the in-flight window at a
few hundred flows rather than optimising write throughput, because the ceiling is the
thing being bought here. The 2 s idle interval is the companion bound that keeps a slow
session from holding a partial batch indefinitely. Both are expected to move once
measured against a large capture; the memory ceiling they imply is the part that is a
commitment, not the numbers themselves.

**2. Re-writing an evolving flow is the normal case, not an error.** A flow flushed after
its request and again after its response is written twice. `InsertFlows` is already an
upsert that clears and rewrites the side tables, precisely because the mitmproxy
`PushFlows` path (`internal/server/ingest.go`) pushes a flow request-first and then again
with its response. That path is the existing proof that incremental writes into these
tables work; the live path adopts it rather than inventing a second scheme.

**3. Bodies are released from memory once they are on disk — but only when the flow has
settled.** After a successful flush the retained `decode.Flow` drops its body slices and
serves them from the blob store instead. This is the change that reclaims the 20 GB, and
the one with a real failure mode: a response body still streaming accumulates into
`f.ResponseBody`, so nulling it mid-stream would make the next flush write a truncated
body. Bodies are therefore released only for a flow that has gone a full flush cycle
without being dirtied, *and* has a status or an error, *and* is not a WebSocket flow.
Anything still moving keeps its buffer.

The quiet cycle is not belt-and-braces; it is what makes the rule correct. Implementation
showed that "has a status" alone is *false* as a completion test on HTTP/2: `emitLocked`
sets the status when the HEADERS frame lands and then emits again for every DATA frame,
so a flow can carry a status with most of its body still to come. Only a flow that has
also gone a whole cycle unchanged is actually done — on HTTP/1.1 the two coincide, because
the body is fully read before the flow is ever emitted with its status, but the rule may
not be simplified to the status check that path would suggest.

Releasing a body also clears the `inline` bytes from the flow's proto, and that carries a
hard invariant: **clear `Body.inline`; never clear `Body.size` or `Body.content_type`.**
The viewer's detail, view and save paths (`_append_body`, `_view_body`, `BodyScreen`) all
gate on `size` and then fetch the real bytes over `GetBody`, so they keep working against
a body that is on disk rather than in the hub — but only because `size` still says the
body exists. A body whose `size` went to zero would read as *no body* and lose the
affordance entirely.

**3a. Clearing `inline` has four consumers; one must be fixed first and one constrains a
constant.** `inline` is an optimization everywhere except the viewer's flow-compare
screen, which compares `request_body.inline` between two flows
(`tui/traffic_viewer/screens.py`). Once inline can be empty for a body that exists, two
*different* bodies both compare as empty and the screen reports them **equal** — a wrong
answer rather than an error. Refetching through `GetBody` there is a precondition of
decision 3, not follow-up cleanup.

The MCP server reads `inline` in three places. Two degrade safely, already emitting a
"fetch with get_body" note when a body is out of line. The third, `_body_text`, backs
content search: it scans `inline` when present, fetches when the body is under
`_SCAN_FETCH_MAX`, and **silently returns no-match above it**. Correctness survives only
because `InlineBlobMax` (1 MiB) is below `_SCAN_FETCH_MAX` (2 MiB), so anything that was
inline still takes the fetch branch. That is a load-bearing relationship between two
constants in two languages, and it is recorded here because nothing enforces it: raising
`InlineBlobMax` past `_SCAN_FETCH_MAX` would make content search quietly miss matches.
The cost that does land is a fetch per candidate body where there was none — bounded by
MCP's existing scan cap and by its header-criteria-first ordering.
[0012](0012-server-side-filtering-and-pagination.md) §2a retires this: body matching
becomes a DSL term evaluated in the gateway, `_body_text` is deleted, and nothing outside
the gateway reads `inline` to match a body — so the constant coupling stops existing
rather than remaining a documented hazard.

Because of this, decision 3 clears `inline` only on the **retained hub copy**. Whether
live flow *events* should stop carrying inline bodies at all is a larger question — it is
most of the viewer's per-flow memory — and belongs with
[0012](0012-server-side-filtering-and-pagination.md), not here.

**3b. A body is written to a blob only once it is final; the flow row flushes without it
until then.** Blobs are content-addressed and never deleted, which is safe today only
because a body is written exactly once, at close, in its final form. Flushing a growing
body would break that: each flush hashes a longer prefix, producing a *different* blob and
leaving the previous one referenced by nothing. A 100 MB download flushed every 2 MB would
strand ~50 dead prefixes totalling ~2.5 GB for a single body. Deleting the superseded blob
on update is not available either — content addressing means blobs are shared, so another
flow may legitimately reference the same hash.

So the flow row is flushed early with `req_body_ref`/`resp_body_ref` left NULL, and the
refs are filled once, when the body is final. This needs no new concept: "final" is
decision 3's settling test, so the moment a body becomes eligible for release from memory
is the moment it is written. One event, two effects.

The cost is that a body is not readable *from the store* while it is still streaming — but
that is exactly the window in which decision 3 keeps it in memory, so `bodyBytes` serves it
from the hub and no reader can tell. A crash mid-stream loses that one body, leaving its
row with a null ref, which is consistent with the durability this decision claims
(everything up to the last flush) and strictly better than today's all-or-nothing.

One narrow exception survives, found in implementation. A flow the decoder touches *while
its write is in flight* has already had a body written that may now be stale; the next
cycle rewrites it, and if the body grew in that window the first blob is stranded. The
flusher keeps this to one blob by leaving such a flow owed rather than releasing it, and
correctness is unaffected — the final body wins — but "no orphans by construction" holds
for the design, not for every interleaving.

Sweeping unreferenced blobs at close was the alternative, and was rejected: it lets
orphans accumulate for the whole capture — worst on exactly the long captures this ADR
exists for — leaves them permanently after a crash, and has to be taught about external
blob *files* and `ws_messages` refs as well as flow refs. Reference counting was rejected
as the most new state for the least benefit. Not creating the garbage beats collecting it.

**4. WebSocket messages flush and release on the same cadence, by their own rule.** The
hub's `messages` slice (`live.go`) holds every frame with both its decoded payload and its
raw bytes inline, and is written only at close. On a WebSocket-heavy capture that slice
*is* the memory, and decision 3 deliberately exempts WebSocket flows from body release —
so without this, such a session stays nearly as bad as it is today.

Frames are easier than flows, and the rule is simpler for it: a frame is immutable once
decoded and the slice is append-only, so there is no upsert, no dirty set, and no
settling question. The flusher writes the frames appended since the last flush with
`InsertWsMessages` and drops them from the slice. What the hub retains for a WebSocket
flow is therefore a bounded tail, not the conversation. Reads of an already-flushed frame
go to `ListMessages`/`GetWsMessageBody` exactly as they do for a closed session, and the
live subscriber fan-out is untouched — a frame is published to followers when it arrives,
independent of when it is written.

**5. A flush that fails errors the session and stops the capture.** The memory bound holds
only while writes succeed, so the failure path is part of the decision rather than an
implementation detail. On a flush error the session is marked
`SESSION_STATUS_ERROR`, the capture is stopped, and the reason is logged and surfaced —
the capture does not continue in a state where its record is not being written.

The two alternatives were both rejected as worse for a tool whose product is a faithful
record. Retrying while holding the batch in memory reinstates unbounded growth and hides
the failure until the process dies; dropping the batch bounds memory by silently losing
traffic, which is the one outcome a capture tool must never choose. Stopping is loud, and
loud is recoverable: everything already flushed stays readable in the bundle, which is
precisely the durability decision 1 buys.

**6. Record-live's fidelity guarantee is unchanged.** Bodies are still kept uncapped;
`SetUnlimitedLiveBodies` stays. What changes is where an uncapped body lives — in the
session bundle rather than in the heap. A viewer reading an open session sees the same
bytes, from `GetBodyBytes` instead of from the hub.

**7. Close stops being a bulk write.** `persistLive` becomes a final flush, a count, and
`FinishSession`. The analysis row moves to session start, since rows now reference it
throughout the capture rather than only at the end.

**8. Bounding the in-memory row set is deferred to a follow-up.** Even with bodies gone,
the proto row map still grows with the session. Serving subscriber snapshots from the
bundle and keeping only the unflushed tail in memory is the next step — but it changes
`StreamFlows`' follow path. A flow flushed between the store read and the subscribe would
be lost without a buffer-then-replay handshake, and a flow missing from a live table stays
missing until the session is reopened. What makes that tractable is that the
viewer folds a repeated flow id in place rather than appending it again (`_ingest`), so
redelivery is idempotent and the handshake can safely err toward sending a flow twice.
That is a separate decision with its own concurrency risk, taken once this one is proven
on a real capture.

## Consequences

- The close-time transaction disappears. Closing a large session becomes a final flush of
  at most one batch plus a catalog update, instead of work proportional to the whole
  session.
- Peak memory stops tracking capture size and starts tracking the unflushed window. This
  is the point of the change; every other benefit is secondary.
- **This bounds the gateway only.** Viewers keep their own full copy of a session — the
  TUI holds every flow to filter it, and MCP re-materializes the session per call — which
  measures in the hundreds of megabytes to gigabytes independently of anything decided
  here. [0012](0012-server-side-filtering-and-pagination.md) is the follow-up that fixes
  that side, and this decision is its prerequisite: filtering cannot move to the gateway
  while an open session's flows exist only in memory.
- **Live follow and live filtering are unaffected, and were checked rather than assumed.**
  The flusher touches only the store: `publish`/`subscribe` and the flow fanout are
  unchanged, so a following viewer keeps receiving `flow_added`/`flow_updated` exactly as
  before. Filtering is entirely viewer-side over fields already held in the flow proto —
  the DSL has terms for method, domain, url, status, content-type, connection and stream,
  plus annotations and metadata, but **no body-content term** — so releasing body bytes
  cannot change a filter result. Membership is re-evaluated per update, so a flow that
  gains a status mid-capture still flips into `~s` correctly.
- **A crash mid-capture stops losing the session.** Today the bundle is empty until close,
  so a gateway that dies takes the capture with it and `ForceCloseSession` can only mark
  the session closed over nothing. After this, the bundle holds everything up to the last
  flush. `ForceCloseSession` keeps the recovery job
  [0010](0010-supervisor-and-capture-modules.md) gave it, and gains something to recover.
- **Write amplification is accepted.** A flow written at request time and again at
  response time costs two row writes plus two side-table rewrites. Bounded memory and
  crash durability are worth more than the writes, and the alternative — waiting for a
  completion signal — does not exist in the live decoders today.
- **Blob storage keeps its "written once, never deleted" property**, which is what lets
  content addressing stay free of reference counting. Decision 3b buys that by not writing
  a body until it is final, rather than by adding a collector — so the bundle never
  carries intermediate states of a streamed response, and no new deletion path touches
  shared blobs.
- **A flow row can exist with no body ref, transiently.** While a body is still streaming
  its row is in the bundle and its `req_body_ref`/`resp_body_ref` are NULL. Read paths
  already treat a null ref as "no body", so an open session needs the hub consulted for
  those flows — the same fallback decision 3 relies on. Code that infers "this flow had no
  body" from a null ref is correct only for a closed session.
- **The reader now races the writer within a session.** Reads of an open session were
  previously served entirely from memory, because the bundle was empty. They now hit a
  file being written. Per-session bundles ([0001](0001-embedded-per-session-sqlite.md))
  keep that contained to one capture, and WAL plus `busy_timeout` already cover concurrent
  access — but "a session's DB is only written at close" stops being true, and any code
  that assumed it must be found rather than trusted.
- **WAL growth was real, and the cause was not the one anticipated.** This was filed as
  "watch it on long captures", expecting continuous writes plus a live reader to defer
  auto-checkpoints. Measured on a real capture, the problem is not the capture at all: the
  store keeps a session's DB handle pooled for the life of the process, so a *finished*
  session's log is never folded back in. A two-minute capture left a 4.8 MB `-wal` beside
  a 6 MB bundle, and it was reclaimed only when the gateway exited — meaning a long-lived
  gateway carries one stranded log per session it has ever recorded, which is a far worse
  shape than a single large capture's log. `FinishSession` now checkpoints the bundle when
  the session reaches a terminal state. Best-effort: a checkpoint blocked by an active
  reader is reported and left to the next one, since nothing about the session's
  correctness depends on it.
- The flush thresholds (128 flows / 2 s) trade memory ceiling against write amplification
  directly, and are starting values to be re-set against a real large session. What is
  committed is that a ceiling exists, not where it currently sits.
- **A capture can now stop for a reason the storage layer chose.** Decision 5 turns a disk
  error into an ended session, so a full disk ends a capture rather than degrading it.
  That is the intended trade — the alternative is a capture that keeps running while
  silently recording nothing — but it makes free disk space an operational precondition
  for a long capture, where before it only mattered at close.
- **`liveFlowCount` stops being the source of truth for an open session.** It exists
  because the catalog's `flow_count` was only written at close; with rows landing during
  capture, an open session's count has to come from the store plus the unflushed tail, or
  it will double-count flows that are in both. The stale comment on it is a marker for
  code that assumed the old invariant.
- `GATEWAY_RECORD_LIVE=off` is untouched: that path still batch-decodes the finished pcap
  on close and never used the hub's retained flows.
