# 0003 — Parse per-frame PDML, not flat fields

Status: accepted; scope narrowed by [0009](0009-native-live-decode-default.md) — this
governs the batch (tshark) decoder, which is no longer the default path.

## Context

The first decoder used `tshark -T ek` with selected `-e` fields, which is flat per
packet: every value of a field collapses into one array. HTTP/2 multiplexes many frames
into a single packet, and `http2.streamid` is emitted for every frame while
`method`/`status` appear only on HEADERS frames — so the arrays don't line up. Taking
the first value silently dropped all but one stream per packet, producing orphaned
request-only or response-only rows.

## Decision

Parse tshark's per-frame PDML tree (`-T pdml`). Emit one stitcher record per protocol
`<proto>` element (one per HTTP/2 frame, the HTTP/1.1 message, each WebSocket frame,
each HTTP/3 frame), merging packet-level fields into each. Bound the detail with `-O`.

## Consequences

- Each frame keeps its own stream id and fields; HTTP/2 multiplexing is correct.
- PDML is the uniform substrate for additional protocols (WebSocket, HTTP/3) — adding
  one is mapping work, not another output-format change.
- PDML is more verbose than flat fields; acceptable for per-app captures.
