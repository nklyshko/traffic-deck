# 0005 — WebSocket and custom frames are message records on one timeline

Status: accepted

## Context

HTTP traffic is request/response shaped, but WebSocket and custom raw-TCP protocols are
streams of directional frames with no request/response pairing. Forcing them into the
`Flow` (request + response) model would distort them.

## Decision

Model these as **message records** distinct from `Flow`: each frame is a directional
record (`from_client`, opcode, payload) bound to a parent flow — the HTTP Upgrade flow
for WebSocket, or a synthetic flow for a custom-protocol connection. Store them in one
`ws_messages` table reused by both, and render them as a single directional timeline in
the viewer. A flow that owns messages is flagged so the UI shows an indicator + count.

## Consequences

- One storage shape, one viewer screen, and one live-streaming path serve both
  WebSocket and every custom protocol; adding a decoder needs no schema or UI change.
- The custom-protocol "flow" is synthetic (it represents a connection, not a
  request/response), which the model accommodates without a separate record type.
