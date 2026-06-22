# 0002 — Use `tshark` for protocol dissection and TLS decryption

Status: accepted

## Context

Decoding captured traffic requires TCP reassembly, TLS decryption from a key-log, and
dissection of HTTP/1.1, HTTP/2 (HPACK), HTTP/3 (QPACK over QUIC), and WebSocket.
Re-implementing that stack is a large, perpetually-moving target.

## Decision

Shell out to Wireshark's `tshark` for dissection and decryption. The gateway runs it,
parses its output, and maps the result to the storage model. The only external runtime
dependency for decoding is the `tshark` binary.

## Consequences

- Correct, maintained dissectors for the whole HTTP family + WebSocket + QUIC for free;
  adding a protocol tshark already speaks is parsing/mapping work, not a new dissector.
- A process boundary and a parse step (see [0003](0003-per-frame-pdml-decode.md)).
- For *undissected* custom protocols, tshark only exposes the decrypted bytes through
  `-z follow,tls,raw` (a whole-stream operation), not as a per-packet field. This is
  fine for batch decode but is the reason the live custom-decode path does TLS
  decryption in Go instead — see [0006](0006-in-process-tls-decryption.md).
