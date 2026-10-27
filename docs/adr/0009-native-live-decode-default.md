# 0009 — The native in-process decoder is the default, authoritative path

Status: accepted. Supersedes much of [0002](0002-tshark-for-dissection.md); generalizes
[0006](0006-in-process-tls-decryption.md). Revised 2026-10-26: the
`GATEWAY_RECORD_LIVE=off` alternative it first kept is gone — see
[Removing the batch alternative](#removing-the-batch-alternative).

## Context

[0002](0002-tshark-for-dissection.md) chose `tshark` for the whole decode stack, to
avoid re-implementing TCP reassembly, TLS decryption and the HTTP dissectors.
[0006](0006-in-process-tls-decryption.md) carved out one exception: custom raw-TCP
protocols decode in-process in Go, because tshark only exposes an undissected
protocol's decrypted bytes through the whole-file `-z follow,tls,raw`. That left two
decoders, with tshark authoritative and the Go one a special case.

Two things pushed the exception to become the rule:

- Once TCP reassembly + TLS decryption already ran in Go for custom protocols, framing
  HTTP on top of the same decrypted byte stream was incremental — while keeping tshark
  for HTTP meant a process boundary, PDML parsing, and a second reassembly of the same
  packets.
- This system exists for parser and anti-bot fingerprinting, which needs the raw
  handshake and frames: JA3/JA4 and the verbatim ClientHello bytes, and the Akamai
  HTTP/2 fingerprint (client SETTINGS, the connection WINDOW_UPDATE increment, PRIORITY
  frames, pseudo-header order). These are wire-level details a dissector's output
  normalizes away — the decoder has to see the bytes itself.

## Decision

Decode natively in Go, in-process, for everything; keep tshark as a secondary path.

- The live pipeline (`decode.LiveTCPDecode`) reassembles TCP and QUIC with `gopacket`
  (plus the Android NFLOG link type), decrypts TLS (SSL 3.0 – TLS 1.3) and QUIC from the
  key-log, and frames HTTP/1.1, HTTP/2, HTTP/3, WebSocket and custom raw-TCP —
  plaintext or TLS.
- It is **authoritative**: a capture decoded live is recorded as the live decode
  produced it, and no batch pass re-decodes it on close.
- `tshark` remains where the live decoder cannot be asked to do the job: pcap import
  (including a closed session's own capture, imported as a new session), `trafficdeck
  redecode --engine tshark` of a session's custom-protocol flows, a capture with
  `GATEWAY_LIVE_DECODE=false` (no live decode at all), and `GATEWAY_TSHARK_VERIFY`
  (decode both ways on close and log the differences; the tshark side is never
  persisted).

## Consequences

- Flows appear as they arrive, with no repeated whole-file decryption and no process
  boundary — the [0006](0006-in-process-tls-decryption.md) argument, now for every
  protocol.
- Fingerprint fields (`ja3`, `ja4`, `tls_client_hello`, `client_hellos`,
  `http2_fingerprint`) are produced **only** by the native decoder; the batch stitcher
  reads the ClientHello just for SNI and the stream index. So a tshark import trades
  the fingerprints for tshark's dissectors.
- The cost [0002](0002-tshark-for-dissection.md) set out to avoid is now partly paid: a
  TLS/QUIC decryptor and HTTP/1.1, HTTP/2 and HTTP/3 framers to maintain. Scope grew
  well past [0006](0006-in-process-tls-decryption.md)'s TLS 1.3 — SSL 3.0 through TLS
  1.3, with QPACK/HPACK.
- Keeping tshark on the import and verify paths is what makes that affordable:
  `GATEWAY_TSHARK_VERIFY` cross-checks the native decoder against Wireshark's dissectors
  on a real capture, so the two can't silently diverge.
- Wireshark is no longer required to decode a live capture — only to import a pcap or
  run the batch/verify passes (`dumpcap` is still what the Chrome tool captures with).
- A connection the live decoder skips is missing from the session. If tshark can decode
  it — an unsupported version, suite or link type, not a missing key-log secret, which
  tshark needs as much — importing the session's `capture.pcap` and `key.log` with
  `trafficdeck import --decoder tshark` recovers it into a new session; the skip
  diagnostic says so. `redecode` does not: it replaces only custom-protocol flows.

## Removing the batch alternative

This ADR first kept `GATEWAY_RECORD_LIVE=off` as a way back: run tshark over the
finished pcap on close and persist *that*, with the live decode only a 256 KiB-per-body
preview while the capture ran. It was the stated recovery for a connection the live
decoder had to skip — an unsupported TLS version or cipher suite — and a way to check the
decoder against Wireshark's dissectors.

It was removed because nobody turned it on and it would not have recovered anything.
Seven weeks of one gateway's log (2026-09-08 – 2026-10-26) hold 11,475 skip diagnostics:
9,632 "no TLS key-log secret" and 1,839 "no QUIC key-log secret" — other processes on a
system-wide capture, or connections that began before it, which tshark cannot decrypt
from the same key-log either — and four HTTP/3 connections whose headers waited on QPACK
inserts that never reached the capture. None was an unsupported version or suite.

Meanwhile the mode was not free. Every reader of a live body had a preview case to
handle and label — `truncated` on the wire, `partial` in MCP, "live preview" in the
TUI — and a body search during capture could say nothing true about a preview, since
neither "contains" nor "lacks" holds on a body's first 256 KiB.

The setting is now ignored, with a log line naming `trafficdeck import --decoder tshark`
as the way to decode a capture with tshark. The live
body cap went with it: the live decoders keep every body whole, so nothing marks a body
as a preview and no reader handles one. `Body.truncated` and `BodyChunk.truncated` stay
in the proto as deprecated, never-set fields, so older readers and writers remain
wire-compatible. A WebSocket frame's payload is read as it arrives rather than into a
buffer of its declared length, since without the cap that 64-bit length off the wire
was the only bound on the allocation.
