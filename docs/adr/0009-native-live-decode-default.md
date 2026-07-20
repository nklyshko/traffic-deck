# 0009 — The native in-process decoder is the default, authoritative path

Status: accepted. Supersedes much of [0002](0002-tshark-for-dissection.md); generalizes
[0006](0006-in-process-tls-decryption.md).

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
- It is **authoritative by default**: `GATEWAY_LIVE_DECODE` and `GATEWAY_RECORD_LIVE`
  both default on, so live-decoded flows are persisted on close and no batch pass runs.
- `tshark` remains for pcap import, for `GATEWAY_RECORD_LIVE=off` (an authoritative
  batch re-decode on close), and for `GATEWAY_TSHARK_VERIFY` (decode both ways on close
  and log the differences).

## Consequences

- Flows appear as they arrive, with no repeated whole-file decryption and no process
  boundary — the [0006](0006-in-process-tls-decryption.md) argument, now for every
  protocol.
- Fingerprint fields (`ja3`, `ja4`, `tls_client_hello`, `client_hellos`,
  `http2_fingerprint`) are produced **only** by the native decoder; the batch stitcher
  reads the ClientHello just for SNI and the stream index. So `GATEWAY_RECORD_LIVE=off`
  trades the fingerprints for tshark's dissectors and full-fidelity bodies.
- The cost [0002](0002-tshark-for-dissection.md) set out to avoid is now partly paid: a
  TLS/QUIC decryptor and HTTP/1.1, HTTP/2 and HTTP/3 framers to maintain. Scope grew
  well past [0006](0006-in-process-tls-decryption.md)'s TLS 1.3 — SSL 3.0 through TLS
  1.3, with QPACK/HPACK.
- Keeping tshark on the import and verify paths is what makes that affordable:
  `GATEWAY_TSHARK_VERIFY` cross-checks the native decoder against Wireshark's dissectors
  on a real capture, so the two can't silently diverge.
- Wireshark is no longer required to decode a live capture — only to import a pcap or
  run the batch/verify passes (`dumpcap` is still what the Chrome tool captures with).
