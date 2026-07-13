# 0006 — In-process Go TLS decryption for live custom-protocol decode

Status: accepted; generalized by [0009](0009-native-live-decode-default.md). What was
the custom-protocol exception here became the default path for every protocol, so two
statements below no longer hold: TLS support has grown past 1.3 (SSL 3.0 – TLS 1.3),
and the batch pass is no longer authoritative by default. The reasoning below is what
held when the decision was made.

## Context

HTTP/WebSocket/HTTP3 decode live through a long-lived `tshark -r -` reading the
streamed capture. Custom raw-TCP protocols can't ride that path: tshark only exposes an
*undissected* protocol's decrypted bytes via `-z follow,tls,raw`, which re-reads the
whole capture file each time ([0002](0002-tshark-for-dissection.md)). Polling that over
a growing capture re-decrypts everything each tick — wasteful and not truly live.

## Decision

Decode custom protocols live **in-process in Go**, with no tshark re-run:

1. Tee the live pcap byte stream to a Go pipeline.
2. Reassemble TCP with `gopacket` (plus a small parser for the Android NFLOG link type,
   which gopacket doesn't decode).
3. Decrypt TLS 1.3 from the NSS key-log in `internal/tlsdecrypt` (HKDF-Expand-Label key
   schedule; AES-128/256-GCM and ChaCha20-Poly1305; handshake records are skipped by
   trying the application traffic secret and ignoring AEAD failures).
4. Feed each matched connection's decrypted bytes to the decoder's stateful `Session`
   ([0004](0004-compiled-in-go-decoders.md)), emitting frames through the same live path
   as WebSocket.

The whole live pipeline is gated by `GATEWAY_LIVE_DECODE` (default on); when off,
captures are archived and decoded only by the batch tshark pass on close. The batch
pass remains authoritative regardless.

## Consequences

- True streaming custom-protocol decode: frames appear in the timeline as they arrive,
  with no repeated whole-file decryption.
- A focused, security-sensitive TLS 1.3 decryptor to maintain. Scope is deliberately
  limited to TLS 1.3 + the common AEADs; other versions/suites (or link types gopacket
  can't decode) fall back to the batch pass. Validated against `crypto/tls` and
  end-to-end on a real device.
- New dependencies: `github.com/google/gopacket`, `golang.org/x/crypto`.
