# Custom protocol decoders

Non-HTTP binary protocols carried over TCP (e.g. MAX messenger, `ru.oneme`) are decoded
by **compiled-in Go modules** under [`gateway/decoders/`](../gateway/decoders/)
([ADR-0004](adr/0004-compiled-in-go-decoders.md)). Each decoder is its own package that
self-registers via `init()`; the gateway blank-imports it in `cmd/gateway`. The decoder
turns a connection's TLS-decrypted directional byte stream into message frames, surfaced
as a synthetic flow with the WebSocket-style `M` message timeline. HTTP and
custom-protocol flows coexist in one session.

Two paths produce the decrypted bytes:

- **Live** (during capture, the default): fully in-process in Go — the gateway taps the
  live pcap, reassembles TCP (`gopacket`, including the Android `NFLOG` link type), and
  decrypts TLS (SSL 3.0 – TLS 1.3) from the key-log
  ([`internal/tlsdecrypt`](../gateway/internal/tlsdecrypt/)), feeding the decoder as bytes
  arrive — no `tshark` re-run. So MAX frames stream into the `M` timeline in real time.
  **Verified end-to-end** on the Android `ru.oneme` (MAX) app: live TLS decryption +
  decoding of MAX frames during capture.
- **Batch** (session close): `tshark -z follow,tls,raw` over each matched stream. Runs
  only with `GATEWAY_RECORD_LIVE=off` (or on import/verify), and is what can still
  recover a connection the live decryptor had to skip — one negotiating a version or
  cipher suite it doesn't implement, or whose key-log secret never arrived.

## Writing one

A decoder implements `decoders.Decoder` (`Name`, `Matches(StreamMeta)`, `NewSession`);
the returned `Session` is a stateful framer — `Feed(fromClient, data) []Message` —
that buffers a partial frame until the rest arrives, so it works fed all-at-once
(batch) or incrementally (live). See `decoders/max` (MAX framing → LZ4 → MessagePack →
JSON). Add one = add a package + a blank import + rebuild.

```sh
# re-run custom decoders over an already-captured session (e.g. after adding a decoder)
mise exec -- go -C gateway run ./cmd/gateway redecode <session-id>
```

Decoding needs the connection's TLS to be decryptable from the capture's `key.log`
(i.e. the app uses the system `libssl` the Android Frida hook logs) — verified working
on `ru.oneme`.
