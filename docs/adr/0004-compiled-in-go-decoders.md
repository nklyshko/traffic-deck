# 0004 — Custom protocols as compiled-in Go decoder modules

Status: accepted

## Context

Apps carry non-HTTP binary protocols over TCP (e.g. the MAX messenger, `ru.oneme`,
which frames LZ4-compressed MessagePack). These need decoding too. Options considered:
a declarative format (Kaitai Struct), a separate decoder process (e.g. Python), a
Wireshark Lua/C dissector, or compiled-in Go.

## Decision

Decoders are compiled-in Go modules under `gateway/decoders/<name>/` that
self-register via `init()`; the gateway blank-imports them. The contract is small:

- `Decoder`: `Name()`, `Matches(StreamMeta)`, `NewSession()`.
- `Session`: `Feed(fromClient, data) []Message` — a **stateful framer** that buffers a
  partial frame until the rest arrives.

The stateful `Session` lets the same framer serve both batch decode (feed the whole
stream at once) and live decode (feed bytes as they arrive). Decoders consume a
connection's decrypted, directional byte stream and emit message records.

## Consequences

- No extra runtime, IPC, or embedded interpreter; a decoder is ordinary Go with full
  access to libraries (LZ4, MessagePack, …). Imperative code suited the reference
  protocols better than a declarative grammar.
- Adding a decoder means adding a package + a blank import + rebuilding (not hot-loaded).
  Acceptable for a self-hosted tool; keeps the trust boundary and build simple.
- Plugins are not sandboxed — they are first-party code compiled into the gateway.
