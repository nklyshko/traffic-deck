# tlshello

A TLS ClientHello parser in TypeScript. It has no dependencies and imports nothing from
outside this folder. It uses only `Uint8Array`, `atob` and `btoa`, so it runs as is in a
browser, Node 18+, Deno, Bun or a worker. To use it elsewhere, copy the folder.

```ts
import { bytesFromText, describe, parseClientHello, serverName, toRecords } from './tlshello'

const hello = parseClientHello(bytesFromText(pasted)!) // throws TlsParseError when it isn't one
serverName(hello)                                      // "example.com"
describe(hello)                                        // JSON-ready: "TLS_AES_128_GCM_SHA256 (0x1301)", bytes as hex
toRecords(hello.message)                               // 16 03 01 <len> <message>, for Wireshark or a replay
```

## Input

- **A handshake message**: `01` followed by a 3-byte length. This is how a TLS stack keeps
  the ClientHello, and how QUIC carries it in CRYPTO frames.
- **TLS records**: `16 03 0x` followed by a 2-byte length. One ClientHello split over
  several records is joined back together.
- **Text, via `bytesFromText`**: any of these forms.
  - hex, with spaces, colons, `0x` and newlines allowed
  - a hex dump with an offset column (Wireshark, `openssl s_client -debug`, `xxd`, `hexdump -C`)
  - base64, standard or URL-safe

## Coverage

- **ClientHello layout**: RFC 8446 §4.1.2, and the TLS 1.0–1.2 form from RFC 5246 §7.4.1.2.
  A ClientHello with no extensions, as SSL 3.0 sent it, also parses.
- **Extensions**: every one a ClientHello can carry under RFC 8446 §4.2 and the IANA TLS
  ExtensionType registry. The table below lists what is decoded into fields. Any other
  extension keeps its raw bytes.

| Extension | Spec |
|---|---|
| server_name, max_fragment_length, status_request | RFC 6066 |
| supported_groups, ec_point_formats | RFC 8422, RFC 7919 |
| signature_algorithms, signature_algorithms_cert | RFC 8446 §4.2.3 |
| use_srtp | RFC 5764 |
| heartbeat | RFC 6520 |
| application_layer_protocol_negotiation | RFC 7301 |
| signed_certificate_timestamp | RFC 6962 |
| client/server_certificate_type | RFC 7250 |
| padding | RFC 7685 |
| encrypt_then_mac | RFC 7366 |
| extended_main_secret | RFC 7627 |
| token_binding | RFC 8472 |
| compress_certificate | RFC 8879 |
| record_size_limit | RFC 8449 |
| delegated_credential | RFC 9345 |
| session_ticket | RFC 5077 |
| pre_shared_key, early_data, supported_versions, cookie, psk_key_exchange_modes, certificate_authorities, post_handshake_auth, key_share | RFC 8446 §4.2 |
| connection_id | RFC 9146 |
| quic_transport_parameters (with GREASE, Google's parameters, version_information) | RFC 9000 §18, RFC 9368 |
| ticket_request | RFC 9149 |
| encrypted_client_hello, ech_outer_extensions | RFC 9849 |
| renegotiation_info | RFC 5746 |
| application_settings (ALPS; old and new code points) | draft-vvv-tls-alps |
| trust_anchors (Chrome's 0xca34) | draft-ietf-tls-trust-anchor-ids |
| next_protocol_negotiation, channel_id | Google drafts, recognised |

- **GREASE** (RFC 8701) is named as such wherever it can appear: cipher suites, extensions,
  groups, key shares, signature schemes, versions, PSK modes, ALPN and QUIC transport
  parameters.
- **Spec checks** produce `warnings` rather than errors, so the rest still parses:
  - a duplicated extension
  - `pre_shared_key` not last
  - non-zero padding
  - TLS 1.3 offered with compression other than `[null]`
  - a session id longer than 32 bytes
  - bytes left after the extensions
- **A malformed extension** gets its own `error` and keeps its raw bytes. Parsing carries on
  with the next extension.

## Names

`iana.ts` is generated from the IANA registries; regenerate it with `node gen-iana.mjs`.
`names.ts` adds three kinds of names:
- the small registries that IANA keeps as prose
- the TLS 1.2 signature pairs that IANA now lists only as reserved
- code points that browsers send without registering them

## Tests

`tlshello.test.ts` uses Vitest, and loads the fixtures with Vite's `?raw` import. The
fixtures in `testdata/` are:

- `rfc8448-*.hex`: the six client handshakes of RFC 8448 (Example Handshake Traces for TLS 1.3),
  each as the complete TLS record the RFC prints:
  - 1-RTT
  - resumed 0-RTT with PSK
  - the HelloRetryRequest pair
  - client authentication
  - compatibility mode
- `rfc9001-initial.hex`: the ClientHello from RFC 9001 Appendix A.2 (QUIC client Initial),
  with transport parameters.
- `chrome-*.hex`, `firefox-*.hex`: real captures, as handshake messages:
  - Chrome over TCP and QUIC: GREASE, ECH, ALPS, X25519MLKEM768, trust anchors
  - Firefox over TCP, plus a Firefox ClientHello that offers only TLS 1.2
