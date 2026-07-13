# Fingerprinting coverage — what traffic-deck can and can't tell you

Gap analysis for parser/anti-bot fingerprinting: which connection and request
parameters a capture can inform, and which it still can't. Most of the original gaps
below have since been closed; the remaining ones are listed first.

## Still not covered

| connection/request parameter | What's missing | Impact |
|---|---|---|
| **Certificate details** | Not captured at all. The server `Certificate` message is on the wire and decryptable, but nothing parses or stores it. | Can't inspect the server cert chain, pinning behaviour, or custom client certs. |
| **QUIC transport parameters** | HTTP/3 is decoded, but no QUIC-level fields are stored: no transport parameters, and no real connection id (`tcp_stream` carries a synthetic `quic:<n>` index assigned by the decoder, not the wire's connection id). | Can't see QUIC-level fingerprint details, or match a capture against a QUIC client's transport-parameter profile. |
| **ALPN as a typed field** | The *offered* ALPN list is in `tls_client_hello` (text), and the *negotiated* protocol is inferable from `protocol` (h2 → ALPN negotiated h2). Neither is a dedicated field. | Enough to read, awkward to query — no `~`-filter or column for ALPN. |

## Now covered

Kept for history: these were the original gaps, with where each is surfaced today.

| parameter | How it's covered | Where |
|---|---|---|
| **TLS fingerprint** | `Flow.ja3`, `ja4`, `tls_client_hello` (JA3 string + offered ALPN), `client_hellos` (raw handshake bytes, more than one entry after a HelloRetryRequest), `tls_hrr`. | Flow detail → *TLS ClientHello*; export the raw ClientHellos from the TUI; MCP `export_client_hellos`. |
| **HTTP/2 SETTINGS** | `Flow.http2_fingerprint` (Akamai format) carries the connection's client SETTINGS. | Flow detail → *HTTP/2 fingerprint*, decoded to named settings. |
| **HTTP/2 header priority** | Same fingerprint: the PRIORITY component. | As above. |
| **HTTP/2 window size / flow control** | Same fingerprint: `initial_window_size` among the SETTINGS, plus the connection-level WINDOW_UPDATE increment. | As above. |
| **HTTP/2 stream ID start** | `h2_stream_id` per flow, plus `tcp_stream` identifying the connection — so the first stream id on each connection is directly observable. | Flow table `Conn`/`Stream` columns; `~conn`/`~stream` filters. |
| **Cookie attributes** | `Cookie` carries `domain`, `path`, `expires`, `max_age`, `secure`, `http_only`, `same_site`; `response_cookies` parses Set-Cookie separately from the bare request `Cookie` pairs. | Flow detail cookie sections. |
| **Redirect chain** | `redirect_location` (absolute, resolved) and `redirected_from_id` link a 3xx to the flow it redirected to, computed across the session. | Flow detail → `↪ redirects to` / `↩ redirected from`. |
