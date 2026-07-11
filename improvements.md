# NOT COVERED — traffic-deck cannot inform these parameters

| connection/request parameter | What's missing in traffic-deck | Impact | Comment |
|---|---|---|
| **TLS fingerprint ** | TLS version, cipher suite, and SNI are parsed internally during decryption but **NOT persisted in the Flow proto**. No JA3/JA4 fingerprint stored. | **Critical gap.** You can't see which TLS ClientHello profile the target app uses. Must guess from UA or use external tools. traffic-deck knows the connection was decrypted but doesn't expose what the ClientHello looked like. | It should be possible to export TLS ClientHello from TUI |
| **ALPN negotiation result** | ALPN is detected in `gateway/internal/decode/livetcp.go` to decide HTTP/2 vs HTTP/1.1, but **not stored as a field** | Can infer from `protocol` field (h2 → ALPN negotiated h2), but can't see the full ALPN list offered | |
| **Certificate details** | Not captured at all | Can't inspect server cert chain, pinning behavior, or custom client certs | |
| **HTTP/2 SETTINGS frames** | Not captured. The `h2_stream_id` is stored but HTTP/2 settings (header_table_size, max_concurrent_streams, initial_window_size, etc.) are not persisted | **Major gap for anti-bot.** vendetta-http transport has granular HTTP/2 settings that must match the browser. traffic-deck doesn't expose what the real browser's HTTP/2 settings are. | Should be possible to view these parameters in TUI |
| **HTTP/2 header priority** | Not captured | Can't see stream dependency/weight the target uses | |
| **HTTP/2 stream ID start** | Not captured | Can't determine `start_stream_id_settings` | |
| **HTTP/2 window size / flow control** | Not captured | Can't tune `initial_window_size`, `window_size_increment` | |
| **HTTP/3 / QUIC details** | QUIC is decoded but no QUIC-specific fields (connection IDs, QUIC transport parameters) stored | Can't see QUIC-level fingerprint details | |
| **Cookie attributes** (domain, path, expires, secure, httpOnly, sameSite) | `Cookie` proto stores only `name` + `value` | Can't fully reconstruct cookie jar behavior (e.g., which cookies are secure/httpOnly, domain scoping) | |
| **Redirect chain** | Each flow is a single request/response; redirects are separate flows without explicit linking | Must manually trace redirect chains via timing/headers | |
