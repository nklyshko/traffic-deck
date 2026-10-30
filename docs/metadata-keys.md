# Metadata keys

Sessions and flows carry free-form `map<string,string>` metadata (`proto/traffic/v1`). The
gateway stores and forwards it verbatim, so the keys below are a contract between
components that share no code. Add a key here when you add a producer or a reader.

Where to name a key in code:

- **Capture tools** (Python): `capture_sdk/metadata_keys.py`.
- **Gateway** (Go): the constants named in the table.
- **TUI and MCP server**: keep their own string copies (they do not depend on
  `capture_sdk`); `tui/traffic_viewer/metadata.py` holds the TUI's display labels.

Beyond the readers named below, MCP's `list_sessions` returns every session key and the
TUI's flow detail and every MCP flow summary (`metadata`) carry every flow key, so any
key here is visible to a person or agent.

## Session metadata

| Key | Written by | Read by | Meaning |
|-----|-----------|---------|---------|
| `viewer.columns` | capture tools (`VIEWER_COLUMNS`) | TUI | Default extra flow-table columns, comma-separated. |
| `capture.iface` | `capture_sdk` live capture | nothing by name | Interface a pcap capture recorded on. |
| `capture.duration_s` | `capture_sdk` live capture, Android | nothing by name | Requested auto-stop, seconds. |
| `capture.pids` | macOS pktap source, at CloseSession | gateway (`pidsCaptureKey`) | Pids the browser used; the gateway prunes the pcap to them. |
| `undecoded.<reason>` | gateway native decoder (`store/undecoded.go`) | gateway, MCP | Count of connections that produced no flow, per reason. |
| `conn.undecoded.<outcome>` | mitmproxy addon (`CONN_UNDECODED_PREFIX`) | MCP | The same count, as the mitmproxy source reports it. Readers accept both prefixes. |
| `browser.binary`, `browser.profile`, `browser.url`, `browser.extra_args` | browser sources (`capture_sdk.browser.launch_metadata`) | nothing by name | The browser binary, the profile it ran with, the URL it opened and any extra arguments. `browser.*` rather than per browser, so captures from different browsers compare key for key. |
| `browser.incognito` | Chrome source (`BROWSER_INCOGNITO`) | nothing by name | `true` or `false`, always stated. |
| `pktap.proc` | macOS pktap source (`PKTAP_PROC`) | nothing by name | The process name pktap's kernel filter matched. |
| `android.package`, `android.uid`, `android.scripts`, `android.url` | Android per-app capture (`ANDROID_*`) | nothing by name | The app, its uid, how many Frida scripts were loaded, and the URL opened. |
| `android.package`, `android.method`, `android.serial`, `android.url` | Android Chrome-proxy capture (`ANDROID_*`) | nothing by name | The app, `proxy`, the device serial and the URL opened. |
| `mitmproxy.mode`, `mitmproxy.listen_port`, `mitmproxy.listen_host` | mitmproxy addon (`MITMPROXY_*`) | nothing by name | The proxy mode and the listen address it was given; the address keys are absent when mitmproxy defaulted them. |

## Flow metadata

| Key | Written by | Read by | Meaning |
|-----|-----------|---------|---------|
| `tls.sni` | mitmproxy addon (`TLS_SNI`) | gateway (`tlsSNIKey`), TUI | SNI the client sent; the gateway uses it to match custom decoders. |
| `hostname.source` | mitmproxy addon (`HOSTNAME_SOURCE`) | gateway (`hostnameSourceKey`), TUI | Where the hostname came from: host, authority, sni, dns, ip or connect. |
| `hostname.dns_flow` | mitmproxy addon | TUI | The DNS flow that named the host, when the source is dns. |
| `hostname.dns_candidates` | mitmproxy addon | TUI | Other names the address resolved to. |
| `conn.outcome` | mitmproxy addon (`CONN_OUTCOME`) | gateway (`filter.ConnOutcomeKey`), TUI, MCP | Fate of a connection that produced no decoded request; some outcomes are hidden by default. |
| `conn.bytes_up` / `conn.bytes_down` | mitmproxy addon | TUI | Bytes each way on such a connection. |
| `dns.rcode` | mitmproxy addon (`DNS_RCODE`) | TUI | A DNS flow's response code (NOERROR, NXDOMAIN, …). |
| `body.truncated` | mitmproxy addon (`BODY_TRUNCATED`, 64 MiB cap), gateway decoders (`decode.BodyTruncatedKey`, 256 MiB after decompression) | TUI | Which bodies were cut at a size cap: `request`, `response`, or both comma-separated; on a message, `payload`. The kept bytes are the body's beginning and its size is the cut size. Each cut is also logged. |

## Message fields

A custom decoder's message carries its own header fields, namespaced by decoder name
(`max.cmd`, `max.opcode`, …). One is about the decode itself:

| Key | Written by | Meaning |
|-----|-----------|---------|
| `max.limit` | MAX decoder (`limitField`) | The frame hit a size or nesting bound (decompresses past 64 MiB, MessagePack over 8 MiB or nested deeper than 64) and was kept raw. Its bytes are intact; only the decoding was skipped. Logged once per connection per bound. |
