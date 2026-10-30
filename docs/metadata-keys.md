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
| `viewer.columns` | capture tools (`VIEWER_COLUMNS_KEY`) | TUI | Default extra flow-table columns, comma-separated. |
| `capture.iface` | `capture_sdk` live capture | nothing by name | Interface a pcap capture recorded on. |
| `capture.duration_s` | `capture_sdk` live capture, Android | nothing by name | Requested auto-stop, seconds. |
| `capture.pids` | macOS pktap source, at CloseSession | gateway (`pidsCaptureKey`) | Pids the browser used; the gateway prunes the pcap to them. |
| `undecoded.<reason>` | gateway native decoder (`store/undecoded.go`) | gateway, MCP | Count of connections that produced no flow, per reason. |
| `conn.undecoded.<outcome>` | mitmproxy addon (`CONN_UNDECODED_PREFIX`) | MCP | The same count, as the mitmproxy source reports it. Readers accept both prefixes. |

## Flow metadata

| Key | Written by | Read by | Meaning |
|-----|-----------|---------|---------|
| `tls.sni` | mitmproxy addon (`TLS_SNI`) | gateway (`tlsSNIKey`), TUI | SNI the client sent; the gateway uses it to match custom decoders. |
| `hostname.source` | mitmproxy addon (`HOSTNAME_SOURCE`) | gateway (`hostnameSourceKey`), TUI | Where the hostname came from: host, authority, sni, dns, ip or connect. |
| `hostname.dns_flow` | mitmproxy addon | TUI | The DNS flow that named the host, when the source is dns. |
| `hostname.dns_candidates` | mitmproxy addon | TUI | Other names the address resolved to. |
| `conn.outcome` | mitmproxy addon (`CONN_OUTCOME`) | gateway (`filter.ConnOutcomeKey`), TUI, MCP | Fate of a connection that produced no decoded request; some outcomes are hidden by default. |
| `conn.bytes_up` / `conn.bytes_down` | mitmproxy addon | TUI | Bytes each way on such a connection. |
