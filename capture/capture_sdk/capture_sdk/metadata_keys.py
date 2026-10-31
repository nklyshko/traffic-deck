"""Well-known metadata keys the capture tools write.

Session and flow metadata are free-form `map<string,string>` on the wire, so the keys are a
contract between components that share no code: the capture tools write them, the gateway
reads a few (tls.sni, hostname.source, capture.pids, conn.outcome), and the TUI and MCP
server display them. Name a key here rather than retyping the string at each producer; the
full registry, including which component reads each key, is docs/metadata-keys.md. The TUI
(traffic_viewer/metadata.py) and MCP server keep their own copies of the strings they read,
since they do not depend on this package — keep those in step with this file.
"""

from __future__ import annotations

from capture_sdk.viewer import VIEWER_COLUMNS_KEY  # noqa: F401 — re-exported: "viewer.columns"

# --- session metadata (set at OpenSession / CloseSession) ---------------------------------

#: Interface a pcap capture recorded on.
CAPTURE_IFACE = "capture.iface"
#: Requested auto-stop, seconds.
CAPTURE_DURATION_S = "capture.duration_s"
#: Comma-separated pids a per-process capture narrowed to (macOS pktap); the gateway prunes
#: the pcap to them on close.
CAPTURE_PIDS = "capture.pids"

# --- flow metadata ------------------------------------------------------------------------

#: TLS SNI the client sent.
TLS_SNI = "tls.sni"
#: Where a flow's hostname came from: host, authority, sni, dns, ip or connect.
HOSTNAME_SOURCE = "hostname.source"
#: Id of the DNS flow that resolved the hostname, when it came from DNS.
HOSTNAME_DNS_FLOW = "hostname.dns_flow"
#: Comma-separated names the address resolved to, when more than one.
HOSTNAME_DNS_CANDIDATES = "hostname.dns_candidates"
#: Fate of a connection that produced no decoded request (see the addon's outcome values).
CONN_OUTCOME = "conn.outcome"
#: Bytes client→server / server→client on such a connection.
CONN_BYTES_UP = "conn.bytes_up"
CONN_BYTES_DOWN = "conn.bytes_down"
#: Prefix of the per-outcome undecoded-connection counts on a session ("conn.undecoded.<o>").
#: The gateway's own native decoder writes these under "undecoded." instead; readers accept
#: both.
CONN_UNDECODED_PREFIX = "conn.undecoded."
