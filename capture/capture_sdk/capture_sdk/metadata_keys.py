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

# --- session metadata (set at OpenSession / CloseSession) ---------------------------------

#: The viewer's default flow-table columns, comma-separated (see capture_sdk.viewer).
VIEWER_COLUMNS = "viewer.columns"
#: Interface a pcap capture recorded on.
CAPTURE_IFACE = "capture.iface"
#: Requested auto-stop, seconds.
CAPTURE_DURATION_S = "capture.duration_s"
#: Comma-separated pids a per-process capture narrowed to (macOS pktap); the gateway prunes
#: the pcap to them on close.
CAPTURE_PIDS = "capture.pids"

# The capture's own options, recorded so a bundle read back later says what it recorded.
# Strings for a person to read; nothing parses them back.
#: Browser sources (capture_sdk.browser.launch_metadata): `browser.*` rather than
#: `chrome.*` so captures from different browsers compare key for key.
BROWSER_BINARY = "browser.binary"
BROWSER_PROFILE = "browser.profile"
BROWSER_URL = "browser.url"
BROWSER_EXTRA_ARGS = "browser.extra_args"
BROWSER_INCOGNITO = "browser.incognito"
#: The process name pktap's kernel filter matched.
PKTAP_PROC = "pktap.proc"
#: Android captures: the app, its uid, how it was captured (proxy for the Chrome path),
#: the device serial, how many Frida scripts were loaded, and the URL opened.
ANDROID_PACKAGE = "android.package"
ANDROID_UID = "android.uid"
ANDROID_METHOD = "android.method"
ANDROID_SERIAL = "android.serial"
ANDROID_SCRIPTS = "android.scripts"
ANDROID_URL = "android.url"
#: mitmproxy's mode and the listen address it was given (absent when defaulted).
MITMPROXY_MODE = "mitmproxy.mode"
MITMPROXY_LISTEN_PORT = "mitmproxy.listen_port"
MITMPROXY_LISTEN_HOST = "mitmproxy.listen_host"

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
#: A DNS flow's response code (NOERROR, NXDOMAIN, …).
DNS_RCODE = "dns.rcode"
#: Which bodies were cut at a size cap, comma-separated: request, response (on a flow) or
#: payload (on a message). The kept bytes are the body's beginning; its size is the cut size.
BODY_TRUNCATED = "body.truncated"
#: Prefix of the per-outcome undecoded-connection counts on a session ("conn.undecoded.<o>").
#: The gateway's own native decoder writes these under "undecoded." instead; readers accept
#: both.
CONN_UNDECODED_PREFIX = "conn.undecoded."
