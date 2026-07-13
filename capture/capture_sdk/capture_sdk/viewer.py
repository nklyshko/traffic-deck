"""Viewer hints a capture tool declares to the gateway at OpenSession.

These ride along as opaque session metadata: the gateway stores and forwards them
verbatim, and only the TUI interprets them.
"""

from __future__ import annotations

# Session-metadata key for the viewer's default flow-table columns (comma-separated).
VIEWER_COLUMNS_KEY = "viewer.columns"

# Default columns for a pcap-based capture (capture_chrome, capture_android). tshark
# decodes the transport connection and the HTTP/2 stream id off the wire, so these
# sessions can show how multiplexed requests share one connection — worth showing by
# default, since that's only visible from the raw frames.
#
# A proxy-based source must NOT declare these: mitmproxy terminates the connection, and
# its addon API exposes no HTTP/2 stream id at all (the id lives in mitmproxy's internal
# HttpStream layer, never reaching flow hooks), so both columns would render empty.
PCAP_VIEWER_COLUMNS = "conn,stream"
