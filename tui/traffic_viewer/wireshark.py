"""Hand a decoded flow back to Wireshark.

The viewer shows flows; Wireshark shows packets. For a pcap-based session both views
describe the same bytes, so a flow can be reopened in Wireshark against the session's
own `capture.pcap` + `key.log` (paths from ControlService.GetSessionArtifacts) with a
display filter that isolates the flow's connection, and the packet cursor parked on the
request's frame.

The connection is pinned by the flow's address/port 4-tuple rather than by its
`tcp_stream` id. The id only agrees with Wireshark's `tcp.stream` index on the tshark
decode path, which reads it from tshark; the native decoder numbers the connections *it*
tracks, skipping the ones it doesn't (and sharing the counter with QUIC), so its ids
address a different connection in Wireshark — measured against the sample capture, 58 of
62 natively decoded flows would have opened on the wrong stream. The 4-tuple is recorded
straight off the packets by both decoders, and selects the same packets `tcp.stream` does
(verified flow-by-flow on that capture).
"""

from __future__ import annotations

import os
import shutil

# Where a GUI Wireshark hides on macOS when it isn't on PATH.
_MAC_APP = "/Applications/Wireshark.app/Contents/MacOS/Wireshark"


def find_wireshark() -> str | None:
    """The Wireshark binary to launch: $TRAFFICDECK_WIRESHARK, else `wireshark` on PATH,
    else the macOS app bundle. None when nothing is installed."""
    override = os.environ.get("TRAFFICDECK_WIRESHARK", "").strip()
    if override:
        return shutil.which(override) or (override if os.path.isfile(override) else None)
    found = shutil.which("wireshark")
    if found:
        return found
    return _MAC_APP if os.path.isfile(_MAC_APP) else None


def build_display_filter(flow) -> str:
    """A Wireshark display filter isolating one flow: its whole transport connection
    (handshake, ACKs and all), narrowed to the flow's own stream when the connection is a
    multiplexed HTTP/2 one — `not http2` keeps the connection-level packets that carry no
    HTTP/2 frames, so the context around the request survives the narrowing.

    Returns "" when the flow records no addresses to pin the connection with, in which
    case the caller should open the pcap unfiltered rather than guess."""
    conn = _connection_filter(flow)
    if not conn:
        return ""
    sid = (flow.h2_stream_id or "").strip()
    if sid.isdigit() and (flow.protocol or "").startswith("HTTP/2"):
        return f"{conn} and (http2.streamid eq {sid} or not http2)"
    return conn


def _connection_filter(flow) -> str:
    """The flow's connection, as its address/port 4-tuple — the same packets Wireshark's
    own conversation filter selects. (Two connections that reused a client port within one
    capture would fold together; nothing in a flow distinguishes them.)"""
    udp = (flow.protocol or "").startswith("HTTP/3") or (flow.tcp_stream or "").startswith("quic:")
    transport = "udp" if udp else "tcp"
    terms: list[str] = []
    for a in (flow.src_addr, flow.dst_addr):
        host, port = split_addr(a or "")
        if host:
            terms.append(f"{'ipv6.addr' if ':' in host else 'ip.addr'} eq {host}")
        if port:
            terms.append(f"{transport}.port eq {port}")
    return " and ".join(terms)


def split_addr(a: str) -> tuple[str, str]:
    """Split an address the decoders wrote into (host, port).

    Three shapes reach us: "1.2.3.4:443", the bracketed IPv6 the native decoder writes
    ("[2606::1]:443"), and the bare colon-joined IPv6 the PDML path writes
    ("2606::1:443") — for that last one the trailing numeric segment is the port, unless
    stripping it would leave a dangling "::" (i.e. the string is a bare address like
    "::1", which we take as host-only)."""
    a = a.strip()
    if not a:
        return "", ""
    if a.startswith("["):
        host, sep, port = a.partition("]")
        return host[1:], port.lstrip(":") if sep else ""
    head, sep, tail = a.rpartition(":")
    if not sep or not tail.isdigit() or not head or head.endswith(":"):
        return a, ""
    return head, tail


def describe_filter(flow) -> str:
    """Short human tag for the notification: what the filter pinned the view to. Names the
    flow's own connection id (what the Conn column shows), not the packet-level 4-tuple the
    filter is written in."""
    conn = (flow.tcp_stream or "").strip()
    where = f"conn {conn}" if conn else (flow.dst_addr or "this connection")
    sid = (flow.h2_stream_id or "").strip()
    if sid.isdigit() and (flow.protocol or "").startswith("HTTP/2"):
        return f"{where} · stream {sid}"
    return where


def wireshark_command(binary: str, pcap: str, keylog: str = "", dfilter: str = "",
                      frame: int = 0) -> list[str]:
    """The argv to launch Wireshark on one flow: the session's pcap, its NSS keylog as an
    override preference (so TLS is decrypted the way the gateway decoded it), the display
    filter, and a jump to the request's frame. Optional pieces are dropped when absent —
    a pcapng with embedded secrets needs no keylog, and a natively decoded flow may carry
    no frame number."""
    cmd = [binary, "-r", pcap]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    if dfilter:
        cmd += ["-Y", dfilter]
    if frame:
        cmd += ["-g", str(frame)]
    return cmd
