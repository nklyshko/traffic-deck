"""Readable forms of the flow metadata keys capture sources set — `hostname.source=dns`
reads as "Hostname from: DNS answer (inferred)". Display only: the stored values are
untouched, and the raw `key=value` stays beside the readable one in the detail view,
because that is what a `~meta` filter matches.

A key not listed here (a decoder's or another source's own) is shown as it is.
"""

from __future__ import annotations

from typing import NamedTuple


class Pretty(NamedTuple):
    label: str      # what the key means
    value: str      # what the value means, in full (the detail view)
    short: str      # the same, short enough for a table cell


def _bytes(v: str) -> str:
    try:
        n = float(int(v))
    except ValueError:
        return v
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return v


# key -> (label, {raw value: (full, short)}); a value absent from its map is shown raw.
_ENUMS: dict[str, tuple[str, dict[str, tuple[str, str]]]] = {
    "hostname.source": ("Hostname from", {
        "host": ("the Host header", "Host header"),
        "authority": ("the :authority pseudo-header (HTTP/2, HTTP/3)", ":authority"),
        "sni": ("the TLS SNI (the request named no host)", "TLS SNI"),
        "dns": ("the device's DNS answer for the IP (inferred)", "DNS (inferred)"),
        "connect": ("the proxy CONNECT target", "CONNECT target"),
        "ip": ("nothing — no name was sent, only the IP", "IP only"),
    }),
    "conn.outcome": ("Not decoded", {
        "tls_rejected": ("the client rejected mitmproxy's certificate (pinned?)", "TLS rejected"),
        "no_request": ("the connection closed before any request", "no request"),
        "udp_undecoded": ("UDP that is neither DNS nor HTTP/3", "UDP, undecoded"),
        "tcp_passthrough": ("a raw TCP stream, kept as messages", "raw TCP"),
    }),
    "dns.rcode": ("DNS result", {
        "NOERROR": ("NOERROR — answered", "answered"),
        "NXDOMAIN": ("NXDOMAIN — no such name", "no such name"),
        "SERVFAIL": ("SERVFAIL — the resolver failed", "server failure"),
        "REFUSED": ("REFUSED — the resolver refused", "refused"),
    }),
}

_LABELS = {
    "tls.sni": "TLS SNI",
    "hostname.dns_flow": "Named by DNS lookup",
    "hostname.dns_candidates": "Other names for this IP",
    "conn.bytes_up": "Bytes sent",
    "conn.bytes_down": "Bytes received",
}


def pretty(key: str, value: str) -> Pretty | None:
    """The readable form of one metadata entry, or None for a key this does not know."""
    if key in _ENUMS:
        label, values = _ENUMS[key]
        full, short = values.get(value, (value, value))
        return Pretty(label, full, short)
    if key not in _LABELS:
        return None
    label = _LABELS[key]
    if key in ("conn.bytes_up", "conn.bytes_down"):
        v = _bytes(value)
        return Pretty(label, v, v)
    if key == "hostname.dns_flow":
        return Pretty(label, f"flow {value[:8]}", value[:8])
    if key == "hostname.dns_candidates":
        v = ", ".join(n for n in value.split(",") if n)
        return Pretty(label, v, v)
    return Pretty(label, value, value)


def cell(key: str, value: str) -> str:
    """A table cell for a metadata column: the short readable value, else the raw one."""
    p = pretty(key, value) if value else None
    return p.short if p else value
