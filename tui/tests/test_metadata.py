"""Readable metadata: the values capture sources store stay as they are; the viewer only
says what they mean."""

from __future__ import annotations

import traffic_viewer.client  # noqa: F401 — puts the generated stubs on sys.path
from traffic_viewer.metadata import cell, pretty


def test_known_values_read_as_what_they_mean():
    p = pretty("hostname.source", "host")
    assert (p.label, p.value, p.short) == ("Hostname from", "the Host header", "Host header")
    assert pretty("hostname.source", "dns").short == "DNS (inferred)"
    assert "pinned" in pretty("conn.outcome", "tls_rejected").value
    assert pretty("dns.rcode", "NXDOMAIN").short == "no such name"


def test_values_are_formatted_not_changed():
    assert pretty("conn.bytes_down", "1536").value == "1.5 KiB"
    assert pretty("conn.bytes_up", "12").value == "12 B"
    assert pretty("hostname.dns_candidates", "a.example,b.example").value == "a.example, b.example"
    assert pretty("hostname.dns_flow", "3f2a9c1b-0000-4000-8000-000000000000").short == "3f2a9c1b"
    assert pretty("tls.sni", "api.example.com") == ("TLS SNI", "api.example.com", "api.example.com")


def test_unknown_keys_and_values_pass_through():
    assert pretty("max.cmd", "Request(0)") is None         # a decoder's own key
    assert cell("max.cmd", "Request(0)") == "Request(0)"
    assert pretty("hostname.source", "future") == ("Hostname from", "future", "future")
    assert cell("hostname.source", "") == ""
