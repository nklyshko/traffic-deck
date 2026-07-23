"""Tests for the Wireshark hand-off (traffic_viewer.wireshark): the display filter that
isolates one flow's packets, and the command line built around it."""

from __future__ import annotations

import types

from traffic_viewer.wireshark import (
    build_display_filter,
    describe_filter,
    split_addr,
    wireshark_command,
)


def flow(**kw):
    d = dict(protocol="HTTP/1.1", tcp_stream="", h2_stream_id="",
             src_addr="192.168.1.5:51000", dst_addr="93.184.216.34:443")
    d.update(kw)
    return types.SimpleNamespace(**d)


_CONN = ("ip.addr eq 192.168.1.5 and tcp.port eq 51000 and "
         "ip.addr eq 93.184.216.34 and tcp.port eq 443")


def test_http1_filter_is_the_whole_connection():
    # An HTTP/1.1 connection isn't multiplexed, so the connection *is* the scope.
    assert build_display_filter(flow(tcp_stream="12")) == _CONN


def test_http2_filter_narrows_to_the_stream_but_keeps_the_connection():
    f = flow(protocol="HTTP/2", tcp_stream="12", h2_stream_id="5")
    assert build_display_filter(f) == f"{_CONN} and (http2.streamid eq 5 or not http2)"


def test_http2_without_a_stream_id_stays_connection_wide():
    assert build_display_filter(flow(protocol="HTTP/2", tcp_stream="12")) == _CONN


def test_stream_id_is_ignored_on_a_non_http2_flow():
    # A WebSocket upgrade rides HTTP/1.1; an http2.streamid term would filter it all out.
    assert build_display_filter(flow(protocol="HTTP/1.1", h2_stream_id="1")) == _CONN


def test_the_connection_id_is_never_used_as_a_tcp_stream_index():
    # Only the tshark decode path numbers connections the way Wireshark does; the native
    # decoder's ids address a different stream, so the filter must not carry them over.
    assert "tcp.stream" not in build_display_filter(flow(tcp_stream="12"))


def test_quic_flow_matches_on_udp_ports():
    f = flow(protocol="HTTP/3", tcp_stream="quic:3")
    assert build_display_filter(f) == (
        "ip.addr eq 192.168.1.5 and udp.port eq 51000 and "
        "ip.addr eq 93.184.216.34 and udp.port eq 443")


def test_ipv6_endpoints_use_the_ipv6_field():
    f = flow(src_addr="[2606:4700::1]:51000", dst_addr="2606:4700::2:443")
    assert build_display_filter(f) == (
        "ipv6.addr eq 2606:4700::1 and tcp.port eq 51000 and "
        "ipv6.addr eq 2606:4700::2 and tcp.port eq 443")


def test_no_addresses_yields_no_filter():
    # Nothing pins the connection — better unfiltered than confidently wrong.
    f = flow(tcp_stream="12", h2_stream_id="5", protocol="HTTP/2", src_addr="", dst_addr="")
    assert build_display_filter(f) == ""


def test_split_addr_shapes():
    assert split_addr("1.2.3.4:443") == ("1.2.3.4", "443")
    assert split_addr("[2606:4700::1]:443") == ("2606:4700::1", "443")
    assert split_addr("2606:4700::1:443") == ("2606:4700::1", "443")
    assert split_addr("1.2.3.4") == ("1.2.3.4", "")
    assert split_addr("::1") == ("::1", "")   # bare address, not host ":" + port "1"
    assert split_addr("") == ("", "")


def test_describe_filter_names_the_scope():
    assert describe_filter(flow(tcp_stream="12")) == "conn 12"
    assert describe_filter(flow(protocol="HTTP/2", tcp_stream="12", h2_stream_id="5")) == \
        "conn 12 · stream 5"
    assert describe_filter(flow(tcp_stream="quic:3")) == "conn quic:3"
    assert describe_filter(flow(tcp_stream="")) == "93.184.216.34:443"


def test_command_carries_pcap_keylog_filter_and_frame():
    cmd = wireshark_command("/usr/bin/wireshark", "/d/capture.pcap", "/d/key.log",
                            "tcp.stream eq 12", 338)
    assert cmd == ["/usr/bin/wireshark", "-r", "/d/capture.pcap",
                   "-o", "tls.keylog_file:/d/key.log",
                   "-Y", "tcp.stream eq 12", "-g", "338"]


def test_command_drops_the_optional_parts():
    # pcapng with embedded secrets (no key.log), a flow with no frame number, no filter.
    assert wireshark_command("wireshark", "/d/capture.pcap") == \
        ["wireshark", "-r", "/d/capture.pcap"]
