"""The addon's launcher-supplied session metadata. Another module driving this proxy (the
Android browser capture) records what the capture *was* this way, so a bundle read back
later says more than "mitmproxy"."""

from __future__ import annotations

from capture_mitmproxy.addon import _extra_metadata


def test_metadata_is_parsed_into_strings():
    assert _extra_metadata('{"android.package": "com.android.chrome", "n": 2}') == {
        "android.package": "com.android.chrome", "n": "2"}


def test_unset_metadata_is_simply_absent():
    assert _extra_metadata("") == {}


def test_bad_metadata_is_dropped_rather_than_raised():
    """A launcher's typo must not cost the capture: the session still opens, just without
    the extra keys."""
    assert _extra_metadata("{not json") == {}
    assert _extra_metadata("[1, 2]") == {}   # a JSON array has no .items()


# --- hostnames -------------------------------------------------------------------------
# In WireGuard and transparent mode mitmproxy's request.host is only the IP it connected
# to; the flow's authority must be the name the client asked for, with its source recorded.

from mitmproxy.test import tflow

from capture_mitmproxy.addon import build_flow, build_tcp_flow


def _wireguard_flow(http_version="HTTP/1.1", host_header="api.example.com", sni="api.example.com"):
    f = tflow.tflow(resp=True)
    f.request.host = "203.0.113.7"          # what WireGuard mode connected to
    f.request.http_version = http_version
    f.request.headers.pop("Host", None)
    if host_header:
        if http_version == "HTTP/1.1":
            f.request.headers["Host"] = host_header
        else:
            f.request.authority = host_header
    else:
        f.request.authority = ""
    f.client_conn.sni = sni
    f.server_conn.sni = sni
    return f


def test_http1_authority_is_the_host_header_not_the_ip():
    pf = build_flow(_wireguard_flow(host_header="api.example.com:8443"))
    assert pf.authority == "api.example.com"            # port stripped, like pretty_host
    assert pf.metadata["hostname.source"] == "host"
    assert pf.metadata["tls.sni"] == "api.example.com"


def test_http2_authority_comes_from_the_authority_pseudo_header():
    pf = build_flow(_wireguard_flow(http_version="HTTP/2.0"))
    assert pf.authority == "api.example.com"
    assert pf.metadata["hostname.source"] == "authority"


def test_no_host_falls_back_to_sni_then_ip():
    pf = build_flow(_wireguard_flow(host_header=None, sni="cdn.example.com"))
    assert (pf.authority, pf.metadata["hostname.source"]) == ("cdn.example.com", "sni")

    pf = build_flow(_wireguard_flow(host_header=None, sni=None))
    assert (pf.authority, pf.metadata["hostname.source"]) == ("203.0.113.7", "ip")
    assert "tls.sni" not in pf.metadata


def test_a_host_header_that_disagrees_with_sni_keeps_both():
    pf = build_flow(_wireguard_flow(host_header="hidden.example", sni="front.example"))
    assert pf.authority == "hidden.example"
    assert pf.metadata["tls.sni"] == "front.example"


def test_tcp_flow_is_named_by_sni_else_ip_and_port():
    f = tflow.ttcpflow()
    f.server_conn.address = ("155.212.204.68", 443)
    f.client_conn.sni = "api.oneme.ru"
    pf = build_tcp_flow(f)
    assert (pf.authority, pf.metadata["hostname.source"]) == ("api.oneme.ru", "sni")

    f.client_conn.sni = None
    f.server_conn.sni = None
    pf = build_tcp_flow(f)
    assert (pf.authority, pf.metadata["hostname.source"]) == ("155.212.204.68:443", "ip")


def test_regular_proxy_target_is_a_connect_name_not_an_ip():
    f = tflow.ttcpflow()
    f.server_conn.address = ("mtalk.google.com", 5228)
    f.client_conn.sni = None
    f.server_conn.sni = None
    pf = build_tcp_flow(f)
    assert (pf.authority, pf.metadata["hostname.source"]) == ("mtalk.google.com:5228", "connect")
