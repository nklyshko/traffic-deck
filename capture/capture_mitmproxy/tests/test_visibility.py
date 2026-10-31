"""Everything a WireGuard capture saw is recorded, even what it could not decode: DNS
lookups, UDP that is not HTTP/3, a client that refused mitmproxy's certificate, and one
that closed before any request — and a connection with no name of its own is named by
the device's DNS answer for its IP."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from unittest.mock import AsyncMock

from mitmproxy import dns
from mitmproxy.proxy.mode_specs import ProxyMode
from mitmproxy.test import tflow, tutils

from capture_mitmproxy.addon import (DnsNames, GatewayPusher, build_dns_flow, build_flow,
                                     build_stream_flow, outcome_counts)


def _lookup(name: str, *ips: str, at: float = 100.0, rcode=dns.response_codes.NOERROR) -> dns.DNSFlow:
    q = dns.Question(name, dns.types.A, dns.classes.IN)
    req = tutils.tdnsreq(questions=[q], timestamp=at)
    resp = tutils.tdnsresp(questions=[q], timestamp=at + 0.02, response_code=rcode,
                           answers=[dns.ResourceRecord.A(name, ipaddress.IPv4Address(ip)) for ip in ips])
    return tflow.tdnsflow(req=req, resp=resp)


def _nameless_http(ip: str, opened: float):
    """An HTTP flow WireGuard mode saw going to ip with neither a Host nor an SNI."""
    f = tflow.tflow(resp=True)
    f.request.host = ip
    f.request.headers.pop("Host", None)
    f.client_conn.sni = None
    f.server_conn.sni = None
    f.client_conn.timestamp_start = opened
    return f


def _pusher() -> GatewayPusher:
    p = GatewayPusher()
    p.session_id = "s"
    p._send = AsyncMock()
    return p


def _pushed(p: GatewayPusher):
    return [f for call in p._send.call_args_list for f in call.kwargs.get("flows", [])]


def test_dns_lookup_is_a_flow_with_its_answers():
    pf = build_dns_flow(_lookup("api.oneme.ru", "155.212.204.68"))
    assert (pf.protocol, pf.method, pf.authority) == ("DNS", "A", "api.oneme.ru")
    assert pf.metadata["dns.rcode"] == "NOERROR" and not pf.error
    answers = json.loads(pf.response_body.inline)
    assert answers[0]["data"] == "155.212.204.68"
    assert pf.duration_micros == 20_000


def test_failed_lookup_says_why():
    pf = build_dns_flow(_lookup("nope.invalid", rcode=dns.response_codes.NXDOMAIN))
    assert pf.metadata["dns.rcode"] == "NXDOMAIN" and pf.error == "NXDOMAIN"


def test_a_nameless_connection_is_named_by_the_dns_answer_before_it():
    names = DnsNames()
    names.learn(_lookup("cdn-a.example", "203.0.113.5", at=100))
    names.learn(_lookup("cdn-b.example", "203.0.113.5", at=200))
    names.learn(_lookup("later.example", "203.0.113.5", at=900))  # after the connection

    pf = build_flow(_nameless_http("203.0.113.5", opened=300), names)
    assert pf.authority == "cdn-b.example"
    assert pf.metadata["hostname.source"] == "dns"
    assert pf.metadata["hostname.dns_flow"]
    assert pf.metadata["hostname.dns_candidates"] == "cdn-a.example"


def test_dns_never_overrides_a_name_the_client_sent():
    names = DnsNames()
    names.learn(_lookup("other.example", "203.0.113.5", at=100))
    f = _nameless_http("203.0.113.5", opened=300)
    f.request.headers["Host"] = "asked.example"
    pf = build_flow(f, names)
    assert (pf.authority, pf.metadata["hostname.source"]) == ("asked.example", "host")
    assert "hostname.dns_flow" not in pf.metadata and "hostname.dns_candidates" not in pf.metadata


def test_an_unanswered_ip_stays_an_ip():
    pf = build_flow(_nameless_http("203.0.113.9", opened=300), DnsNames())
    assert (pf.authority, pf.metadata["hostname.source"]) == ("203.0.113.9", "ip")


def test_flows_carry_their_connection_id():
    f = tflow.tflow(resp=True)
    pf = build_flow(f)
    assert pf.connection_id and pf.connection_id == f.client_conn.id[:8]


def test_udp_that_nothing_decodes_is_a_stream_flow():
    f = tflow.tudpflow()
    f.client_conn.sni = None
    f.server_conn.sni = None
    f.server_conn.address = ("198.51.100.20", 3478)
    pf = build_stream_flow(f)
    assert (pf.protocol, pf.authority) == ("UDP", "198.51.100.20:3478")
    assert pf.metadata["conn.outcome"] == "udp_undecoded"
    assert (pf.metadata["conn.bytes_up"], pf.metadata["conn.bytes_down"]) == ("5", "7")


def test_raw_tcp_is_a_passthrough_stream():
    pf = build_stream_flow(tflow.ttcpflow())
    assert pf.protocol == "TCP" and pf.metadata["conn.outcome"] == "tcp_passthrough"


def _wireguard_client(dst=("155.212.204.68", 443), sni=None):
    c = tflow.tclient_conn()
    c.proxy_mode = ProxyMode.parse("wireguard")
    c.sockname = dst
    c.sni = sni
    return c


class _TlsData:
    def __init__(self, client, error):
        self.context = type("Ctx", (), {"client": client})()
        self.conn = client
        client.error = error


def test_a_rejected_certificate_is_recorded_with_why():
    p = _pusher()
    client = _wireguard_client(sni="api.oneme.ru")
    asyncio.run(p.tls_failed_client(_TlsData(client, "unknown ca")))
    (pf,) = _pushed(p)
    assert (pf.protocol, pf.authority, pf.dst_addr) == ("TCP", "api.oneme.ru", "155.212.204.68:443")
    assert pf.metadata["conn.outcome"] == "tls_rejected"
    assert "pinned" in pf.error and "unknown ca" in pf.error
    # Its disconnect is not a second, no_request record.
    asyncio.run(p.client_disconnected(client))
    assert len(_pushed(p)) == 1
    assert p.outcomes["tls_rejected"] == 1


def test_a_connection_closed_before_any_request_is_recorded():
    p = _pusher()
    p.names.learn(_lookup("quiet.example", "155.212.204.68", at=0))
    client = _wireguard_client()
    asyncio.run(p.client_disconnected(client))
    (pf,) = _pushed(p)
    assert pf.metadata["conn.outcome"] == "no_request"
    assert (pf.authority, pf.metadata["hostname.source"]) == ("quiet.example", "dns")


def test_a_connection_that_carried_a_request_is_not_recorded_again():
    p = _pusher()
    f = tflow.tflow(resp=True)
    asyncio.run(p.request(f))
    asyncio.run(p.client_disconnected(f.client_conn))
    assert [pf.protocol for pf in _pushed(p)] == ["HTTP/1.1"]


def test_a_lookup_counts_as_its_connection_being_used_and_names_later_flows():
    p = _pusher()
    lookup = _lookup("api.example", "203.0.113.5", at=100)
    asyncio.run(p.dns_response(lookup))
    asyncio.run(p.client_disconnected(lookup.client_conn))
    asyncio.run(p.request(_nameless_http("203.0.113.5", opened=300)))
    protos = [(pf.protocol, pf.authority) for pf in _pushed(p)]
    assert protos == [("DNS", "api.example"), ("HTTP/1.1", "api.example")]


def test_close_reports_every_reason_even_zero():
    from collections import Counter
    assert outcome_counts(Counter({"tls_rejected": 2})) == {
        "conn.undecoded.tls_rejected": "2", "conn.undecoded.no_request": "0",
        "conn.undecoded.udp_undecoded": "0"}


def test_a_regular_proxy_tunnel_that_carried_nothing_names_its_connect_target():
    p = _pusher()
    connect = tflow.tflow()
    connect.request.method = "CONNECT"
    connect.request.host, connect.request.port = "quiet.example", 443
    connect.client_conn.sni = None
    p.http_connect(connect)
    asyncio.run(p.client_disconnected(connect.client_conn))
    (pf,) = _pushed(p)
    assert (pf.authority, pf.dst_addr) == ("quiet.example:443", "quiet.example:443")
    assert pf.metadata["conn.outcome"] == "no_request"
