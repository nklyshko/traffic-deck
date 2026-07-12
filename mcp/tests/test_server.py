"""Unit tests for the MCP server's pure (non-RPC) logic: structured-search matching,
timeline rows, and body/payload serialization. Real protobuf Flow/Body messages are
built from the generated stubs, so these exercise the same objects the tools see."""

from __future__ import annotations

# Importing the server wires the generated `gen/` tree onto sys.path (via client.py),
# so `traffic.v1.*` resolves afterwards.
import traffic_mcp.server as S
from traffic.v1 import common_pb2 as cp


def _flow(**kw):
    return cp.Flow(**kw)


# --- search matching ------------------------------------------------------

CRIT0 = dict(domain="", method="", content_type="", status=0, path_contains="",
             url_contains="", websocket=None, has_response=None)


def crit(**over):
    return {**CRIT0, **over}


def test_search_combined_domain_method_content_type():
    f = _flow(method="POST", authority="api.oneme.ru", path="/x", scheme="https",
              status=200, content_type="application/json; charset=utf-8")
    # All three criteria match (domain/content-type substring, method exact-ci).
    assert S._matches(f, **crit(domain="oneme.ru", method="post", content_type="json"))
    # One mismatch fails the AND.
    assert not S._matches(f, **crit(domain="oneme.ru", method="GET"))
    assert not S._matches(f, **crit(content_type="xml"))


def test_search_status_and_tristate():
    f = _flow(authority="h", status=0, websocket=True)
    assert S._matches(f, **crit(status=0))            # 0 == any
    assert not S._matches(f, **crit(status=200))
    assert S._matches(f, **crit(websocket=True))
    assert not S._matches(f, **crit(websocket=False))
    assert S._matches(f, **crit(has_response=False))  # no status => no response
    assert not S._matches(f, **crit(has_response=True))


def test_search_path_and_url_substring():
    f = _flow(scheme="https", authority="api.oneme.ru", path="/v3/items", query="a=1")
    assert S._matches(f, **crit(path_contains="/v3"))
    assert S._matches(f, **crit(url_contains="oneme.ru/v3/items?a=1"))
    assert not S._matches(f, **crit(path_contains="/v4"))


# --- timeline -------------------------------------------------------------

def test_timeline_row_relative_time():
    t0 = 1_000_000  # micros
    f = _flow(id="x", method="GET", authority="h", path="/p", query="q=1",
              status=200, content_type="text/html", protocol="HTTP/2",
              ts_unix_micros=1_500_000)
    row = S._timeline_row(3, f, t0)
    assert row["seq"] == 3
    assert row["t_ms"] == 500.0          # (1.5s - 1.0s) -> 500ms
    assert row["path"] == "/p?q=1"
    assert row["type"] == "html"


def test_timeline_row_unstamped_flow_has_null_time():
    f = _flow(id="ws", authority="h", websocket=True, ws_message_count=70,
              protocol="MAX", ts_unix_micros=0)
    row = S._timeline_row(0, f, 0)
    assert row["t_ms"] is None
    assert row["method"] == "WS"         # falls back to WS marker
    assert row["ws"] is True


# --- serialization helpers ------------------------------------------------

def test_short_type():
    assert S._short_type("application/json; charset=utf-8") == "json"
    assert S._short_type("text/html") == "html"
    assert S._short_type("") == ""


def test_body_ref_metadata_only():
    body = cp.Body(size=342, content_type="application/json", inline=b'{"a":1}')
    ref = S._body_ref(body)
    assert ref == {"content_type": "application/json", "size": 342}
    assert "inline" not in ref and "text" not in ref  # no body bytes
    assert S._body_ref(cp.Body(size=0)) is None


def test_bytes_payload_text_and_binary():
    text = S._bytes_payload(b'{"success":true}')
    assert text["encoding"] == "utf-8" and text["text"] == '{"success":true}'
    assert text["truncated"] is False
    binary = S._bytes_payload(b"\xff\xfe\x00\x01")
    assert binary["encoding"] == "base64" and "base64" in binary


def test_bytes_payload_hex_and_offset():
    data = b"\x0a\x00\x01\x02\x03\x04\x05"
    h = S._bytes_payload(data, as_hex=True)
    assert h["encoding"] == "hex" and h["hex"] == "0a000102030405"
    assert h["size"] == 7 and h["offset"] == 0 and h["returned"] == 7
    # windowed hex from an offset
    w = S._bytes_payload(data, as_hex=True, start=2)
    assert w["hex"] == "0102030405" and w["offset"] == 2 and w["size"] == 7


# --- compare_flows --------------------------------------------------------

def _hdr(name, value):
    return cp.Header(name=name, value=value)


def test_compare_flows_diff_and_identical():
    a = _flow(method="GET", scheme="https", authority="ex.com", path="/", status=200,
              ja4="t13d1516h2_abc_def", http2_fingerprint="1:65536|0|0|m,a,s,p",
              user_agent="UA/1",
              request_headers=[_hdr("user-agent", "UA/1"), _hdr("accept", "*/*")])
    b = _flow(method="GET", scheme="https", authority="ex.com", path="/", status=200,
              ja4="t13d1517h2_xyz_ghi", http2_fingerprint="1:65536|0|0|m,a,s,p",
              user_agent="UA/2",
              request_headers=[_hdr("accept", "*/*"), _hdr("user-agent", "UA/2")])

    d = S._compare_flows(a, b)
    assert d["params"]["ja4"]["equal"] is False
    assert d["params"]["http2_fingerprint"]["equal"] is True
    assert d["params"]["user_agent"]["equal"] is False
    # Header name order differs (ua/accept swapped).
    assert d["request_header_order"]["equal"] is False
    assert set(d["differences"]) == {"ja4", "user_agent", "request_header_order"}
    assert d["identical"] is False

    # A flow compared with itself is identical.
    same = S._compare_flows(a, a)
    assert same["identical"] is True and same["differences"] == []
