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

from capture_mitmproxy.addon import build_flow, build_stream_flow


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
    pf = build_stream_flow(f)
    assert (pf.authority, pf.metadata["hostname.source"]) == ("api.oneme.ru", "sni")

    f.client_conn.sni = None
    f.server_conn.sni = None
    pf = build_stream_flow(f)
    assert (pf.authority, pf.metadata["hostname.source"]) == ("155.212.204.68:443", "ip")


def test_regular_proxy_target_is_a_connect_name_not_an_ip():
    f = tflow.ttcpflow()
    f.server_conn.address = ("mtalk.google.com", 5228)
    f.client_conn.sni = None
    f.server_conn.sni = None
    pf = build_stream_flow(f)
    assert (pf.authority, pf.metadata["hostname.source"]) == ("mtalk.google.com:5228", "connect")


def test_mitmdump_can_load_the_addon_as_a_script():
    """mitmdump loads addon.py as a script, under a module name it never registers in
    sys.modules — not as the package module the other tests import. Anything that looks
    its module up there (a dataclass does) fails only this way, before any capture opens."""
    from pathlib import Path

    from mitmproxy.addons.script import load_script

    import capture_mitmproxy.addon as addon

    m = load_script(str(Path(addon.__file__)))
    assert m is not None, "mitmdump could not load the addon (see the traceback above)"
    assert any(type(a).__name__ == "GatewayPusher" for a in m.addons)


# --- body decoding -----------------------------------------------------------------------
# Bodies are decoded with a bound: mitmproxy's get_content() inflated the whole body before
# the cap applied, so a compression bomb could exhaust the proxy's memory first.

import gzip as _gzip  # noqa: E402
import tracemalloc  # noqa: E402

import pytest  # noqa: E402

from capture_mitmproxy import addon as _addon  # noqa: E402


@pytest.mark.parametrize("enc", ["gzip", "deflate", "br", "zstd"])
def test_compressed_bodies_decode_like_mitmproxy(enc):
    f = tflow.tflow(resp=True)
    body = b'{"hello": "world"} ' * 500
    f.response.content = body
    f.response.encode(enc)  # mitmproxy's own encoder sets content-encoding
    assert f.response.raw_content != body
    assert _addon._content(f.response) == (body, False)


def test_an_unknown_or_chained_encoding_is_kept_as_it_came():
    f = tflow.tflow(resp=True)
    f.response.headers["content-encoding"] = "gzip, br"
    f.response.raw_content = b"\x00\x01opaque"
    assert _addon._content(f.response) == (b"\x00\x01opaque", False)


def test_a_compression_bomb_is_cut_off_at_the_cap(monkeypatch):
    monkeypatch.setattr(_addon, "_MAX_BODY_BYTES", 1 << 20)
    f = tflow.tflow(resp=True)
    f.response.headers["content-encoding"] = "gzip"
    f.response.raw_content = _gzip.compress(b"\x00" * (200 << 20))  # 200 MiB of zeros, ~200 KB
    tracemalloc.start()
    try:
        out, cut = _addon._content(f.response)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(out) == 1 << 20 and cut
    assert peak < 32 << 20, f"decoding peaked at {peak} bytes"


def test_a_body_that_exactly_fits_the_cap_is_not_called_cut(monkeypatch):
    monkeypatch.setattr(_addon, "_MAX_BODY_BYTES", 1000)
    f = tflow.tflow(resp=True)
    f.response.content = b"x" * 1000
    f.response.encode("gzip")
    assert _addon._content(f.response) == (b"x" * 1000, False)
    f.response.raw_content = b"y" * 1000  # plain, no encoding
    del f.response.headers["content-encoding"]
    assert _addon._content(f.response) == (b"y" * 1000, False)


def test_a_cut_body_is_named_on_the_flow_and_logged(monkeypatch, caplog):
    monkeypatch.setattr(_addon, "_MAX_BODY_BYTES", 1000)
    f = tflow.tflow(resp=True)
    f.response.content = b"z" * 5000
    f.response.encode("gzip")
    with caplog.at_level("WARNING", logger=_addon.__name__):
        pf = _addon.build_flow(f)
    assert pf.response_body.size == 1000
    assert pf.metadata["body.truncated"] == "response"
    assert "response cut" in caplog.text


def test_a_cut_message_is_named_and_logged(monkeypatch, caplog):
    monkeypatch.setattr(_addon, "_MAX_BODY_BYTES", 10)
    with caplog.at_level("WARNING", logger=_addon.__name__):
        m = _addon._message("f1", True, "binary", b"0123456789abc", 0)
    assert m.payload.size == 10 and m.payload.inline == b"0123456789"
    assert m.metadata["body.truncated"] == "payload"
    assert "payload cut" in caplog.text
    assert "body.truncated" not in _addon._message("f1", True, "binary", b"short", 0).metadata
