"""Tests for the formatting/rendering helpers (traffic_viewer.render)."""

from __future__ import annotations

import types

from traffic_viewer import render


def header(name, value):
    return types.SimpleNamespace(name=name, value=value)


def flow(**kw):
    d = dict(
        method="GET", authority="api.example.com", path="/v1", query="", scheme="https",
        status=200, protocol="HTTP/2", request_headers=[], response_headers=[],
        mark_color="", tag_ids=[], group_ids=[], favorite=False, comments=[],
        websocket=False, ws_message_count=0,
    )
    d.update(kw)
    return types.SimpleNamespace(**d)


# --- small helpers --------------------------------------------------------

def test_fmt_time():
    assert render.fmt_time(0) == ""
    assert render.fmt_time(1_000_000) == "00:00:01.000"


def test_url():
    assert render.url(flow()) == "https://api.example.com/v1"
    assert render.url(flow(query="a=1")) == "https://api.example.com/v1?a=1"
    assert render.url(flow(scheme="")) == "https://api.example.com/v1"  # default scheme


def test_bytes_preview():
    assert render.bytes_preview(b"") == ""
    assert render.bytes_preview(b"hello\nworld") == "hello⏎world"
    assert render.bytes_preview(b"\xff\xfe") == "fffe"
    assert render.bytes_preview(b"x" * 100, limit=8) == "xxxxxxxx…"


def test_hexdump():
    out = render.hexdump(b"AB")
    assert out == "00000000  41 42                                            AB"


# --- body pretty-printing -------------------------------------------------

def test_format_body_json_pretty_and_highlighted():
    c = render.format_body("application/json", b'{"b":2,"a":[1]}', 20000)
    assert "\n" in c.plain and '"a"' in c.plain  # reindented
    assert len(c.spans) > 0                        # syntax-highlighted


def test_format_body_sniffs_json_without_content_type():
    c = render.format_body("", b"[1, 2, 3]", 20000)
    assert c.plain.startswith("[\n")


def test_format_body_form_urlencoded():
    c = render.format_body("application/x-www-form-urlencoded", b"user=bob&pw=p%40ss", 20000)
    assert c.plain == "user = bob\npw = p@ss"


def test_format_body_plain_text_with_brackets_is_literal():
    # A stray '[' must not be reparsed as markup.
    c = render.format_body("text/plain", b"hello [world] <ok>", 20000)
    assert c.plain == "hello [world] <ok>"


def test_format_body_invalid_json_falls_back_to_plain():
    c = render.format_body("application/json", b"{not json", 20000)
    assert c.plain == "{not json"


def test_format_body_binary_hexdumps():
    # Non-UTF-8 bytes can't be shown as text → hexdump fallback.
    c = render.format_body("application/octet-stream", b"\xff\xfe\xfd", 20000)
    assert "ff fe fd" in c.plain


def test_format_body_truncates_large_json():
    big = b'{"x":"' + b"y" * 30000 + b'"}'
    c = render.format_body("application/json", big, 100)
    assert "bytes total" in c.plain
    assert len(c.plain) < 200


# --- flow-table flags cell ------------------------------------------------

def test_flags_cell():
    f = flow(favorite=True, mark_color="red", tag_ids=["a", "b"],
             comments=[types.SimpleNamespace(body="x")], group_ids=["g"],
             websocket=True, ws_message_count=3)
    plain = render.flags_cell(f, selected=True).plain
    assert "✓" in plain and "★" in plain and "●" in plain
    assert "#2" in plain and "💬" in plain and "⬡" in plain and "⇅3" in plain

    assert render.flags_cell(flow(), selected=False).plain == ""


# --- export ---------------------------------------------------------------

def test_curl():
    f = flow(method="POST", protocol="HTTP/2", request_headers=[
        header(":method", "POST"),          # pseudo-header skipped
        header("host", "api.example.com"),  # host skipped
        header("content-type", "application/json"),
    ])
    cmd, bodyfile = render.curl(f, "abcd1234", b'{"k":1}')
    assert cmd.startswith("curl -X POST https://api.example.com/v1")
    assert "--http2" in cmd
    assert ":method" not in cmd and "-H 'host" not in cmd.lower()
    assert "-H 'content-type: application/json'" in cmd
    assert bodyfile and bodyfile.endswith("abcd1234-request.body")
    assert "--data-binary @" in cmd

    cmd2, bodyfile2 = render.curl(flow(method="GET"), "x", b"")
    assert bodyfile2 is None and "--data-binary" not in cmd2


def test_raw_message():
    f = flow(method="POST", path="/v1", query="a=1", protocol="HTTP/1.1",
             request_headers=[header("content-type", "text/plain")],
             response_headers=[header("server", "nginx")], status=201)
    req = render.raw_message(f, b"body", response=False)
    assert req.startswith(b"POST /v1?a=1 HTTP/1.1\ncontent-type: text/plain\n\nbody")
    resp = render.raw_message(f, b"ok", response=True)
    assert resp.startswith(b"HTTP/1.1 201\nserver: nginx\n\nok")
