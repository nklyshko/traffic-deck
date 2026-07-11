"""Tests for the formatting/rendering helpers (traffic_viewer.render)."""

from __future__ import annotations

import types

from traffic_viewer import render


def header(name, value):
    return types.SimpleNamespace(name=name, value=value)


def proxy(addr="", ptype="", username="", password=""):
    return types.SimpleNamespace(addr=addr, type=ptype, username=username, password=password)


def flow(**kw):
    d = dict(
        method="GET", authority="api.example.com", path="/v1", query="", scheme="https",
        status=200, protocol="HTTP/2", request_headers=[], response_headers=[],
        mark_color="", tag_ids=[], group_ids=[], favorite=False, comments=[],
        websocket=False, ws_message_count=0, proxy=proxy(), metadata={}, error="",
        ts_unix_micros=0, duration_micros=0, http2_fingerprint="",
        ja3="", ja4="", tls_client_hello="", redirect_location="", redirected_from_id="",
    )
    d.update(kw)
    return types.SimpleNamespace(**d)


def test_format_http2_fingerprint():
    lines = render.format_http2_fingerprint("1:65536;3:1000;4:6291456|15663105|0|m,a,s,p")
    assert lines == [
        "SETTINGS: HEADER_TABLE_SIZE=65536, MAX_CONCURRENT_STREAMS=1000, INITIAL_WINDOW_SIZE=6291456",
        "WINDOW_UPDATE: 15663105",
        "PRIORITY: none",
        "pseudo-header order: :method, :authority, :scheme, :path",
    ]
    # A malformed value is returned as-is (never raises).
    assert render.format_http2_fingerprint("garbage") == ["garbage"]


def test_fmt_duration():
    assert render.fmt_duration(0.042) == "42ms"
    assert render.fmt_duration(1.3) == "1.3s"
    assert render.fmt_duration(125) == "2m05s"


def test_duration_cell_final():
    # A completed flow shows its frozen request→response duration.
    cell = render.duration_cell(flow(status=200, duration_micros=230_000))
    assert cell.plain == "230ms"
    assert cell.style == "dim"


def test_duration_cell_live_stopwatch():
    import time as _t
    # An in-flight request (no response, no error) in an open session shows a ticking
    # stopwatch; once the session closes it goes blank rather than ticking forever.
    f = flow(status=0, error="", duration_micros=0, ts_unix_micros=int((_t.time() - 1.5) * 1_000_000))
    cell = render.duration_cell(f, live=True)
    assert cell.plain.startswith("⏱ ")
    assert cell.style == "yellow"
    assert render.duration_cell(f, live=False).plain == ""


def test_duration_cell_blank_when_failed():
    # A failed / response-less flow with a reason shows no stopwatch (the status cell flags it).
    assert render.duration_cell(flow(status=0, error="boom", duration_micros=0)).plain == ""


def test_status_cell_colors_by_class():
    cases = {200: "green", 302: "yellow", 404: "red", 500: "bold red"}
    for status, style in cases.items():
        cell = render.status_cell(flow(status=status))
        assert cell.plain == str(status)
        assert cell.style == style


def test_status_cell_no_response():
    # status 0 with no recorded error → blank (may still be pending).
    assert render.status_cell(flow(status=0, error="")).plain == ""
    # status 0 with a captured failure reason → red error marker.
    cell = render.status_cell(flow(status=0, error="Connection timed out"))
    assert cell.plain == "✗ err"
    assert cell.style == "bold red"


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


# --- editor handoff helpers -----------------------------------------------

def test_is_text():
    assert render.is_text(b'{"k":1}') is True
    assert render.is_text(b"\xff\xfe\xfd") is False


def test_editor_suffix_by_content_type():
    assert render.editor_suffix("application/json; charset=utf-8", b"{}") == ".json"
    assert render.editor_suffix("text/html", b"<x>") == ".html"
    assert render.editor_suffix("application/xml", b"<x/>") == ".xml"
    assert render.editor_suffix("application/javascript", b"x") == ".js"
    assert render.editor_suffix("text/plain", b"hi") == ".txt"
    assert render.editor_suffix("application/x-www-form-urlencoded", b"a=1") == ".txt"


def test_editor_suffix_sniffs_when_content_type_unknown():
    assert render.editor_suffix("application/octet-stream", b"plain text") == ".txt"
    assert render.editor_suffix("application/octet-stream", b"\xff\xfe") == ".bin"


def test_body_for_editor_pretty_prints_json():
    out = render.body_for_editor("application/json", b'{"b":2,"a":1}')
    assert out == b'{\n  "b": 2,\n  "a": 1\n}'


def test_body_for_editor_sniffs_json_without_content_type():
    assert render.body_for_editor("", b"  [1,2]").startswith(b"[\n")


def test_body_for_editor_passes_through_non_json():
    assert render.body_for_editor("text/plain", b"hello [x]") == b"hello [x]"
    assert render.body_for_editor("application/json", b"{bad") == b"{bad"  # invalid → verbatim


def test_editor_command_prefers_env_editor(monkeypatch):
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", "vim -R")
    argv, terminal = render.editor_command("/tmp/x.json")
    assert argv == ["vim", "-R", "/tmp/x.json"] and terminal is True


def test_editor_command_falls_back_to_gui_opener(monkeypatch):
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.delenv("EDITOR", raising=False)
    argv, terminal = render.editor_command("/tmp/x.json")
    assert argv[-1] == "/tmp/x.json" and argv[0] in ("xdg-open", "open")
    assert terminal is False


# --- flow-table flags cell ------------------------------------------------

def test_flags_cell():
    f = flow(favorite=True, mark_color="red", tag_ids=["a", "b"],
             comments=[types.SimpleNamespace(body="x")], group_ids=["g"],
             websocket=True, ws_message_count=3)
    plain = render.flags_cell(f, selected=True).plain
    assert "✓" in plain and "★" in plain and "●" in plain
    assert "#2" in plain and "💬" in plain and "⬡" in plain and "⇅3" in plain

    assert render.flags_cell(flow(), selected=False).plain == ""
    assert "⇄" in render.flags_cell(flow(proxy=proxy("10.0.0.9:8080", "http")), selected=False).plain


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
