"""Tests for the request-comparison screen: the Go-slice export helpers and the
diff renderer that shows every compared field (not just the differing ones)."""

from __future__ import annotations

import types

from traffic_viewer.screens import CompareScreen


def header(name, value):
    return types.SimpleNamespace(name=name, value=value)


def body(inline=b"", content_type=""):
    return types.SimpleNamespace(size=len(inline), inline=inline, content_type=content_type)


def flow(headers, request_body=b""):
    return types.SimpleNamespace(
        method="GET", authority="api.example.com", path="/v1", protocol="HTTP/2",
        request_headers=[header(n, v) for n, v in headers],
        request_body=body(request_body),
    )


# --- Go []string{} export -------------------------------------------------


def test_go_slice_formats_gofmt_style():
    assert CompareScreen._go_slice(["accept", "host"]) == (
        '[]string{\n\t"accept",\n\t"host",\n}'
    )


def test_go_slice_empty():
    assert CompareScreen._go_slice([]) == "[]string{}"


def test_go_quote_escapes():
    assert CompareScreen._go_quote('a"b\\c') == '"a\\"b\\\\c"'


# --- order extraction (what the copy actions export) ----------------------


def test_regular_skips_pseudo_headers():
    f = flow([(":method", "GET"), ("accept", "*/*"), ("host", "x")])
    assert [n for n, _ in CompareScreen._regular(f)] == ["accept", "host"]


def test_pseudo_extracted_separately_from_regular():
    f = flow([(":method", "GET"), (":path", "/v1"), ("accept", "*/*")])
    assert CompareScreen._pseudo(f) == [":method", ":path"]


def test_cookies_preserve_wire_order():
    f = flow([("cookie", "b=2; a=1; sid=zzz")])
    assert [n for n, _ in CompareScreen._cookies(f)] == ["b", "a", "sid"]


# --- diff renderer shows ALL data, highlighting differences ---------------


def _render(a, b, focus="A"):
    """Render both side-by-side columns; returns (left_A, right_B) plain text."""
    screen = CompareScreen.__new__(CompareScreen)
    screen._side = focus
    left, right = CompareScreen._render_columns(screen, a, b)
    return left.plain, right.plain


def test_render_shows_matching_values_not_only_diffs():
    a = flow([("accept", "*/*"), ("x-token", "same")])
    b = flow([("accept", "text/html"), ("x-token", "same")])
    left, right = _render(a, b)
    # Each column shows its own value for the differing header...
    assert "*/*" in left and "text/html" in right
    # ...and a matching header appears in both (the old renderer hid matches).
    assert "x-token: same" in left and "x-token: same" in right
    assert "✓ match" in left and "✗ differ" in left


def test_render_columns_stay_line_aligned():
    # B drops a header and adds one; columns must keep equal line counts so the
    # git-style -/+ rows stay aligned across the two panes.
    a = flow([("accept", "*/*"), ("x-a", "1")])
    b = flow([("accept", "*/*"), ("x-b", "2")])
    left, right = _render(a, b)
    assert left.count("\n") == right.count("\n")
    assert "- x-a: 1" in left  # removed on the left
    assert "+ x-b: 2" in right  # added on the right


def test_render_marks_copy_target_side():
    a = flow([("accept", "*/*")])
    b = flow([("accept", "*/*")])
    left, _ = _render(a, b, focus="A")
    assert "▸ A" in left
    _, right = _render(a, b, focus="B")
    assert "▸ B" in right


# --- request-body diff (ADR-0011 §3a) -------------------------------------


def _render_bodies(a, b, ba, bb):
    """Render with explicit fetched request bodies (what _fetch_body returns)."""
    screen = CompareScreen.__new__(CompareScreen)
    screen._side = "A"
    screen._ba, screen._bb = ba, bb
    left, right = CompareScreen._render_columns(screen, a, b)
    return left.plain, right.plain


def _bodyless(size):
    """A flow whose body is in the bundle: it has a size but carries no inline bytes."""
    f = flow([("accept", "*/*")])
    f.request_body = types.SimpleNamespace(size=size, inline=b"")
    return f


def test_different_bodies_are_not_reported_equal_when_inline_is_empty():
    """Once a body lives in the bundle, `.inline` is empty for every flow. Comparing it
    would read two different bodies as identical — a wrong answer, not an error."""
    left, _ = _render_bodies(_bodyless(11), _bodyless(11), b"hello world", b"world hello")
    assert "Request body  \u2717 differ" in left
    assert "Request body  \u2713 match" not in left


def test_identical_fetched_bodies_match():
    left, _ = _render_bodies(_bodyless(5), _bodyless(5), b"hello", b"hello")
    assert "Request body  \u2713 match" in left


def test_unreadable_body_is_reported_not_assumed_equal():
    left, right = _render_bodies(_bodyless(9), _bodyless(9), None, None)
    assert "unreadable" in left and "unreadable" in right
    assert "Request body  \u2713 match" not in left
