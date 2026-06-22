"""Tests for the mitmproxy-style filter DSL (traffic_viewer.filters)."""

from __future__ import annotations

import types

import pytest

from traffic_viewer.filters import compile_filter


def comment(body):
    return types.SimpleNamespace(body=body)


def flow(**kw):
    d = dict(
        method="GET", authority="api.example.com", path="/v1", query="", scheme="https",
        status=200, content_type="application/json",
        mark_color="", tag_ids=[], group_ids=[], favorite=False, comments=[],
    )
    d.update(kw)
    return types.SimpleNamespace(**d)


def test_empty_expression_is_none():
    assert compile_filter("") is None
    assert compile_filter("   ") is None


def test_field_terms():
    f = flow()
    assert compile_filter("~m GET")(f) is True
    assert compile_filter("~m POST")(f) is False
    assert compile_filter("~d example")(f) is True
    assert compile_filter("~u /v1")(f) is True
    assert compile_filter("~c 200")(f) is True
    assert compile_filter("~c 404")(f) is False
    assert compile_filter("~t json")(f) is True


def test_status_presence():
    assert compile_filter("~s")(flow(status=200)) is True
    assert compile_filter("~s")(flow(status=0)) is False
    assert compile_filter("~q")(flow(status=0)) is True
    assert compile_filter("~q")(flow(status=200)) is False


def test_favorite():
    assert compile_filter("~fav")(flow(favorite=True)) is True
    assert compile_filter("~fav")(flow(favorite=False)) is False


def test_annotation_fields_with_name_maps():
    f = flow(mark_color="red", tag_ids=["t1"], group_ids=["g1"], comments=[comment("needs review")])
    tagnames = {"t1": "auth"}
    groupnames = {"g1": "login-flow"}
    assert compile_filter("~mark red", tagnames, groupnames)(f) is True
    assert compile_filter("~tag auth", tagnames, groupnames)(f) is True
    assert compile_filter("~tag nope", tagnames, groupnames)(f) is False
    assert compile_filter("~group login", tagnames, groupnames)(f) is True
    assert compile_filter("~comment review", tagnames, groupnames)(f) is True


def test_naked_regex_matches_url():
    f = flow(authority="api.oneme.ru", path="/login")
    assert compile_filter("oneme")(f) is True
    assert compile_filter("nomatch")(f) is False


def test_negation_both_forms():
    f = flow(method="GET")
    assert compile_filter("!~m POST")(f) is True
    assert compile_filter("! ~m POST")(f) is True
    assert compile_filter("!~m GET")(f) is False


def test_terms_are_anded():
    f = flow(method="GET", status=200)
    assert compile_filter("~m GET ~c 200")(f) is True
    assert compile_filter("~m GET ~c 404")(f) is False


def test_bad_regex_raises():
    with pytest.raises(ValueError):
        compile_filter("~u (unclosed")
    with pytest.raises(ValueError):
        compile_filter("[bad")  # naked regex


def test_field_missing_argument_raises():
    with pytest.raises(ValueError):
        compile_filter("~m")
