"""Tests for the persistent home (capture_sdk.paths) and remembered selections
(capture_sdk.state), plus the pre-checked multi-select choice mapping."""

from __future__ import annotations

import json

import questionary

from capture_sdk import paths, prompt
from capture_sdk.state import Store


def test_home_respects_env(monkeypatch, tmp_path):
    monkeypatch.setenv("TRAFFIC_DECK_HOME", str(tmp_path))
    assert paths.home() == tmp_path
    d = paths.data_dir("sub", "dir")
    assert d.is_dir() and d == tmp_path / "sub" / "dir"


def test_home_defaults_under_traffic_deck(monkeypatch):
    monkeypatch.delenv("TRAFFIC_DECK_HOME", raising=False)
    assert paths.home().name == ".traffic-deck"


def test_store_persists_and_reloads(monkeypatch, tmp_path):
    monkeypatch.setenv("TRAFFIC_DECK_HOME", str(tmp_path))
    s = Store("demo")
    assert s.get("k", "fallback") == "fallback"
    assert s.remember("k", "v") == "v"  # returns the value for inline wrapping

    saved = tmp_path / "state" / "demo.json"
    assert json.loads(saved.read_text()) == {"k": "v"}
    assert Store("demo").get("k") == "v"  # a fresh Store reloads from disk


def test_store_get_valid_drops_stale_values(monkeypatch, tmp_path):
    monkeypatch.setenv("TRAFFIC_DECK_HOME", str(tmp_path))
    s = Store("demo")
    s.remember("chrome", "/usr/bin/chromium")
    assert s.get_valid("chrome", ["/usr/bin/chromium", "/usr/bin/chrome"]) == "/usr/bin/chromium"
    assert s.get_valid("chrome", ["/snap/chromium"]) is None       # no longer an option
    assert s.get_valid("missing", ["x"], default="d") == "d"


def test_store_remembers_tuple_selection(monkeypatch, tmp_path):
    # A dynamically-built choice (e.g. a discovered Chrome profile) has a tuple value;
    # it must persist and still match the freshly-built choice list next run.
    monkeypatch.setenv("TRAFFIC_DECK_HOME", str(tmp_path))
    choice = ("/home/u/.config/google-chrome", "Profile 1")
    Store("demo").remember("existing_profile", choice)

    saved = json.loads((tmp_path / "state" / "demo.json").read_text())
    assert saved["existing_profile"] == ["/home/u/.config/google-chrome", "Profile 1"]  # JSON list

    s2 = Store("demo")  # reloaded from disk
    values = [("/other", "Default"), choice]
    assert s2.get_valid("existing_profile", values) == choice          # matched back to the tuple
    assert s2.get_valid("existing_profile", [("/other", "Default")]) is None  # no longer offered


def test_store_survives_corrupt_file(monkeypatch, tmp_path):
    monkeypatch.setenv("TRAFFIC_DECK_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "demo.json").write_text("{not json")
    s = Store("demo")  # falls back to empty instead of crashing
    assert s.get("k") is None
    s.remember("k", 1)
    assert Store("demo").get("k") == 1


def test_to_choices_marks_checked():
    out = prompt._to_choices(["a", ("Label B", "b"), "c"], checked={"b", "c"})
    assert out[0] == "a"  # unchecked plain string stays a plain string
    assert isinstance(out[1], questionary.Choice) and out[1].value == "b" and out[1].checked
    assert isinstance(out[2], questionary.Choice) and out[2].value == "c" and out[2].checked
