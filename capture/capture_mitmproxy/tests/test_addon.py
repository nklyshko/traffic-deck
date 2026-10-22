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
