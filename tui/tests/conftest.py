import pytest


@pytest.fixture(autouse=True)
def _viewer_home(tmp_path, monkeypatch):
    """The viewer remembers choices under $TRAFFIC_DECK_HOME; a test must neither read the
    developer's nor write there."""
    monkeypatch.setenv("TRAFFIC_DECK_HOME", str(tmp_path / "td-home"))
