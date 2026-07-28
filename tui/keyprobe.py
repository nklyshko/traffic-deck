"""Scratch: print the key name Textual sees, to find what a terminal really sends.

    uv run --project tui tui/keyprobe.py     (q or ctrl+q to quit)
"""
from textual.app import App, ComposeResult
from textual.widgets import Header, Static


class KeyProbe(App):
    CSS = "Static { padding: 1 2; }"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("press keys — Cmd+↑ Cmd+↓ Cmd+← Cmd+→ …", id="out")

    def on_key(self, event) -> None:
        if event.key in ("q", "ctrl+q"):
            self.exit()
            return
        self.query_one("#out", Static).update(
            f"key={event.key!r}\naliases={event.aliases}\ncharacter={event.character!r}")


if __name__ == "__main__":
    KeyProbe().run()
