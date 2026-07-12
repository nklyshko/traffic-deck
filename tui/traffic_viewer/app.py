"""Traffic-viewer TUI: a read-only Textual UI over the gateway's ViewerService.
Session list → a tabbed workspace (one flow table per open session) → flow detail, with
live follow, annotations, filtering, cross-tab compare, and export. See render.py /
filters.py / screens.py for the pieces."""

from __future__ import annotations

import os

from textual.app import App
from textual.binding import Binding
from textual.screen import Screen

from traffic_viewer.client import GatewayClient
from traffic_viewer.screens import ConfirmScreen, QuitConfirmScreen, SessionsScreen


class TrafficViewerApp(App):
    CSS = """
    DataTable { height: 1fr; }
    TabbedContent { height: 1fr; }
    SessionPane { height: 1fr; }
    #pane-status { color: $text-muted; }
    #filter-help {
        display: none;               /* revealed only while the filter input is focused */
        dock: bottom; height: auto; padding: 0 1;
        color: $text-muted; background: $panel; border-top: tall $accent;
    }
    TextPrompt, SelectPrompt, ConfirmScreen { align: center middle; }
    #prompt {
        width: 60; height: auto; max-height: 80%;
        padding: 1 2; border: thick $accent; background: $surface;
    }
    #prompt Label { margin-bottom: 1; }
    #prompt OptionList { height: auto; max-height: 16; }
    #confirm-buttons { height: auto; align: center middle; }
    #confirm-buttons Button { margin: 0 1; }
    """
    BINDINGS = [Binding("q", "quit", "Quit")]

    def __init__(self, address: str) -> None:
        super().__init__()
        self.address = address
        self.client = GatewayClient(address)
        self.compare_a: tuple[str, str] | None = None  # (session_id, flow_id) for compare slot A

    def get_default_screen(self) -> Screen:
        return SessionsScreen()

    def _open_quit_dialog(self) -> None:
        """Ask before tearing down. No-op if a dialog is already up (don't stack)."""
        if isinstance(self.screen, ConfirmScreen):
            return

        def on_confirm(confirmed: bool | None) -> None:
            if confirmed:
                self.exit()

        self.push_screen(QuitConfirmScreen("Quit TrafficDeck?"), on_confirm)

    def action_quit(self) -> None:  # type: ignore[override]
        # Every screen's `q` binding resolves here.
        self._open_quit_dialog()

    def action_help_quit(self) -> None:  # type: ignore[override]
        # Ctrl+C on a normal screen opens the quit dialog (Textual 8.x no longer quits on
        # Ctrl+C by default). A second Ctrl+C on the dialog confirms — handled by
        # QuitConfirmScreen, since the app-level binding can't reach through a modal.
        self._open_quit_dialog()

    async def on_unmount(self) -> None:
        await self.client.close()


def main() -> None:
    address = os.environ.get("GATEWAY_ADDR", "127.0.0.1:8080")
    TrafficViewerApp(address).run()


if __name__ == "__main__":
    main()
