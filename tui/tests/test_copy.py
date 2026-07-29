"""Copying text out of the TUI.

Textual binds `ctrl+c,super+c` to `screen.copy_text` on every Screen, and the action
raises SkipAction when nothing is selected — so Ctrl+C copies a selection when there is
one and otherwise falls through to the app's quit hint. These tests pin that the app
actually inherits that behaviour: our screens define their own BINDINGS, and a stray
`ctrl+c` binding on one of them would silently take the copy away.

They cover the app side only. Whether the keypress reaches the app, and whether the
terminal honours the OSC 52 write, is the terminal's business — kitty forwards Ctrl+C and
permits clipboard writes by default; macOS terminals consume ⌘C themselves, so `super+c`
never arrives.
"""
from textual.binding import Binding

from tests.test_ui import _open_flows, make_app, settle
from traffic_viewer.screens import BodyScreen, FlowDetailScreen


def _binding_keys(cls) -> dict[str, str]:
    """Every binding visible on a screen, action by key, across its whole MRO."""
    out: dict[str, str] = {}
    for base in reversed(cls.__mro__):
        for b in getattr(base, "BINDINGS", []) or []:
            if isinstance(b, Binding):
                out[b.key] = b.action
    return out


def test_detail_screens_inherit_textuals_copy_binding():
    """The binding comes from Textual; nothing of ours may shadow it."""
    for cls in (FlowDetailScreen, BodyScreen):
        keys = _binding_keys(cls)
        assert keys.get("ctrl+c,super+c") == "screen.copy_text", (
            f"{cls.__name__} lost the copy binding — check its BINDINGS for a ctrl+c entry"
        )


async def test_ctrl_c_copies_the_selection_on_a_flow_detail():
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        await pilot.press("enter")            # open the focused flow
        await settle(pilot)
        assert isinstance(app.screen, FlowDetailScreen)

        app.screen.text_select_all()
        await settle(pilot)
        selected = app.screen.get_selected_text()
        assert selected, "nothing was selectable on the detail pane"

        await pilot.press("ctrl+c")
        await settle(pilot)
        assert app.clipboard == selected


async def test_ctrl_c_without_a_selection_does_not_copy():
    """copy_text raises SkipAction with no selection, so the keypress falls through to the
    app's quit hint — which is why Ctrl+C keeps meaning "quit" the rest of the time."""
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, FlowDetailScreen)

        app.screen.clear_selection()
        await settle(pilot)
        await pilot.press("ctrl+c")
        await settle(pilot)
        assert not app.clipboard


async def test_the_flow_table_contributes_nothing_to_a_selection():
    """DataTable sets ALLOW_SELECT = False, so its rows are never part of a selection.

    Selecting on the flow list therefore copies the surrounding chrome — labels, the
    filter help, the footer — and none of the flows, which is worse than copying nothing
    because it looks like it worked. Copying rows needs explicit actions, not a binding.
    """
    app = make_app()
    async with app.run_test() as pilot:
        await _open_flows(pilot)
        app.screen.text_select_all()
        await settle(pilot)
        await pilot.press("ctrl+c")
        await settle(pilot)

        copied = app.clipboard
        assert copied, "the screen chrome should still be selectable"
        # The fixture's flows are /f1, /f2, /f3 — none of them can appear.
        for path in ("/f1", "/f2", "/f3"):
            assert path not in copied, (
                f"{path} came through, so DataTable.ALLOW_SELECT is no longer False — "
                f"the table's copy story has changed and this test should be revisited"
            )
