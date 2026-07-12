"""Viewer screens: session list, flow table, flow detail, the WebSocket/custom
message timeline, and side-by-side compare."""

from __future__ import annotations

import asyncio
import difflib
import os
import tempfile
from datetime import datetime

from textual import events, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, OptionList, Static,
    TabbedContent, TabPane,
)
from textual.widgets.option_list import Option
from rich.text import Text

from .filters import FILTER_HELP, compile_filter
from .render import (
    MARK_COLORS,
    SESSION_STATUS,
    body_for_editor,
    bytes_preview,
    curl,
    editor_command,
    editor_suffix,
    duration_cell,
    flags_cell,
    fmt_time,
    format_body,
    format_cookie_attrs,
    format_http2_fingerprint,
    is_text,
    raw_message,
    status_cell,
)


class NavDataTable(DataTable):
    """Row DataTable with list-friendly navigation. PageUp/PageDown (inherited) move the
    cursor a page; Home/End and Ctrl/Cmd+Up/Down jump to the first/last row. By default a
    row DataTable maps Home/End to horizontal scroll, which isn't useful for these lists.
    (Terminals that don't deliver Cmd still get the jump via Home/End or Ctrl+Up/Down.)

    Also implements follow mode for live lists: while `follow` is on, the cursor tracks
    each newly added row (tail -f style). Hosts toggle it and jump to the newest row via
    `set_follow`; updates to existing rows never scroll."""

    BINDINGS = [
        Binding("home", "scroll_top", "Top", show=False),
        Binding("end", "scroll_bottom", "Bottom", show=False),
        Binding("ctrl+up", "scroll_top", "Top", show=False),
        Binding("ctrl+down", "scroll_bottom", "Bottom", show=False),
        Binding("cmd+up", "scroll_top", "Top", show=False),
        Binding("cmd+down", "scroll_bottom", "Bottom", show=False),
        Binding("super+up", "scroll_top", "Top", show=False),
        Binding("super+down", "scroll_bottom", "Bottom", show=False),
    ]

    follow = False

    def add_row(self, *cells, **kwargs):
        key = super().add_row(*cells, **kwargs)
        if self.follow:
            self.move_cursor(row=self.row_count - 1)
        return key

    def set_follow(self, on: bool) -> None:
        self.follow = on
        if on and self.row_count:
            self.move_cursor(row=self.row_count - 1)


class TextPrompt(ModalScreen[str | None]):
    """Modal single-line text input; dismisses with the entered text, or None on Esc."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, label: str, value: str = "") -> None:
        super().__init__()
        self._label = label
        self._value = value

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt"):
            yield Label(self._label)
            yield Input(value=self._value, id="prompt-input")

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class SelectPrompt(ModalScreen[str | None]):
    """Modal pick-one list; dismisses with the chosen option id, or None on Esc."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, label: str, options: list[tuple[str, object]]) -> None:
        super().__init__()
        self._label = label
        self._options = options  # (id, renderable-label)

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt"):
            yield Label(self._label)
            yield OptionList(*[Option(lbl, id=val) for val, lbl in self._options])

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    """Modal yes/no confirmation; dismisses True when confirmed, False otherwise."""

    BINDINGS = [
        Binding("y", "confirm", "Yes"),
        Binding("n", "cancel", "No"),
        Binding("escape", "cancel", "No"),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt"):
            yield Label(self._message)
            with Horizontal(id="confirm-buttons"):
                yield Button("Yes (y)", id="yes", variant="error")
                yield Button("No (n)", id="no", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()  # default to the safe choice

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class QuitConfirmScreen(ConfirmScreen):
    """Quit confirmation where a second Ctrl+C also confirms (the app-level Ctrl+C binding
    doesn't reach through a modal, so the dialog handles the repeat press itself)."""

    BINDINGS = [Binding("ctrl+c", "confirm", "Quit", show=False)]


class SessionsScreen(Screen):
    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("n", "rename", "Rename"),
        Binding("g", "set_group", "Group"),
        Binding("e", "export", "Export"),
        Binding("i", "import_session", "Import"),
        Binding("c", "force_close", "Close"),
        Binding("d", "delete", "Delete"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        table = NavDataTable(id="sessions", cursor_type="row", zebra_stripes=True)
        table.add_columns("Group", "Session", "Label", "Status", "Flows", "pcap", "Created")
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.title = "TrafficDeck"
        self.sub_title = "sessions"
        self.query_one("#sessions", DataTable).focus()  # so nav keys work immediately
        self.load_sessions()

    def action_refresh(self) -> None:
        self.load_sessions()

    @work(exclusive=True)
    async def load_sessions(self) -> None:
        table = self.query_one("#sessions", DataTable)
        table.clear()
        try:
            sessions = await self.app.client.list_sessions()
        except Exception as exc:  # noqa: BLE001
            self.notify(f"list_sessions failed: {exc}", severity="error")
            return
        self._labels = {s.id: s.label for s in sessions}  # for the workspace tab title
        # Cluster by group (grouped first, alphabetical; ungrouped last). Stable sort keeps
        # the server's created-DESC order within each group and when nothing is grouped.
        sessions = sorted(sessions, key=lambda s: (s.group == "", s.group.lower()))
        prev_group = None
        for s in sessions:
            created = datetime.fromtimestamp(s.created_at_unix_ms / 1e3).strftime("%Y-%m-%d %H:%M")
            # Only label the first row of each group, so the column reads like a header.
            group_cell = (s.group or "—") if s.group != prev_group else ""
            prev_group = s.group
            table.add_row(
                group_cell,
                s.id[:8],
                s.label or "—",
                SESSION_STATUS.get(s.status, "?"),
                str(s.flow_count),
                f"{s.pcap_bytes/1_048_576:.1f}M",
                created,
                key=s.id,
            )
        if not sessions:
            self.notify("no sessions — import one with `gateway import`")

    def _selected_session(self) -> str | None:
        table = self.query_one("#sessions", DataTable)
        if table.row_count == 0:
            return None
        try:
            return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:  # noqa: BLE001
            return None

    def action_set_group(self) -> None:
        sid = self._selected_session()
        if sid is None:
            return

        async def _apply(name: str | None) -> None:
            if name is None:
                return
            try:
                await self.app.client.set_session_group(sid, name.strip())
            except Exception as exc:  # noqa: BLE001
                self.notify(f"set group failed: {exc}", severity="error")
                return
            self.load_sessions()

        self.app.push_screen(TextPrompt("Group (empty to clear):"), _apply)

    def action_rename(self) -> None:
        sid = self._selected_session()
        if sid is None:
            return
        current = getattr(self, "_labels", {}).get(sid, "")

        async def _apply(name: str | None) -> None:
            if name is None:
                return
            try:
                await self.app.client.set_session_label(sid, name.strip())
            except Exception as exc:  # noqa: BLE001
                self.notify(f"rename failed: {exc}", severity="error")
                return
            self.load_sessions()

        self.app.push_screen(TextPrompt("Rename session:", current), _apply)

    def action_force_close(self) -> None:
        """Finalize a session stuck open (a capture that died without CloseSession)."""
        sid = self._selected_session()
        if sid is None:
            return
        label = getattr(self, "_labels", {}).get(sid, "") or sid[:8]

        async def _confirm(ok: bool | None) -> None:
            if not ok:
                return
            self.notify(f"closing session {label} …")
            try:
                await self.app.client.force_close_session(sid)
            except Exception as exc:  # noqa: BLE001
                self.notify(f"force-close failed: {exc}", severity="error")
                return
            self.notify(f"closed session {label}")
            self.load_sessions()

        self.app.push_screen(
            ConfirmScreen(f"Force-close session {label}? Finalizes a stuck/interrupted capture."),
            _confirm,
        )

    def action_delete(self) -> None:
        sid = self._selected_session()
        if sid is None:
            return
        label = getattr(self, "_labels", {}).get(sid, "") or sid[:8]

        async def _confirm(ok: bool | None) -> None:
            if not ok:
                return
            try:
                await self.app.client.delete_session(sid)
            except Exception as exc:  # noqa: BLE001
                self.notify(f"delete failed: {exc}", severity="error")
                return
            self.notify(f"deleted session {label}")
            self.load_sessions()

        self.app.push_screen(
            ConfirmScreen(f"Delete session {label}? This erases its capture permanently."),
            _confirm,
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        sid = str(event.row_key.value)
        label = getattr(self, "_labels", {}).get(sid, "")
        self.app.push_screen(WorkspaceScreen(sid, label))

    def _focused_session_id(self) -> str | None:
        table = self.query_one("#sessions", DataTable)
        if table.cursor_coordinate is None or table.row_count == 0:
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    def action_export(self) -> None:
        """Export the selected session as a .tar.gz bundle (prompt for the destination)."""
        sid = self._selected_session()
        if sid is None:
            return

        async def _do(dest: str | None) -> None:
            if not dest:
                return
            dest_path = os.path.abspath(os.path.expanduser(dest.strip()))
            self.notify(f"exporting {sid[:8]} …")
            try:
                n = await self.app.client.export_session(sid, dest_path)
            except Exception as exc:  # noqa: BLE001
                self.notify(f"export failed: {exc}", severity="error")
                return
            self.notify(f"exported {n/1_048_576:.1f}M → {dest_path}")

        self.app.push_screen(TextPrompt("Export to:", os.path.abspath(f"{sid}.tar.gz")), _do)

    def action_import_session(self) -> None:
        """Import a .tar.gz session bundle (as produced by Export) under a fresh id."""

        async def _do(path: str | None) -> None:
            if not path:
                return
            self.notify("importing …")
            try:
                sess = await self.app.client.import_session(os.path.abspath(os.path.expanduser(path.strip())))
            except Exception as exc:  # noqa: BLE001
                self.notify(f"import failed: {exc}", severity="error")
                return
            self.notify(f"imported {sess.label or sess.id[:8]}")
            self.load_sessions()

        self.app.push_screen(TextPrompt("Import bundle (.tar.gz path):"), _do)


def _env_meta_columns() -> list[str]:
    """Metadata keys to show as flow-table columns by default, from
    TRAFFICDECK_META_COLUMNS (comma-separated). A source may also declare defaults
    per session (viewer.columns); the pane unions both."""
    raw = os.environ.get("TRAFFICDECK_META_COLUMNS", "")
    return [k.strip() for k in raw.split(",") if k.strip()]


# How wide a metadata value cell may get before it's truncated in the table.
_META_CELL_MAX = 24


class AnnotatableTable:
    """Shared annotation behavior for a record table — flows (SessionPane) or messages
    (WsMessagesScreen). The annotation store is keyed on record_id, so the same mark / tag /
    comment / favorite / group actions and bulk-selection work for both, given a few hooks
    the host supplies. Mixed into a Textual widget/screen (so self.app, self.notify, and
    @work are available).

    Host must provide: `session_id`, a `_selected: set[str]`, `_tags`/`_groups` lists, and
    implement `_focused_record_id`, `_record`, `_apply_record`, `_fetch_record`, and
    `_update_subtitle`."""

    # --- hooks the host implements -------------------------------------------
    def _focused_record_id(self) -> "str | None":
        raise NotImplementedError

    def _record(self, rid: str):
        """The cached record for rid, or None."""
        raise NotImplementedError

    def _apply_record(self, rec) -> None:
        """Store the record in the cache and (re-)render its row."""
        raise NotImplementedError

    async def _fetch_record(self, rid: str):
        """Fetch a fresh record from the server (raises if unavailable)."""
        raise NotImplementedError

    # --- shared behavior -----------------------------------------------------
    @work(exclusive=True, group="defs")
    async def load_defs(self) -> None:
        """Load tag/group definitions for the palette + name resolution."""
        try:
            self._tags = await self.app.client.list_tags()
            self._groups = await self.app.client.list_groups()
        except Exception as exc:  # noqa: BLE001
            self.notify(f"load annotations failed: {exc}", severity="warning")
            return
        self._tagnames = {t.id: t.name for t in self._tags}
        self._groupnames = {g.id: g.name for g in self._groups}

    def action_select(self) -> None:
        """Toggle the focused row's membership in the bulk-annotation selection."""
        rid = self._focused_record_id()
        if rid is None:
            return
        if rid in self._selected:
            self._selected.discard(rid)
        else:
            self._selected.add(rid)
        rec = self._record(rid)
        if rec is not None:
            self._apply_record(rec)  # re-render the flags cell
        self._update_subtitle()

    def action_clear_selection(self) -> None:
        """Reset the whole bulk-annotation selection in one keystroke."""
        if not self._selected:
            return
        cleared, self._selected = self._selected, set()
        for rid in cleared:
            rec = self._record(rid)
            if rec is not None:
                self._apply_record(rec)  # re-render the (now unselected) flags cell
        self._update_subtitle()

    def _targets(self) -> list[str]:
        """Records an annotation applies to: the selection if any, else the focus."""
        if self._selected:
            return list(self._selected)
        rid = self._focused_record_id()
        return [rid] if rid else []

    async def _refresh(self, ids: list[str]) -> None:
        """Re-fetch annotated records so their row/cache reflect the change."""
        for rid in ids:
            try:
                rec = await self._fetch_record(rid)
            except Exception:  # noqa: BLE001 (live/unpersisted record — best effort)
                continue
            self._apply_record(rec)

    @work(exclusive=True, group="annotate")
    async def action_mark(self) -> None:
        targets = self._targets()
        if not targets:
            return
        opts = [(c, Text("● " + c, style=c)) for c in MARK_COLORS] + [("__clear__", "✕ clear")]
        choice = await self.app.push_screen_wait(SelectPrompt("Color mark", opts))
        if choice is None:
            return
        try:
            if choice == "__clear__":
                await self.app.client.clear_mark(self.session_id, targets)
            else:
                await self.app.client.set_mark(self.session_id, targets, choice)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"mark failed: {exc}", severity="error")
            return
        await self._refresh(targets)

    @work(exclusive=True, group="annotate")
    async def action_tag(self) -> None:
        targets = self._targets()
        if not targets:
            return
        opts = [(t.id, Text(("★ " if t.is_favorite else "") + t.name, style=t.color or "white"))
                for t in self._tags]
        opts.append(("__new__", "＋ new tag…"))
        choice = await self.app.push_screen_wait(SelectPrompt("Toggle tag", opts))
        if choice is None:
            return
        if choice == "__new__":
            name = await self.app.push_screen_wait(TextPrompt("New tag name"))
            if not name:
                return
            color = await self.app.push_screen_wait(
                SelectPrompt("Tag color", [(c, Text("● " + c, style=c)) for c in MARK_COLORS]))
            try:
                tag = await self.app.client.create_tag(name, color or "")
                await self.app.client.set_tags(self.session_id, targets, add=[tag.id])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"tag failed: {exc}", severity="error")
                return
            self.load_defs()
        else:
            present = all(choice in (self._record(r).tag_ids if self._record(r) else []) for r in targets)
            try:
                if present:
                    await self.app.client.set_tags(self.session_id, targets, remove=[choice])
                else:
                    await self.app.client.set_tags(self.session_id, targets, add=[choice])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"tag failed: {exc}", severity="error")
                return
        await self._refresh(targets)

    @work(exclusive=True, group="annotate")
    async def action_favorite(self) -> None:
        targets = self._targets()
        if not targets:
            return
        try:
            await self.app.client.toggle_favorite(self.session_id, targets)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"favorite failed: {exc}", severity="error")
            return
        await self._refresh(targets)

    @work(exclusive=True, group="annotate")
    async def action_comment(self) -> None:
        rid = self._focused_record_id()  # comments target a single record
        if rid is None:
            return
        rec = self._record(rid)
        existing = rec.comments[0] if (rec and rec.comments) else None
        body = await self.app.push_screen_wait(
            TextPrompt("Comment (empty to delete)", existing.body if existing else ""))
        if body is None:
            return
        try:
            if existing and body == "":
                await self.app.client.delete_comment(self.session_id, existing.id)
            elif existing:
                await self.app.client.edit_comment(self.session_id, existing.id, body)
            elif body:
                await self.app.client.add_comment(self.session_id, rid, body)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"comment failed: {exc}", severity="error")
            return
        await self._refresh([rid])

    @work(exclusive=True, group="annotate")
    async def action_group(self) -> None:
        targets = self._targets()
        if not targets:
            return
        opts = [(g.id, Text(g.name, style=g.color or "white")) for g in self._groups]
        opts.append(("__new__", "＋ new group…"))
        choice = await self.app.push_screen_wait(SelectPrompt("Toggle group", opts))
        if choice is None:
            return
        if choice == "__new__":
            name = await self.app.push_screen_wait(TextPrompt("New group name"))
            if not name:
                return
            color = await self.app.push_screen_wait(
                SelectPrompt("Group color", [(c, Text("● " + c, style=c)) for c in MARK_COLORS]))
            try:
                grp = await self.app.client.create_group(name, color or "")
                await self.app.client.set_groups(self.session_id, targets, add=[grp.id])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"group failed: {exc}", severity="error")
                return
            self.load_defs()
        else:
            present = all(choice in (self._record(r).group_ids if self._record(r) else []) for r in targets)
            try:
                if present:
                    await self.app.client.set_groups(self.session_id, targets, remove=[choice])
                else:
                    await self.app.client.set_groups(self.session_id, targets, add=[choice])
            except Exception as exc:  # noqa: BLE001
                self.notify(f"group failed: {exc}", severity="error")
                return
        await self._refresh(targets)


class SessionPane(AnnotatableTable, Vertical):
    """One session's live flow table + filtering + annotations. Hosted as a tab in the
    WorkspaceScreen so several sessions can be open and compared side by side. (Was a
    full Screen; the shared Header/Footer now live on the workspace.)"""

    BINDINGS = [
        Binding("f", "filter", "Filter"),
        Binding("c", "compare", "Compare A/B"),
        Binding("space", "select", "Select"),
        Binding("D", "clear_selection", "Deselect"),
        Binding("m", "mark", "Mark"),
        Binding("t", "tag", "Tag"),
        Binding("F", "favorite", "Favorite"),
        Binding("n", "comment", "Comment"),
        Binding("g", "group", "Group"),
        Binding("C", "columns", "Columns"),
        Binding("M", "messages", "WS msgs"),
        Binding("l", "follow", "Follow new"),
    ]

    def __init__(self, session_id: str, label: str = "") -> None:
        super().__init__()
        self.session_id = session_id
        self.label = label
        self.flows: dict[str, object] = {}  # flow id -> cached Flow (for live detail)
        self._rows: set[str] = set()
        self._cols: list = []                   # base (fixed) column keys
        self._meta_cols: list[str] = _env_meta_columns()  # metadata keys shown as columns
        self._meta_col_keys: dict[str, object] = {}       # metadata key -> DataTable ColumnKey
        self._predicate = None  # active filter
        self._selected: set[str] = set()       # multi-selection for bulk annotation
        self._tags: list = []                  # tag defs (catalog)
        self._groups: list = []                # group defs (catalog)
        self._tagnames: dict[str, str] = {}
        self._groupnames: dict[str, str] = {}
        self._live = True                       # session open → tick in-flight stopwatches
        self._dur_timer = None

    def compose(self) -> ComposeResult:
        yield Label("", id="pane-status")
        yield Input(id="filter", placeholder="filter: ~m GET  ~d example.com  ~fav  ~tag auth  ~mark red  (f focus, Enter apply)")
        table = NavDataTable(id="flows", cursor_type="row", zebra_stripes=True)
        self._cols = table.add_columns("", "Time", "Method", "Status", "Dur", "Proto", "Authority", "Path")
        self._dur_col = self._cols[4]
        for key in self._meta_cols:  # source metadata shown as extra columns
            self._meta_col_keys[key] = table.add_column(key, key=f"meta:{key}")
        yield table
        # Filter cheat sheet, docked at the bottom; only shown while the filter is focused.
        yield Static(FILTER_HELP, id="filter-help")

    def _ordered_cols(self) -> list:
        """All column keys in display order: the fixed base columns then metadata columns."""
        return [*self._cols, *(self._meta_col_keys[k] for k in self._meta_cols)]

    def _meta_value(self, f, key: str) -> str:
        return (f.metadata.get(key, "") or "")[:_META_CELL_MAX]

    def _add_meta_column(self, key: str) -> None:
        if key in self._meta_cols:
            return
        table = self.query_one("#flows", DataTable)
        self._meta_cols.append(key)
        self._meta_col_keys[key] = table.add_column(key, default="", key=f"meta:{key}")
        for fid in self._rows:  # backfill the new cell for rows already on screen
            f = self.flows.get(fid)
            if f is not None:
                table.update_cell(fid, self._meta_col_keys[key], self._meta_value(f, key))

    def _remove_meta_column(self, key: str) -> None:
        if key not in self._meta_cols:
            return
        table = self.query_one("#flows", DataTable)
        table.remove_column(self._meta_col_keys.pop(key))
        self._meta_cols.remove(key)

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        # Reveal the filter help only while the filter input is being edited.
        if event.widget.id == "filter":
            self.query_one("#filter-help", Static).display = True

    def on_descendant_blur(self, event: events.DescendantBlur) -> None:
        if event.widget.id == "filter":
            self.query_one("#filter-help", Static).display = False

    def on_mount(self) -> None:
        self._update_subtitle()
        self.query_one("#flows", DataTable).focus()
        self.load_defs()
        self.load_flows()
        # Tick in-flight requests' duration cells so they read as a live stopwatch.
        self._dur_timer = self.set_interval(0.5, self._tick_durations)

    def _tick_durations(self) -> None:
        """Refresh the Dur cell of each still-pending request (no response, no error) so
        the elapsed time updates live; completed flows are frozen at their final duration.
        Once the session is closed nothing is pending anymore, so this stops."""
        if not self._live:
            return
        table = self.query_one("#flows", DataTable)
        for fid in list(self._rows):
            f = self.flows.get(fid)
            if f is None or f.status or f.error or f.duration_micros:
                continue
            try:
                table.update_cell(fid, self._dur_col, duration_cell(f, self._live))
            except Exception:  # noqa: BLE001 — row removed between snapshot and update
                pass

    def _finalize_live(self) -> None:
        """The session closed: stop the stopwatch. Clear the ⏱ from any flow still pending
        (its request never got a response) so it doesn't tick forever, and stop the timer."""
        if not self._live:
            return
        self._live = False
        if self._dur_timer is not None:
            self._dur_timer.stop()
        try:
            table = self.query_one("#flows", DataTable)
        except Exception:  # noqa: BLE001 — screen torn down; nothing to refresh
            return
        for fid in list(self._rows):
            f = self.flows.get(fid)
            if f is None or f.status or f.error or f.duration_micros:
                continue
            try:
                table.update_cell(fid, self._dur_col, duration_cell(f, live=False))
            except Exception:  # noqa: BLE001
                pass

    def _update_subtitle(self) -> None:
        base = f"{len(self.flows)} flows"
        if self._selected:
            base += f" · {len(self._selected)} selected"
        if self._predicate is not None:
            base += f" · {len(self._rows)}/{len(self.flows)} shown"
        if self.query_one("#flows", NavDataTable).follow:
            base += " · ⇣ follow"
        self.query_one("#pane-status", Label).update(base)

    def action_follow(self) -> None:
        """Toggle follow mode: the cursor tracks each newly arriving flow."""
        table = self.query_one("#flows", NavDataTable)
        table.set_follow(not table.follow)
        self._update_subtitle()

    def _matches(self, f) -> bool:
        return self._predicate is None or self._predicate(f)

    def action_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        try:
            self._predicate = compile_filter(event.value, self._tagnames, self._groupnames)
        except Exception as exc:  # noqa: BLE001 (bad regex / syntax)
            self.notify(f"bad filter: {exc}", severity="error")
            return
        self._apply_filter()
        self.query_one("#flows", DataTable).focus()

    def _apply_filter(self) -> None:
        table = self.query_one("#flows", DataTable)
        table.clear()
        self._rows.clear()
        for f in self.flows.values():
            if self._matches(f):
                table.add_row(*self._cells(f), key=f.id)
                self._rows.add(f.id)
        self._update_subtitle()

    def on_key(self, event) -> None:
        # Escape while editing the filter returns to the table without going back.
        if event.key == "escape" and self.query_one("#filter", Input).has_focus:
            self.query_one("#flows", DataTable).focus()
            event.stop()

    def _cells(self, f) -> tuple:
        return (
            flags_cell(f, f.id in self._selected),
            fmt_time(f.ts_unix_micros),
            f.method or "",
            status_cell(f),
            duration_cell(f, self._live),
            f.protocol or "",
            f.authority or "",
            (f.path or "")[:80],
            *(self._meta_value(f, k) for k in self._meta_cols),
        )

    def _upsert(self, f) -> None:
        table = self.query_one("#flows", DataTable)
        self.flows[f.id] = f
        if not self._matches(f):
            if f.id in self._rows:
                table.remove_row(f.id)
                self._rows.discard(f.id)
                self._update_subtitle()
            return
        cells = self._cells(f)
        if f.id in self._rows:
            for col, val in zip(self._ordered_cols(), cells):
                table.update_cell(f.id, col, val)
        else:
            table.add_row(*cells, key=f.id)
            self._rows.add(f.id)
            self._update_subtitle()

    @work(exclusive=True)
    async def load_flows(self) -> None:
        self.query_one("#flows", DataTable).clear()
        self.flows.clear()
        self._rows.clear()
        try:
            async for ev in self.app.client.stream_flows(self.session_id, follow=True):
                kind = ev.WhichOneof("event")
                if kind == "flow_added":
                    self._upsert(ev.flow_added)
                elif kind == "flow_updated":
                    self._upsert(ev.flow_updated)
                elif kind == "session_event":
                    self.notify("session closed — live capture ended")
                    self._finalize_live()
        except Exception as exc:  # noqa: BLE001
            self.notify(f"stream_flows failed: {exc}", severity="error")
        finally:
            # The stream ended: either the session closed, or it was already closed when we
            # opened it (backfill only). Either way nothing is in flight — stop ticking.
            self._finalize_live()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        fid = str(event.row_key.value)
        self.app.push_screen(
            FlowDetailScreen(self.session_id, fid, self.flows.get(fid),
                             self._tagnames, self._groupnames))

    def _focused_flow_id(self) -> str | None:
        table = self.query_one("#flows", DataTable)
        if table.cursor_coordinate is None or table.row_count == 0:
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    @work(exclusive=True)
    async def action_columns(self) -> None:
        """Toggle a source-metadata key as a table column. Keys are discovered from the
        loaded flows (plus any already shown); ✓ marks columns currently displayed."""
        keys = sorted({k for f in self.flows.values() for k in f.metadata.keys()})
        for k in self._meta_cols:  # keep a shown column listed even if no loaded flow has it
            if k not in keys:
                keys.append(k)
        if not keys:
            self.notify("no source metadata on these flows", severity="warning")
            return
        opts = [(k, Text(("✓ " if k in self._meta_cols else "  ") + k)) for k in keys]
        choice = await self.app.push_screen_wait(SelectPrompt("Toggle column", opts))
        if choice is None:
            return
        if choice in self._meta_cols:
            self._remove_meta_column(choice)
        else:
            self._add_meta_column(choice)

    def action_compare(self) -> None:
        fid = self._focused_flow_id()
        if fid is None:
            return
        sel = (self.session_id, fid)
        if self.app.compare_a is None:
            self.app.compare_a = sel
            self.notify("marked A — focus a flow in another session and press c")
        elif self.app.compare_a == sel:
            self.app.compare_a = None
            self.notify("cleared compare selection")
        else:
            a = self.app.compare_a
            self.app.compare_a = None
            self.app.push_screen(CompareScreen(a, sel))

    def action_messages(self) -> None:
        fid = self._focused_flow_id()
        if fid is None:
            return
        f = self.flows.get(fid)
        if not (f and f.websocket):
            self.notify("not a WebSocket flow", severity="warning")
            return
        self.app.push_screen(WsMessagesScreen(self.session_id, fid))

    # --- annotation hooks (see AnnotatableTable) -------------------
    def _focused_record_id(self):
        return self._focused_flow_id()

    def _record(self, rid):
        return self.flows.get(rid)

    def _apply_record(self, rec) -> None:
        self._upsert(rec)

    async def _fetch_record(self, rid):
        return await self.app.client.get_flow(self.session_id, rid)

class WorkspaceScreen(Screen):
    """Tabbed workspace: one SessionPane per open session, so several sessions can be
    viewed and compared side by side. Compare A/B (c) works across tabs via app.compare_a."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Sessions", show=False),
        Binding("o", "open_session", "Open session"),
        Binding("w", "close_tab", "Close tab"),
        Binding("ctrl+w", "close_tab", "Close tab", show=False),
        Binding("]", "next_tab", "Next tab"),
        Binding("[", "prev_tab", "Prev tab"),
        Binding("ctrl+pagedown", "next_tab", "Next tab", show=False),
        Binding("ctrl+pageup", "prev_tab", "Prev tab", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, label: str = "") -> None:
        super().__init__()
        self._first = (session_id, label)

    def compose(self) -> ComposeResult:
        yield Header()
        yield TabbedContent(id="tabs")
        yield Footer()

    async def on_mount(self) -> None:
        self.title = "TrafficDeck"
        await self.open_session(*self._first)

    @staticmethod
    def _tab_id(session_id: str) -> str:
        return "t" + session_id.replace("-", "")[:16]

    async def open_session(self, session_id: str, label: str = "") -> None:
        """Open the session in a tab, or focus its existing tab."""
        tabs = self.query_one(TabbedContent)
        tid = self._tab_id(session_id)
        if any(p.id == tid for p in tabs.query(TabPane)):
            tabs.active = tid
        else:
            await tabs.add_pane(TabPane(label or session_id[:8], SessionPane(session_id, label), id=tid))
            tabs.active = tid
        self._sync_subtitle()
        self.call_after_refresh(self._focus_active)

    def _active_pane(self) -> "SessionPane | None":
        pane = self.query_one(TabbedContent).active_pane
        return pane.query_one(SessionPane) if pane else None

    def _focus_active(self) -> None:
        pane = self._active_pane()
        if pane is not None:
            pane.query_one("#flows", DataTable).focus()

    def _sync_subtitle(self) -> None:
        pane = self._active_pane()
        self.sub_title = (pane.label or pane.session_id[:8]) if pane else "workspace"

    def on_tabbed_content_tab_activated(self, _event) -> None:
        self._sync_subtitle()
        self.call_after_refresh(self._focus_active)

    def _cycle(self, step: int) -> None:
        tabs = self.query_one(TabbedContent)
        ids = [p.id for p in tabs.query(TabPane)]
        if not ids:
            return
        i = ids.index(tabs.active) if tabs.active in ids else 0
        tabs.active = ids[(i + step) % len(ids)]
        self._sync_subtitle()
        self.call_after_refresh(self._focus_active)

    def action_next_tab(self) -> None:
        self._cycle(1)

    def action_prev_tab(self) -> None:
        self._cycle(-1)

    async def action_close_tab(self) -> None:
        tabs = self.query_one(TabbedContent)
        if not tabs.active:
            return
        await tabs.remove_pane(tabs.active)
        if not tabs.query(TabPane):
            self.app.pop_screen()  # closed the last tab — back to the sessions list
        else:
            self._sync_subtitle()
            self.call_after_refresh(self._focus_active)

    @work
    async def action_open_session(self) -> None:
        """Pick another session to open as a tab (the sessions list from the workspace)."""
        try:
            sessions = await self.app.client.list_sessions()
        except Exception as exc:  # noqa: BLE001
            self.notify(f"list_sessions failed: {exc}", severity="error")
            return
        if not sessions:
            self.notify("no sessions")
            return
        labels = {s.id: s.label for s in sessions}
        opts = [(s.id, f"{s.label or '—'}  ({s.id[:8]}, {s.flow_count} flows)") for s in sessions]
        choice = await self.app.push_screen_wait(SelectPrompt("Open session", opts))
        if choice:
            await self.open_session(choice, labels.get(choice, ""))


class FlowDetailScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=False),
        Binding("b", "view_request", "View req body"),
        Binding("B", "view_response", "View resp body"),
        Binding("r", "save_request", "Save req body"),
        Binding("s", "save_response", "Save resp body"),
        Binding("x", "export_curl", "Export curl"),
        Binding("w", "export_raw", "Export raw"),
        Binding("H", "export_client_hellos", "Export CHs"),
        Binding("M", "messages", "WS msgs"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, flow_id: str, cached=None,
                 tagnames: dict | None = None, groupnames: dict | None = None) -> None:
        super().__init__()
        self.session_id = session_id
        self.flow_id = flow_id
        self.cached = cached  # full Flow from a live event, used if not yet persisted
        self._flow = None     # the loaded Flow (for export)
        self._tagnames = tagnames or {}
        self._groupnames = groupnames or {}

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="detail"):
            yield Static("loading…", id="body")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "TrafficDeck"
        self.sub_title = "flow detail"
        self.load_flow()

    @work(exclusive=True)
    async def load_flow(self) -> None:
        # Persisted flows come from GetFlow (full headers+bodies); live flows aren't
        # persisted yet, so fall back to the cached flow from the live stream.
        f = None
        try:
            f = await self.app.client.get_flow(self.session_id, self.flow_id)
        except Exception:  # noqa: BLE001
            f = self.cached
        if f is None:
            self.query_one("#body", Static).update("[red]flow unavailable[/red]")
            return
        self._flow = f
        self.query_one("#body", Static).update(self._format_flow(f))

    def action_messages(self) -> None:
        if not (self._flow and self._flow.websocket):
            self.notify("not a WebSocket flow", severity="warning")
            return
        self.app.push_screen(WsMessagesScreen(self.session_id, self.flow_id))

    async def _full_body(self, response: bool) -> bytes:
        try:
            return await self.app.client.get_body(self.session_id, self.flow_id, response)
        except Exception:  # noqa: BLE001 (no body)
            return b""

    @work(exclusive=True)
    async def action_export_curl(self) -> None:
        if self._flow is None:
            return
        dest = await self.app.push_screen_wait(
            TextPrompt("Export curl to:", os.path.abspath(f"{self.flow_id[:8]}.curl")))
        if not dest:
            return
        path = os.path.abspath(os.path.expanduser(dest.strip()))
        # The bodyfile (if any) lives next to the .curl and is referenced by the
        # command, so derive the id-prefix from the chosen destination.
        prefix = path[:-len(".curl")] if path.endswith(".curl") else path
        body = await self._full_body(response=False)
        cmd, bodyfile = curl(self._flow, prefix, body)
        try:
            if bodyfile:
                with open(bodyfile, "wb") as fp:
                    fp.write(body)
            with open(path, "w") as fp:
                fp.write(cmd + "\n")
        except OSError as exc:
            self.notify(f"export failed: {exc}", severity="error")
            return
        self.notify(f"wrote {path}" + (f" (+ {bodyfile})" if bodyfile else ""))

    @work(exclusive=True)
    async def action_export_raw(self) -> None:
        if self._flow is None:
            return
        dest = await self.app.push_screen_wait(
            TextPrompt("Export raw to (prefix):", os.path.abspath(self.flow_id[:8])))
        if not dest:
            return
        prefix = os.path.abspath(os.path.expanduser(dest.strip()))
        req = raw_message(self._flow, await self._full_body(response=False), response=False)
        resp = raw_message(self._flow, await self._full_body(response=True), response=True)
        rp = f"{prefix}-request.http"
        sp = f"{prefix}-response.http"
        try:
            with open(rp, "wb") as fp:
                fp.write(req)
            with open(sp, "wb") as fp:
                fp.write(resp)
        except OSError as exc:
            self.notify(f"export failed: {exc}", severity="error")
            return
        self.notify(f"wrote {rp} and {sp}")

    @work(exclusive=True)
    async def action_export_client_hellos(self) -> None:
        """Export the raw TLS ClientHello(s) as hex text, one per line (in wire order).
        There's more than one line only when the server sent a HelloRetryRequest."""
        if self._flow is None:
            return
        hellos = list(self._flow.client_hellos)
        if not hellos:
            self.notify("no raw ClientHello for this flow (plaintext / pushed source)",
                        severity="warning")
            return
        dest = await self.app.push_screen_wait(
            TextPrompt("Export ClientHello(s) to:", os.path.abspath(f"{self.flow_id[:8]}.clienthello.hex")))
        if not dest:
            return
        path = os.path.abspath(os.path.expanduser(dest.strip()))
        text = "\n".join(ch.hex() for ch in hellos) + "\n"
        try:
            with open(path, "w") as fp:
                fp.write(text)
        except OSError as exc:
            self.notify(f"export failed: {exc}", severity="error")
            return
        n = len(hellos)
        self.notify(f"wrote {n} ClientHello{'' if n == 1 else 's'} → {path}")

    def action_view_request(self) -> None:
        self._view_body(response=False)

    def action_view_response(self) -> None:
        self._view_body(response=True)

    def _view_body(self, response: bool) -> None:
        """Open the full, formatted+highlighted body in a dedicated viewer (which
        falls back to the system editor for bodies too large to show in the TUI)."""
        if self._flow is None:
            return
        label = "response" if response else "request"
        body = self._flow.response_body if response else self._flow.request_body
        if body is None or body.size == 0:
            self.notify(f"no {label} body", severity="warning")
            return
        self.app.push_screen(BodyScreen(
            self.session_id, self.flow_id, body.content_type, response, self.flow_id[:8]))

    @work(exclusive=True)
    async def action_save_request(self) -> None:
        await self._save_body(response=False, label="request")

    @work(exclusive=True)
    async def action_save_response(self) -> None:
        await self._save_body(response=True, label="response")

    async def _save_body(self, response: bool, label: str) -> None:
        try:
            data = await self.app.client.get_body(self.session_id, self.flow_id, response)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"no {label} body to save ({exc})", severity="warning")
            return
        path = os.path.abspath(f"{self.flow_id[:8]}-{label}.bin")
        with open(path, "wb") as fp:
            fp.write(data)
        self.notify(f"saved {len(data)} bytes → {path}")

    # Cap body rendering so a large body doesn't choke the TUI.
    _BODY_RENDER_LIMIT = 20000

    def _format_flow(self, f) -> Content:
        # Build a Textual Content with $-substitution for all flow-derived text:
        # values are inserted literally, never reparsed as markup (a stray '[' / byte
        # sequence in a header or body must not raise MarkupError).
        cls = type(self)
        lines: list[Content] = []
        url = f"{f.scheme or 'https'}://{f.authority}{f.path}"
        if f.query:
            url += f"?{f.query}"
        lines.append(Content.from_markup("[b]$v[/b]", v=f.method + " " + url))
        lines.append(Content.from_markup(
            "[dim]$proto  status=$status  tls=$tls  $src → $dst[/dim]",
            proto=f.protocol, status=str(f.status),
            tls="yes" if f.tls_decrypted else "no", src=f.src_addr, dst=f.dst_addr))
        if f.proxy.addr:
            creds = f"  {f.proxy.username}:{f.proxy.password}" if f.proxy.username else ""
            lines.append(Content.from_markup(
                "[yellow]⇄ via $type proxy $addr[/yellow]$creds",
                type=f.proxy.type, addr=f.proxy.addr, creds=creds))
        # Explain what went wrong, prominently: a recorded failure reason (no response),
        # a bare no-response, or a non-2xx status.
        if f.error:
            lines.append(Content.from_markup("[b red]✗ failed:[/b red] $e", e=f.error))
        elif f.status == 0:
            lines.append(Content.from_markup("[yellow]⏳ no response captured[/yellow]"))
        elif f.status >= 400:
            lines.append(Content.from_markup("[b red]⚠ HTTP $s[/b red]", s=str(f.status)))
        if f.redirect_location:
            lines.append(Content.from_markup("[blue]↪ redirects to:[/blue] $v", v=f.redirect_location))
        if f.redirected_from_id:
            lines.append(Content.from_markup("[blue]↩ redirected from flow[/blue] $v",
                                             v=f.redirected_from_id[:8]))
        for k, v in f.metadata.items():
            lines.append(Content.from_markup(
                "[magenta]◆ $k:[/magenta] $v", k=k, v=v))
        self._append_annotations(lines, f)
        if f.ja3 or f.ja4:
            lines.append(Content(""))
            lines.append(Content.from_markup("[b u]TLS ClientHello[/b u]"))
            if f.ja4:
                lines.append(Content.from_markup("  [cyan]JA4:[/cyan] $v", v=f.ja4))
            if f.ja3:
                lines.append(Content.from_markup("  [cyan]JA3:[/cyan] $v", v=f.ja3))
            if f.tls_client_hello:
                lines.append(Content.from_markup("  [dim]$v[/dim]", v=f.tls_client_hello))
            if f.client_hellos:
                n = len(f.client_hellos)
                hrr = "  [yellow](HelloRetryRequest)[/yellow]" if f.tls_hrr else ""
                lines.append(Content.from_markup(
                    "  [cyan]Raw:[/cyan] $n ClientHello$s captured — press [b]H[/b] to export$hrr",
                    n=str(n), s="" if n == 1 else "s", hrr=hrr))
            elif f.tls_hrr:
                lines.append(Content.from_markup("  [yellow](HelloRetryRequest seen)[/yellow]"))
        if f.http2_fingerprint:
            lines.append(Content(""))
            lines.append(Content.from_markup("[b u]HTTP/2 fingerprint[/b u]"))
            lines.append(Content.from_markup("  [dim]$fp[/dim]", fp=f.http2_fingerprint))
            for line in format_http2_fingerprint(f.http2_fingerprint):
                lines.append(Content.from_markup("  [cyan]$l[/cyan]", l=line))
        lines.append(Content(""))
        lines.append(Content.from_markup("[b u]Request headers[/b u]"))
        for h in f.request_headers:
            lines.append(Content.from_markup("  [cyan]$n[/cyan]: $val", n=h.name, val=h.value))
        cls._append_body(lines, "Request body", f.request_body, "r", "b")
        lines.append(Content(""))
        lines.append(Content.from_markup("[b u]Response headers[/b u]"))
        for h in f.response_headers:
            lines.append(Content.from_markup("  [green]$n[/green]: $val", n=h.name, val=h.value))
        cls._append_body(lines, "Response body", f.response_body, "s", "B")
        if f.request_cookies or f.response_cookies:
            lines.append(Content(""))
            lines.append(Content.from_markup("[b u]Cookies[/b u]"))
            for c in f.request_cookies:
                lines.append(Content.from_markup("  [dim]→[/dim] [cyan]$n[/cyan]=$v", n=c.name, v=c.value))
            for c in f.response_cookies:
                lines.append(Content.from_markup(
                    "  [dim]←[/dim] [green]$n[/green]=$v  [dim]$a[/dim]",
                    n=c.name, v=c.value, a=format_cookie_attrs(c)))
        return Content("\n").join(lines)

    def _append_annotations(self, lines: list[Content], f) -> None:
        """Render the record's annotations: mark, favorite, tags, groups,
        comments. Names resolve via the maps passed from the flow list."""
        bits: list[Content] = []
        if f.favorite:
            bits.append(Content.from_markup("[yellow]★ favorite[/yellow]"))
        if f.mark_color:
            color = f.mark_color if f.mark_color in MARK_COLORS else "white"
            bits.append(Content.from_markup(f"[{color}]● $c[/{color}]", c=f.mark_color))
        if f.tag_ids:
            names = ", ".join(self._tagnames.get(t, t) for t in f.tag_ids)
            bits.append(Content.from_markup("[cyan]tags:[/cyan] $names", names=names))
        if f.group_ids:
            names = ", ".join(self._groupnames.get(g, g) for g in f.group_ids)
            bits.append(Content.from_markup("[blue]groups:[/blue] $names", names=names))
        if bits:
            lines.append(Content.from_markup("[dim]│[/dim] ").append(Content("   ").join(bits)))
        for c in f.comments:
            lines.append(Content.from_markup("  [dim]💬[/dim] $body", body=c.body))

    @classmethod
    def _append_body(cls, lines: list[Content], title: str, body, save_key: str,
                     view_key: str) -> None:
        if body is None or body.size == 0:
            return
        meta = f"{body.content_type or '?'} · {body.size} bytes"
        lines.append(Content(""))
        lines.append(Content.from_markup(
            "[b u]$title[/b u] [dim]$meta · press $vkey to view · $key to save[/dim]",
            title=title, meta=meta, key=save_key, vkey=view_key))
        if body.WhichOneof("content") != "inline":
            lines.append(Content.from_markup(
                "  [dim]large body — press $vkey to view (opens your editor) · "
                "$key to save the full $size bytes[/dim]",
                key=save_key, vkey=view_key, size=str(body.size)))
            return
        data = body.inline
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            lines.append(Content.from_markup(
                "  [dim]$txt[/dim]", txt=f"[binary {len(data)} bytes — press {save_key} to save]"))
            return
        lines.append(format_body(body.content_type, data, cls._BODY_RENDER_LIMIT))


class _PayloadView(Screen):
    """Shared full-payload viewer for HTTP request/response bodies and WebSocket
    frames. Text under `_VIEW_LIMIT` is formatted + syntax-highlighted in place
    (JSON reindented, form bodies as key/value lines); larger text is written to a
    temp file and opened in the system editor ($VISUAL/$EDITOR, else xdg-open/open)
    — automatically on open, and again on `o`. Binary is hex-dumped, or for large
    payloads left for `s` to save. Subclasses supply the bytes (`_fetch`), the
    content-type, and naming (`_what` / `_subtitle` / `_file_stem`)."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=False),
        Binding("o", "open_editor", "Open in editor"),
        Binding("s", "save", "Save"),
        Binding("q", "quit", "Quit"),
    ]

    # Above this many decoded bytes we don't render in the TUI; hand off to an editor.
    _VIEW_LIMIT = 256_000

    _content_type: str = ""

    def __init__(self) -> None:
        super().__init__()
        self._data = b""

    # --- subclass hooks -------------------------------------------------------
    async def _fetch(self) -> bytes:
        raise NotImplementedError

    @property
    def _what(self) -> str:  # noun used in notifications ("request body", "payload")
        return "body"

    @property
    def _subtitle(self) -> str:
        return self._what

    @property
    def _file_stem(self) -> str:  # base name for temp + saved files
        return "payload"

    # --- shared behaviour -----------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="payload"):
            yield Static("loading…", id="pbody")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "TrafficDeck"
        self.sub_title = self._subtitle
        self.load()

    @work(exclusive=True)
    async def load(self) -> None:
        self._data = await self._fetch()
        body = self.query_one("#pbody", Static)
        if not self._data:
            body.update(Content.from_markup("[dim]empty $what[/dim]", what=self._what))
            return
        n = len(self._data)
        if n > self._VIEW_LIMIT:
            if is_text(self._data):
                body.update(Content.from_markup(
                    "[dim]large $what — $n bytes — opening in your editor…\n"
                    "press o to reopen · s to save[/dim]", what=self._what, n=str(n)))
                self._open_external()
            else:
                body.update(Content.from_markup(
                    "[dim]large binary $what — $n bytes — press s to save[/dim]",
                    what=self._what, n=str(n)))
            return
        body.update(format_body(self._content_type, self._data, self._VIEW_LIMIT))

    def action_open_editor(self) -> None:
        self._open_external()

    @work(exclusive=True, group="editor")
    async def _open_external(self) -> None:
        if not self._data:
            self.notify(f"empty {self._what}", severity="warning")
            return
        content = body_for_editor(self._content_type, self._data)
        suffix = editor_suffix(self._content_type, self._data)
        fd, path = tempfile.mkstemp(prefix=f"trafficdeck-{self._file_stem}-", suffix=suffix)
        with os.fdopen(fd, "wb") as fp:
            fp.write(content)
        cmd, terminal = editor_command(path)
        try:
            if terminal:
                # Terminal editor shares this terminal: suspend the TUI while it runs.
                with self.app.suspend():
                    proc = await asyncio.create_subprocess_exec(*cmd)
                    await proc.wait()
            else:
                # GUI opener launches a separate program — don't suspend, don't wait.
                await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        except OSError as exc:
            self.notify(f"could not open editor ({cmd[0]}): {exc}", severity="error")
            return
        self.notify(f"opened {self._what} → {path}")

    @work(exclusive=True)
    async def action_save(self) -> None:
        path = os.path.abspath(f"{self._file_stem}.bin")
        with open(path, "wb") as fp:
            fp.write(self._data)
        self.notify(f"saved {len(self._data)} bytes → {path}")


class BodyScreen(_PayloadView):
    """Full, formatted + syntax-highlighted view of one HTTP request/response body."""

    def __init__(self, session_id: str, flow_id: str, content_type: str,
                 response: bool, id_prefix: str) -> None:
        super().__init__()
        self.session_id = session_id
        self.flow_id = flow_id
        self._content_type = content_type
        self._response = response
        self._id_prefix = id_prefix
        self._label = "response" if response else "request"

    async def _fetch(self) -> bytes:
        try:
            return await self.app.client.get_body(self.session_id, self.flow_id, self._response)
        except Exception:  # noqa: BLE001 (no body / unpersisted)
            return b""

    @property
    def _what(self) -> str:
        return f"{self._label} body"

    @property
    def _subtitle(self) -> str:
        return f"{self._label} body · {self._id_prefix}"

    @property
    def _file_stem(self) -> str:
        return f"{self._id_prefix}-{self._label}"


class WsMessagesScreen(AnnotatableTable, Screen):
    """WebSocket / TCP-parsed message timeline for a flow — directional frames in time
    order, distinct from the request/response view. Messages are annotatable records: the
    same mark/comment/tag/favorite/group actions as the flow table (via AnnotatableTable)."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=False),
        Binding("space", "select", "Select"),
        Binding("D", "clear_selection", "Deselect"),
        Binding("m", "mark", "Mark"),
        Binding("t", "tag", "Tag"),
        Binding("F", "favorite", "Favorite"),
        Binding("n", "comment", "Comment"),
        Binding("g", "group", "Group"),
        Binding("l", "follow", "Follow new"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, session_id: str, flow_id: str) -> None:
        super().__init__()
        self.session_id = session_id
        self.flow_id = flow_id
        self._msgs: dict[str, object] = {}
        self._rows: set[str] = set()
        self._cols: list = []
        self._selected: set[str] = set()       # multi-selection for bulk annotation
        self._tags: list = []
        self._groups: list = []
        self._tagnames: dict[str, str] = {}
        self._groupnames: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        table = NavDataTable(id="msgs", cursor_type="row", zebra_stripes=True)
        self._cols = table.add_columns("", "Time", "Dir", "Opcode", "Len", "Preview")
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.title = "TrafficDeck"
        self._update_subtitle()
        self.query_one("#msgs", DataTable).focus()
        self.load_defs()
        self.load()

    def _update_subtitle(self) -> None:
        base = f"websocket · {self.flow_id[:8]}"
        if self._selected:
            base += f" · {len(self._selected)} selected"
        if self.query_one("#msgs", NavDataTable).follow:
            base += " · ⇣ follow"
        self.sub_title = base

    def action_follow(self) -> None:
        """Toggle follow mode: the cursor tracks each newly arriving frame."""
        table = self.query_one("#msgs", NavDataTable)
        table.set_follow(not table.follow)
        self._update_subtitle()

    def _msg_cells(self, m) -> tuple:
        arrow = "[cyan]C→S[/cyan]" if m.from_client else "[magenta]S→C[/magenta]"
        size = m.payload.size if m.payload else 0
        inline = m.payload.inline if (m.payload and m.payload.WhichOneof("content") == "inline") else b""
        preview = bytes_preview(inline) if inline else (f"[dim]{size} bytes[/dim]" if size else "")
        return (
            flags_cell(m, m.id in self._selected),
            fmt_time(m.ts_unix_micros), arrow, m.opcode, str(size),
            Text.from_markup(preview),
        )

    def _upsert_msg(self, m) -> None:
        """Add a new frame row or update an existing one in place (annotation refresh)."""
        self._msgs[m.id] = m
        table = self.query_one("#msgs", DataTable)
        cells = self._msg_cells(m)
        if m.id in self._rows:
            for col, val in zip(self._cols, cells):
                table.update_cell(m.id, col, val)
        else:
            table.add_row(*cells, key=m.id)
            self._rows.add(m.id)
            self._update_subtitle()

    @work(exclusive=True)
    async def load(self) -> None:
        # Stream frames: backfill of stored frames, then (for a live session) new
        # frames as they're decoded — so a live WebSocket timeline updates in place.
        try:
            async for ev in self.app.client.stream_messages(self.session_id, self.flow_id, follow=True):
                kind = ev.WhichOneof("event")
                if kind == "message_added":
                    self._upsert_msg(ev.message_added)
                elif kind == "session_event":
                    self.notify("session closed — live capture ended")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"stream_messages failed: {exc}", severity="error")
            return
        if not self._msgs:
            self.notify("no websocket frames recorded for this flow")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        mid = str(event.row_key.value)
        self.app.push_screen(WsPayloadScreen(self.session_id, self._msgs[mid]))

    # --- annotation hooks (see AnnotatableTable) -------------------
    def _focused_record_id(self) -> "str | None":
        table = self.query_one("#msgs", DataTable)
        if table.cursor_coordinate is None or table.row_count == 0:
            return None
        return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

    def _record(self, rid):
        return self._msgs.get(rid)

    def _apply_record(self, rec) -> None:
        self._upsert_msg(rec)

    async def _fetch_record(self, rid):
        return await self.app.client.get_message(self.session_id, rid)


class WsPayloadScreen(_PayloadView):
    """Full payload of a single WebSocket frame — formatted + syntax-highlighted
    like an HTTP body (text), or hex-dumped (binary), with the same editor handoff
    for payloads too large to view in the TUI."""

    def __init__(self, session_id: str, msg) -> None:
        super().__init__()
        self.session_id = session_id
        self.msg = msg

    async def _fetch(self) -> bytes:
        try:
            return await self.app.client.get_message_body(self.session_id, self.msg.id)
        except Exception:  # noqa: BLE001 (empty payload — e.g. a bare close/ping frame)
            return self.msg.payload.inline if self.msg.payload else b""

    @property
    def _content_type(self) -> str:
        return self.msg.payload.content_type if self.msg.payload else ""

    @property
    def _what(self) -> str:
        return "payload"

    @property
    def _subtitle(self) -> str:
        return f"{self.msg.opcode} · {'C→S' if self.msg.from_client else 'S→C'}"

    @property
    def _file_stem(self) -> str:
        return f"{self.msg.id[:8]}.ws"


class CompareScreen(Screen):
    """Side-by-side diff of two requests from different sessions.

    Compares (order-sensitively): HTTP version, pseudo-header order, header order +
    values, cookie order, and request body — the client/parser fingerprint surface.
    A is shown in the left column and B in the right, rendered git-diff style: one
    entry per line, with matching lines kept aligned and differences shown as `-`
    (removed/left) / `+` (added/right). Pseudo-headers are compared and exported
    separately from regular headers. One side is "focused" (▸); `p`/`h`/`k` copy that
    side's pseudo-header/header/cookie order to the clipboard as a Go `[]string{…}`
    literal, and `s` switches the focus between A and B.
    """

    CSS = """
    CompareScreen #cols { height: auto; }
    CompareScreen #diff-a, CompareScreen #diff-b { width: 1fr; padding: 0 1; }
    CompareScreen #diff-a { border-right: solid $surface-lighten-2; }
    """

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=False),
        Binding("s", "switch_side", "Switch A/B"),
        Binding("h", "copy_headers", "Copy header order"),
        Binding("p", "copy_pseudo", "Copy pseudo order"),
        Binding("k", "copy_cookies", "Copy cookie order"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, a: tuple[str, str], b: tuple[str, str]) -> None:
        super().__init__()
        self.a, self.b = a, b
        self._side = "A"           # which request the copy actions target
        self._fa = self._fb = None  # loaded flows, kept for copy/refresh

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="cmp"):
            with Horizontal(id="cols"):
                yield Static("loading…", id="diff-a")
                yield Static(id="diff-b")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "TrafficDeck"
        self._set_subtitle()
        self.load()

    def _set_subtitle(self) -> None:
        self.sub_title = f"compare A ⟷ B · copy target ▸{self._side}"

    @work(exclusive=True)
    async def load(self) -> None:
        try:
            self._fa = await self.app.client.get_flow(*self.a)
            self._fb = await self.app.client.get_flow(*self.b)
        except Exception as exc:  # noqa: BLE001
            self.query_one("#diff-a", Static).update(
                f"[red]could not load both flows: {exc}[/red]\n[dim](live/unpersisted "
                f"sessions can't be compared yet — close them first)[/dim]")
            self.query_one("#diff-b", Static).update("")
            return
        self._refresh()

    def _refresh(self) -> None:
        if self._fa is None or self._fb is None:
            return
        left, right = self._render_columns(self._fa, self._fb)
        self.query_one("#diff-a", Static).update(left)
        self.query_one("#diff-b", Static).update(right)

    # --- copy/export actions --------------------------------------------------

    def action_switch_side(self) -> None:
        self._side = "B" if self._side == "A" else "A"
        self._set_subtitle()
        self._refresh()

    def action_copy_headers(self) -> None:
        f = self._fa if self._side == "A" else self._fb
        if f is None:
            return
        self._copy_go_slice([n for n, _ in self._regular(f)], "header order")

    def action_copy_pseudo(self) -> None:
        f = self._fa if self._side == "A" else self._fb
        if f is None:
            return
        self._copy_go_slice(self._pseudo(f), "pseudo-header order")

    def action_copy_cookies(self) -> None:
        f = self._fa if self._side == "A" else self._fb
        if f is None:
            return
        self._copy_go_slice([n for n, _ in self._cookies(f)], "cookie order")

    def _copy_go_slice(self, items: list[str], what: str) -> None:
        self.app.copy_to_clipboard(self._go_slice(items))
        self.notify(
            f"copied request {self._side} {what} ({len(items)} entries) "
            f"to clipboard as a Go []string{{}}")

    @staticmethod
    def _go_slice(items: list[str]) -> str:
        """Render names as a gofmt-style `[]string{…}` literal (tab-indented)."""
        if not items:
            return "[]string{}"
        body = "".join(f"\t{CompareScreen._go_quote(s)},\n" for s in items)
        return "[]string{\n" + body + "}"

    @staticmethod
    def _go_quote(s: str) -> str:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    # --- diff helpers ---------------------------------------------------------

    @staticmethod
    def _pseudo(f) -> list[str]:
        return [h.name for h in f.request_headers if h.name.startswith(":")]

    @staticmethod
    def _regular(f) -> list:  # list of (name, value)
        return [(h.name, h.value) for h in f.request_headers if not h.name.startswith(":")]

    @staticmethod
    def _cookies(f) -> list:  # ordered (name, value) from the Cookie header
        for h in f.request_headers:
            if h.name.lower() == "cookie":
                out = []
                for part in h.value.split(";"):
                    part = part.strip()
                    if not part:
                        continue
                    k, _, v = part.partition("=")
                    out.append((k.strip(), v))
                return out
        return []

    @staticmethod
    def _mark(equal: bool) -> Content:
        return Content.from_markup(
            "[green]✓ match[/green]" if equal else "[red]✗ differ[/red]")

    def _render_columns(self, a, b) -> tuple[Content, Content]:
        """Build the left (A) and right (B) columns of a git-style, line-by-line diff.
        Every logical line is emitted to both columns at once (a blank fills the side
        that has no content), so the two columns always have equal line counts and stay
        vertically aligned. All header/cookie text is inserted via $-substitution and
        never reparsed as markup."""
        left: list[Content] = []
        right: list[Content] = []

        def row(l: Content, r: Content) -> None:
            left.append(l)
            right.append(r)

        def cell(marker: str, color: str, text: str, indent: int = 2) -> Content:
            return Content.from_markup(f"{' ' * indent}[{color}]{marker}[/{color}] $v", v=text)

        def eq(va: str, vb: str) -> None:  # unchanged context line on both sides
            row(cell(" ", "dim", va), cell(" ", "dim", vb))

        def chg(va: str | None, vb: str | None) -> None:  # -removed (left) / +added (right)
            row(cell("-", "red", va) if va is not None else Content(""),
                cell("+", "green", vb) if vb is not None else Content(""))

        def title(text: str, equal: bool) -> None:
            row(Content(""), Content(""))
            t = Content.from_markup("[b u]$t[/b u]  ", t=text).append(self._mark(equal))
            row(t, t)

        def diff_list(items_a: list[str], items_b: list[str]) -> None:
            for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
                    None, items_a, items_b, autojunk=False).get_opcodes():
                if tag == "equal":
                    for k in range(i2 - i1):
                        eq(items_a[i1 + k], items_b[j1 + k])
                else:  # replace/delete/insert: pair up removed/added, padding the short side
                    la, lb = items_a[i1:i2], items_b[j1:j2]
                    for k in range(max(len(la), len(lb))):
                        chg(la[k] if k < len(la) else None, lb[k] if k < len(lb) else None)

        # Column headers, with the ▸ copy-target marker on the focused side.
        ma, mb = ("▸" if self._side == s else " " for s in ("A", "B"))
        row(Content.from_markup(f"{ma} [b cyan]A[/b cyan] [dim]$m $auth$p[/dim]",
                                m=a.method, auth=a.authority, p=a.path),
            Content.from_markup(f"{mb} [b magenta]B[/b magenta] [dim]$m $auth$p[/dim]",
                                m=b.method, auth=b.authority, p=b.path))

        # HTTP version
        title("HTTP version", a.protocol == b.protocol)
        (eq if a.protocol == b.protocol else chg)(a.protocol or "∅", b.protocol or "∅")

        # Pseudo-header order (compared separately from regular headers)
        pa, pb = self._pseudo(a), self._pseudo(b)
        title("Pseudo-header order", pa == pb)
        diff_list(pa, pb)

        # Header order (names only)
        na = [n for n, _ in self._regular(a)]
        nb = [n for n, _ in self._regular(b)]
        title("Header order", na == nb)
        diff_list(na, nb)

        # Cookie order (names only)
        cna = [n for n, _ in self._cookies(a)]
        cnb = [n for n, _ in self._cookies(b)]
        title("Cookie order", cna == cnb)
        diff_list(cna, cnb)

        # Header values — one "name: value" line per header (A's order, then B-only).
        da, db = dict(self._regular(a)), dict(self._regular(b))
        names = list(dict.fromkeys(na + nb))
        title("Header values", not [n for n in names if da.get(n) != db.get(n)])
        for n in names:
            la = f"{n}: {da[n]}" if n in da else None
            lb = f"{n}: {db[n]}" if n in db else None
            if la is not None and la == lb:
                eq(la, lb)
            else:
                chg(la, lb)

        # Request body (size only; bodies may be large/binary)
        ba = a.request_body.inline if a.request_body.size else b""
        bb = b.request_body.inline if b.request_body.size else b""
        title("Request body", ba == bb)
        (eq if ba == bb else chg)(f"{a.request_body.size}B", f"{b.request_body.size}B")

        return Content("\n").join(left), Content("\n").join(right)
