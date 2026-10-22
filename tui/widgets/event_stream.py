"""
tui/widgets/event_stream.py

Interactive Event Stream DataTable with filtering, search, and keyboard navigation.
Handles empty database gracefully without crashing.
"""

from __future__ import annotations

from typing import Callable
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.widget import Widget
from textual.widgets import DataTable, Input, Select, Static


class EventSelected(Message):
    """Fired when an event is selected in the event table."""

    def __init__(self, event_data: dict) -> None:
        super().__init__()
        self.event_data = event_data


class EventStreamWidget(Widget):
    """Event Stream Widget with interactive DataTable, search input, and filter controls."""

    DEFAULT_CSS = """
    EventStreamWidget {
        height: 1fr;
        background: #0d1117;
        border: round #1e293b;
        padding: 0 1;
    }
    .stream-header {
        height: 3;
        margin-bottom: 0;
        align-vertical: middle;
    }
    .stream-title {
        color: #00ff66;
        text-style: bold;
        width: 1fr;
    }
    .stream-controls {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
        align-vertical: middle;
    }
    .event-search-input {
        width: 2fr;
        background: #07090e;
        border: round #334155;
        color: #00ff66;
    }
    .event-filter-select {
        width: 1fr;
        margin-left: 1;
        background: #07090e;
        border: round #334155;
    }
    .empty-state {
        height: 1fr;
        content-align: center middle;
        color: #64748b;
        text-style: italic;
    }
    """

    def __init__(
        self,
        events: list[dict] | None = None,
        on_event_select: Callable[[dict], None] | None = None,
        title: str = "LIVE EVENT LOG STREAM",
        show_controls: bool = True,
        max_rows: int = 150,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.events_data = events or []
        self.on_event_select = on_event_select
        self.title_text = title
        self.show_controls = show_controls
        self.max_rows = max_rows
        self.search_query: str = ""
        self.severity_filter: str = "ALL"
        self.source_filter: str = "ALL"

    def compose(self) -> ComposeResult:
        with Horizontal(classes="stream-header"):
            yield Static(f"[bold #00ff66]📜 {self.title_text}[/]", classes="stream-title", id="stream-title-label")

        if self.show_controls:
            with Horizontal(classes="stream-controls"):
                yield Input(
                    placeholder="Search descriptions / processes... (press / to focus)",
                    id="event-search-input",
                    classes="event-search-input",
                )
                yield Select(
                    [("All Severities", "ALL"), ("Error/Fault", "ERROR"), ("Info", "INFO"), ("Default", "DEFAULT")],
                    value="ALL",
                    id="event-sev-filter",
                    classes="event-filter-select",
                    allow_blank=False,
                )
                yield Select(
                    [("All Sources", "ALL"), ("com.apple", "APPLE"), ("LaunchItems", "LAUNCH"), ("Processes", "PROCESS")],
                    value="ALL",
                    id="event-src-filter",
                    classes="event-filter-select",
                    allow_blank=False,
                )

        table = DataTable(id="events-datatable", cursor_type="row")
        table.add_columns(
            "ID",
            "Timestamp (UTC)",
            "Severity",
            "Event Source",
            "Event Type",
            "Process",
            "Short Description",
        )
        yield table

    def on_mount(self) -> None:
        """Populate initial events."""
        self.refresh_table()

    def set_events(self, events: list[dict]) -> None:
        """Update event list and refresh table view."""
        self.events_data = events
        self.refresh_table()

    def refresh_table(self) -> None:
        """Filter and render events into the DataTable."""
        try:
            table = self.query_one("#events-datatable", DataTable)
        except Exception:
            return

        table.clear()

        filtered: list[dict] = []
        for evt in self.events_data:
            # Search filter
            if self.search_query:
                q = self.search_query.lower()
                msg = (evt.get("message") or "").lower()
                proc = (evt.get("process") or "").lower()
                src = (evt.get("source") or "").lower()
                if q not in msg and q not in proc and q not in src:
                    continue

            # Severity filter
            if self.severity_filter != "ALL":
                etype = (evt.get("event_type") or "").upper()
                if self.severity_filter == "ERROR" and etype not in ("ERROR", "FAULT"):
                    continue
                elif self.severity_filter == "INFO" and etype != "INFO":
                    continue
                elif self.severity_filter == "DEFAULT" and etype != "DEFAULT":
                    continue

            # Source filter
            if self.source_filter != "ALL":
                src = (evt.get("source") or "").lower()
                if self.source_filter == "APPLE" and "apple" not in src:
                    continue
                elif self.source_filter == "LAUNCH" and "launch" not in src:
                    continue
                elif self.source_filter == "PROCESS" and "process" not in src:
                    continue

            filtered.append(evt)

        # Update title count
        try:
            title_lbl = self.query_one("#stream-title-label", Static)
            title_lbl.update(f"[bold #00ff66]📜 {self.title_text}[/] [dim]({len(filtered)} / {len(self.events_data)} shown)[/]")
        except Exception:
            pass

        if not filtered:
            # Add single empty row so table renders cleanly without crashing
            table.add_row(
                "—",
                "—",
                Text("NONE", style="dim"),
                Text("—", style="dim"),
                Text("—", style="dim"),
                Text("—", style="dim"),
                Text("No matching events. Press 'R' to refresh or '5' for simulation.", style="dim italic yellow"),
                key="empty-row",
            )
            return

        for evt in filtered[: self.max_rows]:
            row_key = str(evt.get("id", id(evt)))
            ts = (evt.get("timestamp") or "")[:19]
            etype = evt.get("event_type") or "Info"

            # Severity styling
            if etype in ("Error", "Fault"):
                sev_styled = Text("CRITICAL" if etype == "Fault" else "HIGH", style="bold red")
            elif etype == "Default":
                sev_styled = Text("MEDIUM", style="bold yellow")
            else:
                sev_styled = Text("LOW", style="green")

            src = (evt.get("source") or "")[:20]
            proc = (evt.get("process") or "—")[:15]
            msg = (evt.get("message") or "")[:70]

            table.add_row(
                str(evt.get("id") or "—"),
                ts,
                sev_styled,
                src,
                etype[:8],
                proc,
                msg,
                key=row_key,
            )

    def on_input_changed(self, event: Input.Changed) -> None:
        """Live search filter as user types."""
        if event.input.id == "event-search-input":
            self.search_query = event.value.strip()
            self.refresh_table()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle severity or source select changes."""
        if event.select.id == "event-sev-filter":
            self.severity_filter = str(event.value)
            self.refresh_table()
        elif event.select.id == "event-src-filter":
            self.source_filter = str(event.value)
            self.refresh_table()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Emit EventSelected message when user presses Enter on a row."""
        row_key = str(event.row_key.value)
        if row_key == "empty-row":
            return

        # Find matching event dict
        for evt in self.events_data:
            if str(evt.get("id", id(evt))) == row_key:
                self.post_message(EventSelected(evt))
                if self.on_event_select:
                    self.on_event_select(evt)
                break
