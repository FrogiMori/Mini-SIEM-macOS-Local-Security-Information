"""
tui/app.py

FrogiSIEM — Cybersecurity Terminal User Interface (TUI) Dashboard.
Built with Textual for Apple Silicon (M1/macOS).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add project root to sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, ContentSwitcher, DataTable, Footer, Input, RichLog, Select, Static

from tui.state import FrogiSIEMState
from tui.widgets.detection_panel import DetectionStatusPanel
from tui.widgets.event_dossier import EventDossierPanel
from tui.widgets.event_stream import EventSelected, EventStreamWidget
from tui.widgets.header import FrogiSIEMHeader
from tui.widgets.source_health import SourceHealthWidget
from tui.widgets.summary_cards import SummaryCardsRow

CSS_PATH = Path(__file__).parent / "styles.tcss"


class FrogiSIEMApp(App[None]):
    """Main Textual Application for FrogiSIEM Blue Team Lab."""

    TITLE = "FrogiSIEM"
    SUB_TITLE = "macOS Blue Team SOC Console"
    CSS_PATH = CSS_PATH

    BINDINGS = [
        Binding("1", "switch_view('overview')", "Overview", show=True, priority=True),
        Binding("2", "switch_view('events')", "Events", show=True, priority=True),
        Binding("3", "switch_view('alerts')", "Alerts", show=True, priority=True),
        Binding("4", "switch_view('investigation')", "Investigation", show=True, priority=True),
        Binding("5", "switch_view('sources')", "Sources", show=True, priority=True),
        Binding("r", "refresh_data", "Refresh", show=True),
        Binding("slash", "focus_search", "Search", show=True),
        Binding("c", "trigger_collection", "Collect Live", show=True),
        Binding("s", "trigger_simulation", "Simulate", show=True),
        Binding("escape", "handle_escape", "Back/Overview", show=True),
        Binding("q", "quit_app", "Quit", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.state = FrogiSIEMState()
        self.selected_event_data: dict | None = None
        if self.state.alerts:
            self.selected_event_data = self.state.alerts[0]
        elif self.state.events:
            self.selected_event_data = self.state.events[0]

    def compose(self) -> ComposeResult:
        """Compose the full FrogiSIEM dashboard layout."""
        # Top Header
        host_info = self.state.system_info
        yield FrogiSIEMHeader(
            hostname=host_info.get("hostname", "MacBook-Air"),
            arch=host_info.get("architecture", "arm64"),
            os_ver=host_info.get("os_version", "macOS"),
            collector_status=self.state.collector_status,
            last_collection=self.state.last_collection_time,
            id="main-header",
        )

        # Tab Navigation Bar
        with Horizontal(id="nav-tabs-bar"):
            yield Button("[1] OVERVIEW", id="tab-btn-overview", classes="nav-tab-btn nav-tab-active")
            yield Button("[2] EVENTS", id="tab-btn-events", classes="nav-tab-btn")
            yield Button("[3] ALERTS", id="tab-btn-alerts", classes="nav-tab-btn")
            yield Button("[4] INVESTIGATION", id="tab-btn-investigation", classes="nav-tab-btn")
            yield Button("[5] SENSORS & HEALTH", id="tab-btn-sources", classes="nav-tab-btn")

        # Metric Summary Cards Row
        crit_high = self.state.severity_counts.get("critical", 0) + self.state.severity_counts.get("high", 0)
        yield SummaryCardsRow(
            total_events=self.state.stats.get("event_count", 0),
            crit_high_alerts=crit_high,
            medium_alerts=self.state.severity_counts.get("medium", 0),
            active_sources=3,
            id="main-summary-cards",
        )

        # Content Switcher containing the 5 dedicated views
        with ContentSwitcher(initial="view-overview", id="main-content-switcher"):
            # ─────────────────────────────────────────────────────────────
            # VIEW 1: OVERVIEW
            # ─────────────────────────────────────────────────────────────
            with Container(id="view-overview", classes="screen-container"):
                with Horizontal(classes="split-horizontal"):
                    # Left: Live Event Stream Preview
                    yield EventStreamWidget(
                        events=self.state.events[:80],
                        title="RECENT LOG ACTIVITY",
                        show_controls=False,
                        id="overview-event-stream",
                    )
                    # Right: Detection status & active rules
                    with Vertical(classes="panel-box", id="overview-right-col"):
                        yield DetectionStatusPanel(
                            engine_status="ACTIVE",
                            enabled_rules=5,
                            last_eval=self.state.last_eval_time,
                            recent_errors=self.state.recent_errors,
                            severity_counts=self.state.severity_counts,
                            id="overview-detection-panel",
                        )

            # ─────────────────────────────────────────────────────────────
            # VIEW 2: EVENTS (Full Interactive Event Stream)
            # ─────────────────────────────────────────────────────────────
            with Container(id="view-events", classes="screen-container"):
                with Horizontal(classes="split-horizontal"):
                    yield EventStreamWidget(
                        events=self.state.events,
                        title="MACOS NORMALIZED LOG STREAM",
                        show_controls=True,
                        id="full-event-stream",
                    )
                    yield EventDossierPanel(
                        event_data=self.selected_event_data,
                        id="events-dossier-panel",
                    )

            # ─────────────────────────────────────────────────────────────
            # VIEW 3: ALERTS (Triage Console)
            # ─────────────────────────────────────────────────────────────
            with Container(id="view-alerts", classes="screen-container"):
                with Horizontal(classes="split-horizontal"):
                    with Vertical(classes="panel-box"):
                        yield Static("[bold #ef4444]🚨 SOC THREAT ALERTS CONSOLE[/]", classes="panel-title")
                        table = DataTable(id="alerts-datatable", cursor_type="row")
                        table.add_columns("ID", "Severity", "Conf", "Rule ID", "Created", "Title", "Process", "Status")
                        yield table
                    yield EventDossierPanel(
                        event_data=self.selected_event_data,
                        id="alerts-dossier-panel",
                    )

            # ─────────────────────────────────────────────────────────────
            # VIEW 4: INVESTIGATION (Timeline & Incident Report)
            # ─────────────────────────────────────────────────────────────
            with Container(id="view-investigation", classes="screen-container"):
                with Horizontal(classes="split-horizontal"):
                    with Vertical(classes="panel-box"):
                        yield Static("[bold #c084fc]⏳ UNIFIED FORENSIC TIMELINE[/]", classes="panel-title")
                        tl_table = DataTable(id="timeline-datatable", cursor_type="row")
                        tl_table.add_columns("Timestamp", "Kind", "Level", "Subject / Process", "Telemetry Detail")
                        yield tl_table
                    with Vertical(classes="panel-box"):
                        yield Static("[bold #38bdf8]📑 INCIDENT INVESTIGATION REPORT (L1 PLAYBOOK)[/]", classes="panel-title")
                        with VerticalScroll():
                            yield Static(self.state.get_incident_report(), id="investigation-report-text")

            # ─────────────────────────────────────────────────────────────
            # VIEW 5: SOURCES & COLLECTOR HEALTH
            # ─────────────────────────────────────────────────────────────
            with Container(id="view-sources", classes="screen-container"):
                yield SourceHealthWidget(
                    system_info=self.state.system_info,
                    last_collect_time=self.state.last_collection_time,
                    last_events_count=len(self.state.events),
                    id="sources-health-widget",
                )

        # Bottom Keybinding Footer
        yield Footer()

    def on_mount(self) -> None:
        """Populate initial tables after DOM is ready."""
        self.populate_alerts_table()
        self.populate_timeline_table()

    # ─────────────────────────────────────────────────────────────────────────
    # Table Population Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def populate_alerts_table(self) -> None:
        """Populate the Alerts DataTable safely."""
        try:
            table = self.query_one("#alerts-datatable", DataTable)
        except Exception:
            return

        table.clear()
        if not self.state.alerts:
            table.add_row(
                "—",
                Text("NONE", style="dim"),
                "—",
                "—",
                "—",
                Text("No security alerts generated yet. Press 'S' to simulate attack scenarios.", style="dim yellow italic"),
                "—",
                "—",
                key="empty-alert",
            )
            return

        for alr in self.state.alerts:
            aid = str(alr.get("id", "—"))
            sev = (alr.get("severity") or "low").lower()
            if sev == "critical":
                sev_text = Text("CRITICAL", style="bold red")
            elif sev == "high":
                sev_text = Text("HIGH", style="bold orange3")
            elif sev == "medium":
                sev_text = Text("MEDIUM", style="bold yellow")
            else:
                sev_text = Text("LOW", style="green")

            conf = (alr.get("confidence") or "?").upper()
            rule = alr.get("rule_id", "—")
            ts = (alr.get("created_at") or alr.get("timestamp") or "")[:19]
            title = (alr.get("title") or "Untitled")[:40]

            # Process from evidence
            ev = alr.get("evidence")
            if isinstance(ev, dict):
                proc = ev.get("process", "—")
            else:
                proc = "—"

            stat = alr.get("status", "open").upper()
            stat_text = Text(stat, style="bold red" if stat == "OPEN" else "dim green")

            table.add_row(
                aid,
                sev_text,
                conf,
                Text(rule, style="bold cyan"),
                ts,
                title,
                proc[:15],
                stat_text,
                key=f"alert-{aid}",
            )

    def populate_timeline_table(self) -> None:
        """Populate the Forensic Timeline DataTable."""
        try:
            table = self.query_one("#timeline-datatable", DataTable)
        except Exception:
            return

        table.clear()
        if not self.state.timeline:
            table.add_row("—", "—", "—", "—", Text("No chronological timeline available.", style="dim"))
            return

        for i, item in enumerate(self.state.timeline[:100]):
            ts = (item.get("ts_sort") or "")[:19]
            kind = item.get("kind", "event")
            kind_badge = Text("ALERT", style="bold red") if kind == "alert" else Text("EVENT", style="dim cyan")
            sev = item.get("severity", "Info")
            proc = item.get("process") or "—"
            detail = (item.get("title") or "")[:60]

            table.add_row(
                ts,
                kind_badge,
                Text(str(sev)[:10], style="bold yellow" if kind == "alert" else "dim"),
                proc[:15],
                detail,
                key=f"tl-{i}",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # Event Handlers & View Switching
    # ─────────────────────────────────────────────────────────────────────────

    def action_switch_view(self, view_name: str) -> None:
        """Switch current screen via ContentSwitcher and update active tab style."""
        switcher = self.query_one("#main-content-switcher", ContentSwitcher)
        target_id = f"view-{view_name}"
        switcher.current = target_id

        # Update active tab button style
        for tab_id in ("overview", "events", "alerts", "investigation", "sources"):
            btn = self.query_one(f"#tab-btn-{tab_id}", Button)
            if tab_id == view_name:
                btn.add_class("nav-tab-active")
            else:
                btn.remove_class("nav-tab-active")

        # Focus table if applicable
        if view_name == "events":
            try:
                self.query_one("#full-event-stream #events-datatable", DataTable).focus()
            except Exception:
                pass
        elif view_name == "alerts":
            try:
                self.query_one("#alerts-datatable", DataTable).focus()
            except Exception:
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle navigation tab clicks and action button presses."""
        btn_id = event.button.id or ""
        if btn_id.startswith("tab-btn-"):
            view_name = btn_id.replace("tab-btn-", "")
            self.action_switch_view(view_name)
        elif btn_id == "btn-collect":
            self.action_trigger_collection()
        elif btn_id == "btn-simulate":
            self.action_trigger_simulation()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in any DataTable."""
        table_id = event.data_table.id
        row_key = str(event.row_key.value)

        if table_id == "alerts-datatable":
            # Lookup alert by id
            for alr in self.state.alerts:
                if f"alert-{alr.get('id')}" == row_key:
                    self.selected_event_data = alr
                    try:
                        self.query_one("#alerts-dossier-panel", EventDossierPanel).set_event(alr)
                    except Exception:
                        pass
                    break

        elif table_id == "timeline-datatable":
            # Lookup timeline raw item
            try:
                idx = int(row_key.replace("tl-", ""))
                item = self.state.timeline[idx].get("raw")
                if item:
                    self.selected_event_data = item
            except Exception:
                pass

    def on_event_selected(self, message: EventSelected) -> None:
        """Handle EventSelected custom message from EventStreamWidget."""
        self.selected_event_data = message.event_data
        try:
            self.query_one("#events-dossier-panel", EventDossierPanel).set_event(message.event_data)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Background Workers (Non-blocking operations)
    # ─────────────────────────────────────────────────────────────────────────

    @work(exclusive=True, thread=True)
    def action_trigger_collection(self) -> None:
        """Harvest live macOS telemetry in background without freezing UI."""
        header = self.query_one("#main-header", FrogiSIEMHeader)
        self.call_from_thread(header.update_status, collector_status="COLLECTING...", monitoring_mode="HARVESTING")
        self.notify("Starting live macOS ULS, process, and LaunchAgent collection...", title="Collector Active", severity="information")

        try:
            inserted, alerts_count = self.state.harvest_live_macos_telemetry(minutes=1)
            self.call_from_thread(self._finish_collection, inserted, alerts_count)
        except Exception as exc:
            self.call_from_thread(self._fail_collection, str(exc))

    def _finish_collection(self, inserted: int, alerts_count: int) -> None:
        header = self.query_one("#main-header", FrogiSIEMHeader)
        header.update_status(collector_status="ONLINE", last_collection=self.state.last_collection_time, monitoring_mode="LOCAL AGENT")
        self.action_refresh_data()
        self.notify(f"Successfully collected {inserted} events! Generated {alerts_count} alerts.", title="Collection Complete", severity="information")

    def _fail_collection(self, error_msg: str) -> None:
        header = self.query_one("#main-header", FrogiSIEMHeader)
        header.update_status(collector_status="ERROR", monitoring_mode="LOCAL AGENT")
        self.notify(f"Collection error: {error_msg}", title="Collector Failed", severity="error")

    @work(exclusive=True, thread=True)
    def action_trigger_simulation(self) -> None:
        """Execute safe attack simulation in background thread."""
        self.notify("Injecting synthetic attack scenarios (Rule A-E)...", title="Simulation Started", severity="warning")
        try:
            inserted, alerts_count = self.state.execute_simulation()
            self.call_from_thread(self._finish_simulation, inserted, alerts_count)
        except Exception as exc:
            self.notify(f"Simulation failed: {exc}", title="Simulation Error", severity="error")

    def _finish_simulation(self, inserted: int, alerts_count: int) -> None:
        self.action_refresh_data()
        self.action_switch_view("alerts")
        self.notify(f"Loaded {inserted} simulated attack events → {alerts_count} alerts correlated!", title="Threats Detected", severity="warning")

    # ─────────────────────────────────────────────────────────────────────────
    # Global Shortcuts
    # ─────────────────────────────────────────────────────────────────────────

    def action_refresh_data(self) -> None:
        """Refresh all data models and tables from SQLite."""
        self.state.reload()

        # Update Summary Cards
        crit_high = self.state.severity_counts.get("critical", 0) + self.state.severity_counts.get("high", 0)
        cards = self.query_one("#main-summary-cards", SummaryCardsRow)
        cards.update_metrics(
            total_events=self.state.stats.get("event_count", 0),
            crit_high=crit_high,
            med=self.state.severity_counts.get("medium", 0),
            sources=3,
        )

        # Update Detection Panel
        try:
            det_panel = self.query_one("#overview-detection-panel", DetectionStatusPanel)
            det_panel.update_status(
                last_eval=self.state.last_eval_time,
                recent_errors=self.state.recent_errors,
                severity_counts=self.state.severity_counts,
            )
        except Exception:
            pass

        # Update Event Streams
        try:
            self.query_one("#overview-event-stream", EventStreamWidget).set_events(self.state.events[:80])
        except Exception:
            pass
        try:
            self.query_one("#full-event-stream", EventStreamWidget).set_events(self.state.events)
        except Exception:
            pass

        # Update Tables
        self.populate_alerts_table()
        self.populate_timeline_table()

        # Update Report
        try:
            rep_text = self.query_one("#investigation-report-text", Static)
            rep_text.update(self.state.get_incident_report())
        except Exception:
            pass

        # Update Sources Widget
        try:
            src_widget = self.query_one("#sources-health-widget", SourceHealthWidget)
            src_widget.update_info(self.state.system_info, self.state.last_collection_time, len(self.state.events))
        except Exception:
            pass

    def action_focus_search(self) -> None:
        """Focus the event search bar."""
        self.action_switch_view("events")
        try:
            inp = self.query_one("#event-search-input", Input)
            inp.focus()
        except Exception:
            pass

    def action_handle_escape(self) -> None:
        """Escape returns to overview screen."""
        self.action_switch_view("overview")

    def action_quit_app(self) -> None:
        """Quit FrogiSIEM cleanly."""
        self.exit()


def run_app() -> None:
    """Entry point for running the FrogiSIEM Textual dashboard."""
    app = FrogiSIEMApp()
    app.run()


# Aliases for backward compatibility
MiniSiemTUI = FrogiSIEMApp
run_tui = run_app


if __name__ == "__main__":
    run_app()
