"""
tui/app.py

Main interactive Terminal User Interface (TUI) for Mini-SIEM.
Provides a full-featured, keyboard-driven SOC Level 1 console.

Run standalone:
    python3 tui/app.py
    # or
    python3 main.py tui
"""

from __future__ import annotations

import os
import select
import sys
import termios
import time
import tty
from pathlib import Path

# Add project root to path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from collector.macos import collect_all, collect_system_info
from data.sample_events import get_sample_events
from detection.engine import run_detection, run_detection_on_events
from investigation.timeline import build_timeline, generate_report
from parser.macos import normalize_event, normalize_launch_item, normalize_process
from storage.database import (
    count_events,
    get_alert_count_by_severity,
    get_alerts,
    get_connection,
    get_db_stats,
    get_events,
    init_database,
    insert_alert,
    insert_events,
)
from tui.components import (
    TABS,
    render_alert_detail_panel,
    render_alerts_table,
    render_events_table,
    render_footer,
    render_header,
    render_metrics_cards,
    render_timeline_table,
)
from tui.theme import (
    COLOR_ACCENT,
    COLOR_BORDER,
    COLOR_CRITICAL,
    COLOR_HIGH,
    COLOR_LOW,
    COLOR_MEDIUM,
    COLOR_MUTED,
    COLOR_PURPLE,
)


class MiniSiemTUI:
    """Terminal User Interface application controller."""

    def __init__(self) -> None:
        self.console = Console()
        self.active_tab: str = "overview"
        self.previous_tab: str = "overview"

        # Indices for list navigation
        self.selected_alert_idx: int = 0
        self.selected_event_idx: int = 0
        self.selected_timeline_idx: int = 0

        # State cache
        self.system_info: dict = {}
        self.stats: dict = {}
        self.severity_counts: dict = {}
        self.alerts: list[dict] = []
        self.events: list[dict] = []
        self.timeline: list[dict] = []

        # Filters
        self.event_filter: str = ""
        self.alert_severity_filter: str | None = None

        # Detail view state
        self.inspecting_alert: dict | None = None
        self.inspecting_trigger_event: dict | None = None

        # Status flash message
        self.status_msg: str = "READY"
        self.is_running: bool = True

        # Initialize DB
        init_database()
        self.refresh_data()

    def refresh_data(self) -> None:
        """Fetch fresh metrics and data from database and system."""
        try:
            self.stats = get_db_stats()
            self.severity_counts = get_alert_count_by_severity()
            self.alerts = get_alerts(
                limit=300,
                severity_filter=self.alert_severity_filter,
            )

            # Events with optional search
            filters = {}
            if self.event_filter:
                filters["search"] = self.event_filter
            self.events = get_events(limit=200, filters=filters)

            # Build timeline
            self.timeline = build_timeline(self.events[:150], self.alerts[:100])

            if not self.system_info:
                try:
                    self.system_info = collect_system_info()
                except Exception:
                    self.system_info = {"hostname": "localhost", "os_version": "macOS", "architecture": "arm64"}

            # Bounds check
            if self.alerts:
                self.selected_alert_idx = max(0, min(self.selected_alert_idx, len(self.alerts) - 1))
            else:
                self.selected_alert_idx = 0

            if self.events:
                self.selected_event_idx = max(0, min(self.selected_event_idx, len(self.events) - 1))
            else:
                self.selected_event_idx = 0

            if self.timeline:
                self.selected_timeline_idx = max(0, min(self.selected_timeline_idx, len(self.timeline) - 1))
            else:
                self.selected_timeline_idx = 0

        except Exception as exc:
            self.status_msg = f"ERROR: {exc}"

    # ─────────────────────────────────────────────────────────────────────────
    # Input Reader
    # ─────────────────────────────────────────────────────────────────────────

    def get_key(self) -> str:
        """Read a single keypress or ANSI escape sequence in raw mode."""
        if not sys.stdin.isatty():
            line = sys.stdin.readline()
            return line.strip() if line else "q"

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            # Check for multi-byte escape sequences (arrow keys)
            if ch == "\x1b":
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    seq = sys.stdin.read(2)
                    if seq == "[A":
                        return "UP"
                    elif seq == "[B":
                        return "DOWN"
                    elif seq == "[C":
                        return "RIGHT"
                    elif seq == "[D":
                        return "LEFT"
                    return "ESC"
                return "ESC"
            elif ch in ("\r", "\n"):
                return "ENTER"
            elif ch == "\x7f":
                return "BACKSPACE"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    # ─────────────────────────────────────────────────────────────────────────
    # View Renderers
    # ─────────────────────────────────────────────────────────────────────────

    def render_overview(self) -> Layout:
        """Render the primary SOC Overview dashboard."""
        layout = Layout()
        layout.split_column(
            Layout(name="kpi", size=4),
            Layout(name="body"),
        )

        layout["kpi"].update(render_metrics_cards(self.stats, self.severity_counts))

        # Split body into Alerts overview (left) and Activity feed (right)
        body = Layout()
        body.split_row(
            Layout(name="recent_alerts", ratio=3),
            Layout(name="activity_feed", ratio=2),
        )

        # Recent alerts table
        alerts_panel = Panel(
            render_alerts_table(self.alerts[:8], self.selected_alert_idx, max_rows=8),
            title="[bold red]🚨 LATEST SECURITY ALERTS[/]",
            box=box.ROUNDED,
            border_style=COLOR_CRITICAL if self.alerts else COLOR_BORDER,
        )
        body["recent_alerts"].update(alerts_panel)

        # Activity summary
        feed = Table.grid(expand=True)
        feed.add_column(style="dim", width=12)
        feed.add_column(style="white")

        feed.add_row("[bold cyan]DB Location:[/]", f" {self.stats.get('db_path', '—')}")
        feed.add_row("[bold cyan]Last Event:[/]", f" {self.stats.get('last_event_ts', 'None')[:19]}")
        feed.add_row("[bold cyan]Active Rules:[/]", " 5 Rules (A001 - E001)")
        feed.add_row("[bold cyan]Sensors:[/]", " ULS, Process Snapshots, LaunchItems")
        feed.add_row("", "")

        # Action hints
        help_card = Panel(
            "[bold white]QUICK ACTIONS & PLAYBOOKS[/]\n"
            "• Press [bold yellow]5[/] to simulate attack scenarios safely\n"
            "• Press [bold green]6[/] to collect live macOS events\n"
            "• Press [bold cyan]2[/] to inspect & triage open alerts\n"
            "• Press [bold magenta]7[/] to export/read SOC investigation report\n"
            "• Press [bold #38bdf8]4[/] to navigate timeline chronology",
            box=box.ROUNDED,
            border_style=COLOR_ACCENT,
            padding=(1, 2),
        )

        side_layout = Layout()
        side_layout.split_column(
            Layout(Panel(feed, title="[bold #38bdf8]📡 SENSOR STATUS[/]", box=box.ROUNDED), size=7),
            Layout(help_card),
        )
        body["activity_feed"].update(side_layout)

        layout["body"].update(body)
        return layout

    def render_alerts_view(self) -> Panel:
        """Render the Alerts triage console."""
        sev_label = f" (Filter: {self.alert_severity_filter.upper()})" if self.alert_severity_filter else ""
        table = render_alerts_table(self.alerts, self.selected_alert_idx, max_rows=16)

        return Panel(
            table,
            title=f"[bold red]🚨 SOC ALERTS CONSOLE[/] - [white]{len(self.alerts)} Detected{sev_label}[/]",
            box=box.ROUNDED,
            border_style=COLOR_CRITICAL,
            subtitle=Text("Use [↑/↓ or j/k] to select, [Enter] to inspect dossier, [F] to filter severity, [C] to clear filter", style="dim"),
            subtitle_align="center",
        )

    def render_events_view(self) -> Panel:
        """Render the Normalized Events Browser."""
        search_label = f" (Search: '{self.event_filter}')" if self.event_filter else ""
        table = render_events_table(self.events, self.selected_event_idx, max_rows=16)

        return Panel(
            table,
            title=f"[bold #38bdf8]📜 NORMALIZED EVENT LOG STREAM[/] - [white]{len(self.events)} Events{search_label}[/]",
            box=box.ROUNDED,
            border_style=COLOR_BORDER,
            subtitle=Text("Use [↑/↓ or j/k] to browse, [/] to search/filter messages, [C] to clear search", style="dim"),
            subtitle_align="center",
        )

    def render_timeline_view(self) -> Panel:
        """Render the Forensic Timeline."""
        table = render_timeline_table(self.timeline, self.selected_timeline_idx, max_rows=16)

        return Panel(
            table,
            title=f"[bold #c084fc]⏳ UNIFIED FORENSIC TIMELINE[/] - [white]{len(self.timeline)} Entries (Chronological)[/]",
            box=box.ROUNDED,
            border_style=COLOR_BORDER,
            subtitle=Text("Use [↑/↓ or j/k] to navigate chronological progression", style="dim"),
            subtitle_align="center",
        )

    def render_simulate_view(self) -> Panel:
        """Render the Safe Simulation Console."""
        grid = Table.grid(expand=True)
        grid.add_column()

        intro = (
            "[bold white]CYBERSECURITY DETECTION LAB — SAFE ATTACK SIMULATION[/]\n"
            "[dim]Inject synthetic attack telemetry into the Mini-SIEM to evaluate Rule A–E coverage without modifying your host.[/]\n"
        )
        grid.add_row(intro)

        scenarios = Table(box=box.SIMPLE, expand=True, header_style="bold #94a3b8")
        scenarios.add_column("Scenario", width=12, style="bold cyan")
        scenarios.add_column("Technique / Vector", width=24, style="white")
        scenarios.add_column("Target Rule", width=14, style="bold yellow")
        scenarios.add_column("Expected Severity", width=16)
        scenarios.add_column("Description", style="dim")

        scenarios.add_row("S1 — Persistence", "LaunchAgent Plist Write", "Rule A001", "[bold orange3]HIGH[/]", "Plist dropped in ~/Library/LaunchAgents")
        scenarios.add_row("S2 — Suspicious Path", "Exec from ~/Downloads", "Rule B001", "[bold yellow]MEDIUM[/]", "Unverified binary execution from writable folder")
        scenarios.add_row("S3 — Input Capability", "TCC Accessibility Grant", "Rule C001", "[bold orange3]HIGH[/]", "kTCCServiceAccessibility granted via TCC")
        scenarios.add_row("S4 — Network Exfil", "Socket Connect from Downloads", "Rule D001", "[bold yellow]MEDIUM[/]", "Outbound TCP connection from suspicious executable")
        scenarios.add_row("S5 — Combined Attack", "Correlated Multi-indicator", "Rule E001", "[bold red]CRITICAL[/]", "Same process triggers multiple independent rules")
        scenarios.add_row("S6 — Benign Activity", "Finder File Movement", "None (Baseline)", "[bold green]NO ALERT[/]", "Normal user action verifying low false-positive rate")
        scenarios.add_row("S7 — IOHID Hook", "IOHIDManager LaunchDaemon", "Rule A+C", "[bold red]CRITICAL[/]", "Hardware Input monitoring daemon installed")
        scenarios.add_row("S8 — KeyTap Creation", "CGEventTap KeyDown Monitor", "Rule C+E", "[bold red]CRITICAL[/]", "Direct keystroke interception capability")

        grid.add_row(scenarios)
        grid.add_row("\n")

        action_box = Panel(
            Align.center(
                "[bold white]Press [bold yellow][S][/] to EXECUTE SIMULATION SUITE NOW[/]\n"
                "[dim]This loads 8 synthetic events into the database and triggers real-time rule correlation.[/]"
            ),
            box=box.ROUNDED,
            border_style="yellow",
        )
        grid.add_row(action_box)

        return Panel(
            grid,
            title="[bold yellow]🧪 ATTACK SIMULATION WORKBENCH[/]",
            box=box.ROUNDED,
            border_style="yellow",
            padding=(1, 2),
        )

    def render_collect_view(self) -> Panel:
        """Render the macOS Data Collection Console."""
        grid = Table.grid(expand=True)
        grid.add_column()

        intro = (
            "[bold white]LIVE MACOS DATA COLLECTION ENGINE[/]\n"
            "[dim]Reads non-privileged security signals directly from your Apple Silicon host.[/]\n\n"
        )
        grid.add_row(intro)

        sources = Table(box=box.SIMPLE, expand=True, header_style="bold #94a3b8")
        sources.add_column("Data Source", width=22, style="bold cyan")
        sources.add_column("System Tool", width=18, style="white")
        sources.add_column("Privilege", width=14, style="green")
        sources.add_column("Scope / Purpose", style="dim")

        sources.add_row("Unified Logging System", "log show --style json", "Standard User", "Captures security subsystems, TCC, sandbox, auth events")
        sources.add_row("Running Processes", "ps -eo pid,ppid,comm", "Standard User", "Snapshots live processes, parent PIDs, resource metrics")
        sources.add_row("Launch Items Inventory", "plistlib (readable plists)", "Standard User", "Scans LaunchAgents & Daemons for persistence plists")
        sources.add_row("System Hardware & OS", "sw_vers, uname, sysctl", "Standard User", "Identifies host architecture, OS build, uptime, user")

        grid.add_row(sources)
        grid.add_row("\n")

        action_box = Panel(
            Align.center(
                "[bold white]Press [bold green][C][/] to COLLECT LAST 1 MINUTE OF REAL MACOS LOGS[/]\n"
                "[dim]Harvests live ULS logs, running processes, and LaunchItems into the database.[/]"
            ),
            box=box.ROUNDED,
            border_style="green",
        )
        grid.add_row(action_box)

        return Panel(
            grid,
            title="[bold green]📡 LIVE SENSOR COLLECTOR[/]",
            box=box.ROUNDED,
            border_style="green",
            padding=(1, 2),
        )

    def render_report_view(self) -> Panel:
        """Render the Forensic Incident Report viewer."""
        try:
            report_text = generate_report(
                incident_id=None,
                events=self.events[:300],
                alerts=self.alerts[:100],
                system_info=self.system_info,
            )
        except Exception as exc:
            report_text = f"Failed to generate report: {exc}"

        return Panel(
            Text(report_text, style="white"),
            title="[bold #c084fc]📑 INCIDENT INVESTIGATION REPORT (SOC Level 1 Playbook)[/]",
            box=box.ROUNDED,
            border_style=COLOR_PURPLE,
            subtitle=Text("Press [R] to re-generate, [Esc] to return", style="dim"),
            subtitle_align="center",
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Action Handlers
    # ─────────────────────────────────────────────────────────────────────────

    def execute_simulation(self) -> None:
        """Load synthetic events and trigger detection engine."""
        self.status_msg = "Running safe attack simulation..."
        try:
            events = get_sample_events()
            count = insert_events(events)

            # Re-fetch with row IDs and run detection
            stored = get_events(limit=count + 100)
            alerts = run_detection(stored)

            self.refresh_data()
            self.active_tab = "alerts"
            self.status_msg = f"SIMULATION COMPLETE: {count} events stored → {len(alerts)} alerts triggered!"
        except Exception as exc:
            self.status_msg = f"Simulation failed: {exc}"

    def execute_collection(self) -> None:
        """Harvest live logs, processes, and launch plists from macOS."""
        self.status_msg = "Collecting live macOS telemetry (1 min logs + processes)..."
        try:
            data = collect_all(minutes=1)
            norm_events: list[dict] = []

            for raw in data.get("log_events", []):
                n = normalize_event(raw)
                if n:
                    norm_events.append(n)
            for raw in data.get("processes", []):
                n = normalize_process(raw)
                if n:
                    norm_events.append(n)
            for raw in data.get("launch_items", []):
                n = normalize_launch_item(raw)
                if n:
                    norm_events.append(n)

            inserted = insert_events(norm_events)

            # Run detection on newly stored events
            new_alerts = run_detection()
            self.refresh_data()
            self.status_msg = f"COLLECTION SUCCESS: {inserted} events ingested, {len(new_alerts)} alerts generated."
        except Exception as exc:
            self.status_msg = f"Collector failed: {exc}"

    def inspect_selected_alert(self) -> None:
        """Drill into the selected alert dossier."""
        if not self.alerts or self.selected_alert_idx >= len(self.alerts):
            return

        alr = self.alerts[self.selected_alert_idx]
        self.inspecting_alert = alr

        # Find triggering event if event_id is present
        evt_id = alr.get("event_id")
        self.inspecting_trigger_event = None
        if evt_id:
            try:
                conn = get_connection()
                row = conn.execute("SELECT * FROM events WHERE id = ?", [evt_id]).fetchone()
                conn.close()
                if row:
                    self.inspecting_trigger_event = dict(row)
            except Exception:
                pass

        self.previous_tab = self.active_tab
        self.active_tab = "alert_detail"

    def prompt_search(self) -> None:
        """Prompt user in terminal for search string."""
        # Restore normal terminal mode temporarily for prompt
        self.console.clear()
        query = Prompt.ask("[bold yellow]Enter keyword or process name to filter events[/] (or leave empty to reset)")
        self.event_filter = query.strip()
        self.refresh_data()
        self.status_msg = f"Filter applied: '{self.event_filter}'" if self.event_filter else "Filter reset."

    def cycle_severity_filter(self) -> None:
        """Cycle through severity filter options."""
        sevs = [None, "critical", "high", "medium", "low"]
        cur_idx = sevs.index(self.alert_severity_filter) if self.alert_severity_filter in sevs else 0
        self.alert_severity_filter = sevs[(cur_idx + 1) % len(sevs)]
        self.refresh_data()
        self.status_msg = f"Severity filter: {self.alert_severity_filter.upper() if self.alert_severity_filter else 'ALL'}"

    # ─────────────────────────────────────────────────────────────────────────
    # Main Render & Event Loop
    # ─────────────────────────────────────────────────────────────────────────

    def draw(self) -> None:
        """Clear and render the full screen layout."""
        self.console.clear()

        # Top SOC Header
        header = render_header(
            system_info=self.system_info,
            active_tab=self.active_tab if self.active_tab != "alert_detail" else "alerts",
            status_msg=self.status_msg,
        )

        # Body selection
        if self.active_tab == "overview":
            body = self.render_overview()
        elif self.active_tab == "alerts":
            body = self.render_alerts_view()
        elif self.active_tab == "alert_detail":
            body = render_alert_detail_panel(self.inspecting_alert or {}, self.inspecting_trigger_event)
        elif self.active_tab == "events":
            body = self.render_events_view()
        elif self.active_tab == "timeline":
            body = self.render_timeline_view()
        elif self.active_tab == "simulate":
            body = self.render_simulate_view()
        elif self.active_tab == "collect":
            body = self.render_collect_view()
        elif self.active_tab == "report":
            body = self.render_report_view()
        else:
            body = self.render_overview()

        # Footer
        footer = render_footer(
            status_text=f"Total: {self.stats.get('event_count', 0):,} Events | {self.stats.get('alert_count', 0):,} Alerts",
            help_hint="Press [1-7] for tabs",
        )

        main_layout = Layout()
        main_layout.split_column(
            Layout(header, size=4),
            Layout(body),
            Layout(footer, size=3),
        )

        self.console.print(main_layout)

    def run(self) -> None:
        """Start the interactive event loop."""
        try:
            while self.is_running:
                self.draw()
                key = self.get_key()

                # Global tab hotkeys
                if key in ("1", "2", "3", "4", "5", "6", "7"):
                    tab_map = {
                        "1": "overview",
                        "2": "alerts",
                        "3": "events",
                        "4": "timeline",
                        "5": "simulate",
                        "6": "collect",
                        "7": "report",
                    }
                    self.active_tab = tab_map[key]
                    self.status_msg = f"Navigated to {self.active_tab.upper()}"
                    continue

                if key in ("q", "Q"):
                    self.is_running = False
                    break

                if key in ("r", "R"):
                    self.refresh_data()
                    self.status_msg = "Data refreshed."
                    continue

                if key == "ESC" or key in ("b", "B"):
                    if self.active_tab == "alert_detail":
                        self.active_tab = self.previous_tab
                    else:
                        self.active_tab = "overview"
                    continue

                # Contextual actions
                if self.active_tab in ("overview", "alerts"):
                    if key in ("UP", "k", "K"):
                        self.selected_alert_idx = max(0, self.selected_alert_idx - 1)
                    elif key in ("DOWN", "j", "J"):
                        self.selected_alert_idx = min(len(self.alerts) - 1, self.selected_alert_idx + 1)
                    elif key == "ENTER":
                        self.inspect_selected_alert()
                    elif key in ("f", "F"):
                        self.cycle_severity_filter()
                    elif key in ("c", "C"):
                        self.alert_severity_filter = None
                        self.refresh_data()
                        self.status_msg = "Alert filter cleared."

                elif self.active_tab == "events":
                    if key in ("UP", "k", "K"):
                        self.selected_event_idx = max(0, self.selected_event_idx - 1)
                    elif key in ("DOWN", "j", "J"):
                        self.selected_event_idx = min(len(self.events) - 1, self.selected_event_idx + 1)
                    elif key == "/":
                        self.prompt_search()
                    elif key in ("c", "C"):
                        self.event_filter = ""
                        self.refresh_data()
                        self.status_msg = "Search filter cleared."

                elif self.active_tab == "timeline":
                    if key in ("UP", "k", "K"):
                        self.selected_timeline_idx = max(0, self.selected_timeline_idx - 1)
                    elif key in ("DOWN", "j", "J"):
                        self.selected_timeline_idx = min(len(self.timeline) - 1, self.selected_timeline_idx + 1)

                elif self.active_tab == "simulate":
                    if key in ("s", "S", "ENTER"):
                        self.execute_simulation()

                elif self.active_tab == "collect":
                    if key in ("c", "C", "ENTER"):
                        self.execute_collection()

        except KeyboardInterrupt:
            pass
        finally:
            self.console.clear()
            self.console.print("\n[bold cyan]🛡 Mini-SIEM TUI closed. Have a secure day![/]\n")


def run_tui() -> None:
    """Entry point to launch the TUI application."""
    app = MiniSiemTUI()
    app.run()


if __name__ == "__main__":
    run_tui()
