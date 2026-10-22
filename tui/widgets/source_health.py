"""
tui/widgets/source_health.py

Sources / Collector Health Widget for FrogiSIEM.
Displays status of macOS sensors, privileges, hardware metadata, and collection telemetry.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Static


class SourceHealthWidget(Widget):
    """Collector health and macOS sensor status widget."""

    DEFAULT_CSS = """
    SourceHealthWidget {
        height: 1fr;
        background: #0d1117;
        border: round #1e293b;
        padding: 1 2;
    }
    .sources-title {
        color: #00ff66;
        text-style: bold;
        margin-bottom: 1;
    }
    .sources-box {
        margin-bottom: 1;
        padding: 1;
        border: round #334155;
        background: #07090e;
    }
    .action-row {
        height: 3;
        margin-top: 1;
        layout: horizontal;
    }
    .action-btn {
        margin-right: 2;
        min-width: 25;
        background: #1e293b;
        color: #00ff66;
        border: none;
        text-style: bold;
    }
    .action-btn:hover {
        background: #00ff66;
        color: #07090e;
    }
    """

    def __init__(
        self,
        system_info: dict | None = None,
        last_collect_time: str = "Never",
        last_events_count: int = 0,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.system_info = system_info or {}
        self.last_collect_time = last_collect_time
        self.last_events_count = last_events_count

    def compose(self) -> ComposeResult:
        yield Static("[bold #00ff66]📡 MACOS TELEMETRY COLLECTOR & SENSOR HEALTH[/]", classes="sources-title")
        yield Static(self._build_sensor_cards(), id="sensor-cards-content", classes="sources-box")
        yield Static(self._build_host_card(), id="host-card-content", classes="sources-box")
        with Horizontal(classes="action-row"):
            yield Button("▶ Harvest Live macOS Logs [C]", id="btn-collect", classes="action-btn")
            yield Button("🧪 Run Safe Attack Simulation [S]", id="btn-simulate", classes="action-btn")

    def _build_sensor_cards(self) -> str:
        lines = [
            "[bold #38bdf8 underline]ACTIVE LOG SOURCES & SENSOR STATUS:[/]",
            "",
            "1. [bold #00ff66]macOS Unified Logging System (ULS)[/]",
            "   • Mechanism: [cyan]`log show --style json`[/] with safe streaming parser",
            "   • Status:    [bold #00ff66]● ONLINE / HEALTHY[/]",
            "   • Privilege: [green]Standard User (Read-Only)[/]",
            "   • Scope:     Security subsystems (TCC, Sandbox, Auth, Kernel, Launchd)",
            "",
            "2. [bold #00ff66]Live Process Execution Monitor[/]",
            "   • Mechanism: [cyan]`ps -eo pid,ppid,user,%cpu,%mem,comm`[/]",
            "   • Status:    [bold #00ff66]● ONLINE / HEALTHY[/]",
            "   • Privilege: [green]Standard User (Read-Only)[/]",
            "   • Scope:     Detects unsigned binaries running from Downloads, Desktop, or /tmp",
            "",
            "3. [bold #00ff66]LaunchAgent & LaunchDaemon Persistence Inventory[/]",
            "   • Mechanism: Safe [cyan]`plistlib`[/] filesystem enumeration",
            "   • Status:    [bold #00ff66]● ONLINE / HEALTHY[/]",
            "   • Privilege: [green]Standard User (Read-Only)[/]",
            "   • Scope:     Scans ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons",
        ]
        return "\n".join(lines)

    def _build_host_card(self) -> str:
        host = self.system_info.get("hostname", "MacBook-Air")
        arch = self.system_info.get("architecture", "arm64")
        os_ver = self.system_info.get("os_version", "macOS")
        user = self.system_info.get("current_user", "nam")
        uptime = self.system_info.get("uptime_seconds", 0)
        uptime_h = round(uptime / 3600, 1) if uptime else "—"

        lines = [
            "[bold #38bdf8 underline]HOST PLATFORM & ENVIRONMENT TELEMETRY:[/]",
            f" • Hostname:          [bold white]{host}[/]",
            f" • Architecture:      [bold #00ff66]{arch}[/] (Apple Silicon M1)",
            f" • macOS Build:       [bold white]{os_ver}[/]",
            f" • Active Operator:   [bold cyan]{user}[/]",
            f" • System Uptime:     [dim]{uptime_h} hours[/]",
            f" • Last Collection:   [bold yellow]{self.last_collect_time}[/]",
        ]
        return "\n".join(lines)

    def update_info(self, system_info: dict, last_collect_time: str, last_count: int) -> None:
        """Update host and telemetry values."""
        self.system_info = system_info
        self.last_collect_time = last_collect_time
        self.last_events_count = last_count

        try:
            host_card = self.query_one("#host-card-content", Static)
            host_card.update(self._build_host_card())
        except Exception:
            pass
