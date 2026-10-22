"""
tui/widgets/header.py

FrogiSIEM Top Header widget.
Displays Product name, Hostname, Local monitoring mode, Collector status,
Last collection timestamp, and overall system status.
"""

from __future__ import annotations

from datetime import datetime, timezone
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Static


class FrogiSIEMHeader(Widget):
    """Header widget displaying FrogiSIEM status banner."""

    DEFAULT_CSS = """
    FrogiSIEMHeader {
        height: 3;
        background: #0b0f19;
        border-bottom: heavy #00ff66;
        padding: 0 1;
        layout: horizontal;
    }
    .header-left {
        width: 1fr;
        content-align: left middle;
    }
    .header-center {
        width: 1fr;
        content-align: center middle;
    }
    .header-right {
        width: 1fr;
        content-align: right middle;
    }
    """

    def __init__(
        self,
        hostname: str = "MacBook",
        arch: str = "arm64",
        os_ver: str = "macOS",
        collector_status: str = "ONLINE",
        last_collection: str = "Never",
        monitoring_mode: str = "LOCAL AGENT",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.hostname = hostname
        self.arch = arch
        self.os_ver = os_ver
        self.collector_status = collector_status
        self.last_collection = last_collection
        self.monitoring_mode = monitoring_mode

    def compose(self) -> ComposeResult:
        # Left: Product and Host
        left_text = (
            f"[bold #00ff66]🛡 FrogiSIEM[/]  "
            f"[dim #64748b]|[/]  "
            f"[bold #f8fafc]{self.hostname}[/] "
            f"[dim]({self.arch} / {self.os_ver})[/]"
        )

        # Center: Monitoring Mode & Collector Status
        center_text = (
            f"[dim]Mode:[/] [bold #38bdf8]{self.monitoring_mode}[/]  "
            f"[dim #64748b]|[/]  "
            f"[dim]Collector:[/] [bold #00ff66]{self.collector_status}[/]"
        )

        # Right: Last Harvest & Local Time
        right_text = (
            f"[dim]Last Sync:[/] [bold #94a3b8]{self.last_collection}[/]  "
            f"[dim #64748b]|[/]  "
            f"[bold #00ff66]● ACTIVE[/]"
        )

        yield Static(left_text, classes="header-left", id="header-left")
        yield Static(center_text, classes="header-center", id="header-center")
        yield Static(right_text, classes="header-right", id="header-right")

    def update_status(
        self,
        collector_status: str | None = None,
        last_collection: str | None = None,
        monitoring_mode: str | None = None,
        status_line: str | None = None,
    ) -> None:
        """Update header metrics dynamically."""
        if collector_status is not None:
            self.collector_status = collector_status
        if last_collection is not None:
            self.last_collection = last_collection
        if monitoring_mode is not None:
            self.monitoring_mode = monitoring_mode

        center = self.query_one("#header-center", Static)
        status_color = "#00ff66" if self.collector_status in ("ONLINE", "READY") else "#f59e0b"
        center.update(
            f"[dim]Mode:[/] [bold #38bdf8]{self.monitoring_mode}[/]  "
            f"[dim #64748b]|[/]  "
            f"[dim]Collector:[/] [bold {status_color}]{self.collector_status}[/]"
        )

        right = self.query_one("#header-right", Static)
        right.update(
            f"[dim]Last Sync:[/] [bold #94a3b8]{self.last_collection}[/]  "
            f"[dim #64748b]|[/]  "
            f"[bold #00ff66]● ACTIVE[/]"
        )
