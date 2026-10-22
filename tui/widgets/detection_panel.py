"""
tui/widgets/detection_panel.py

Detection Engine Status Widget.
Displays:
  - Detection Engine status (ACTIVE / READY)
  - Number of enabled rules (5 rules supported: A001 - E001)
  - Most recent detection evaluation timestamp
  - Recent detection errors (0)
  - Breakdown of alerts by severity
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.widget import Widget
from textual.widgets import Static


class DetectionStatusPanel(Widget):
    """Detection Engine health and alert statistics panel."""

    DEFAULT_CSS = """
    DetectionStatusPanel {
        height: 100%;
        background: #0d1117;
        border: round #1e293b;
        padding: 1;
    }
    .detection-title {
        color: #00ff66;
        text-style: bold;
        margin-bottom: 1;
    }
    .rule-chip {
        color: #38bdf8;
        text-style: bold;
    }
    """

    def __init__(
        self,
        engine_status: str = "ACTIVE",
        enabled_rules: int = 5,
        last_eval: str = "Never",
        recent_errors: int = 0,
        severity_counts: dict | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.engine_status = engine_status
        self.enabled_rules = enabled_rules
        self.last_eval = last_eval
        self.recent_errors = recent_errors
        self.severity_counts = severity_counts or {}

    def compose(self) -> ComposeResult:
        yield Static("[bold #00ff66]🛡 DETECTION ENGINE STATUS[/]", classes="detection-title")
        yield Static(self._build_content(), id="detection-content")

    def _build_content(self) -> str:
        crit = self.severity_counts.get("critical", 0)
        high = self.severity_counts.get("high", 0)
        med = self.severity_counts.get("medium", 0)
        low = self.severity_counts.get("low", 0)
        total = crit + high + med + low

        status_badge = "[bold #00ff66]● ACTIVE / EVALUATING[/]" if self.engine_status == "ACTIVE" else f"[bold yellow]{self.engine_status}[/]"

        lines = [
            f"[dim]Engine Status:[/]       {status_badge}",
            f"[dim]Enabled Rules:[/]       [bold #38bdf8]5 / 5 Rules Online[/]",
            f"[dim]Last Evaluation:[/]     [bold #94a3b8]{self.last_eval}[/]",
            f"[dim]Recent Errors:[/]       [bold #22c55e]{self.recent_errors} errors[/]",
            "",
            "[bold #94a3b8 underline]ACTIVE DETECTION RULES (v1.0):[/]",
            " • [bold cyan]A001[/] LaunchAgent/Daemon Persistence  [dim](High)[/]",
            " • [bold cyan]B001[/] Suspicious Path Executable      [dim](Medium)[/]",
            " • [bold cyan]C001[/] Input Monitoring / Accessibility [dim](High)[/]",
            " • [bold cyan]D001[/] Process + Network Correlation   [dim](Medium)[/]",
            " • [bold cyan]E001[/] Multi-Indicator Correlated Threat [dim](Critical)[/]",
            "",
            "[bold #94a3b8 underline]ALERTS BY SEVERITY:[/]",
            f" [bold red]☠ CRITICAL:[/]   {crit:<4}   [bold orange3]🔥 HIGH:[/]   {high:<4}",
            f" [bold yellow]⚡ MEDIUM:[/]     {med:<4}   [bold green]🛡 LOW:[/]    {low:<4}",
            f" [dim]TOTAL ALERTS:[/] [bold white]{total}[/]",
        ]
        return "\n".join(lines)

    def update_status(
        self,
        engine_status: str | None = None,
        last_eval: str | None = None,
        recent_errors: int | None = None,
        severity_counts: dict | None = None,
    ) -> None:
        """Update detection status dynamically."""
        if engine_status is not None:
            self.engine_status = engine_status
        if last_eval is not None:
            self.last_eval = last_eval
        if recent_errors is not None:
            self.recent_errors = recent_errors
        if severity_counts is not None:
            self.severity_counts = severity_counts

        try:
            content_widget = self.query_one("#detection-content", Static)
            content_widget.update(self._build_content())
        except Exception:
            pass
