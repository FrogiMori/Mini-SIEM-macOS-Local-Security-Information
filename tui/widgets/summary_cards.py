"""
tui/widgets/summary_cards.py

FrogiSIEM Metric Summary Cards widget.
Displays real values: Total events, Critical/high alerts, Medium alerts, Active sources.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.widget import Widget
from textual.widgets import Static


class MetricCard(Widget):
    """A single cybersecurity KPI metric card."""

    DEFAULT_CSS = """
    MetricCard {
        height: 100%;
        background: #0d1117;
        border: round #334155;
        padding: 0 1;
        content-align: center middle;
    }
    """

    def __init__(
        self,
        title: str,
        value: str | int,
        color: str = "#00ff66",
        icon: str = "📊",
        card_id: str = "",
        **kwargs,
    ) -> None:
        super().__init__(id=f"card-{card_id}" if card_id else None, **kwargs)
        self.title_text = title
        self.val = str(value)
        self.color = color
        self.icon = icon
        self.card_id = card_id

    def compose(self) -> ComposeResult:
        yield Static(
            f"[{self.color} bold]{self.icon} {self.val}[/]\n[dim #94a3b8]{self.title_text}[/]",
            id=f"card-val-{self.card_id}",
            classes="metric-card-inner",
        )

    def set_value(self, value: str | int) -> None:
        """Update card count dynamically."""
        self.val = str(value)
        label = self.query_one(f"#card-val-{self.card_id}", Static)
        label.update(
            f"[{self.color} bold]{self.icon} {self.val}[/]\n[dim #94a3b8]{self.title_text}[/]"
        )


class SummaryCardsRow(Widget):
    """Grid row containing the 4 primary FrogiSIEM metric cards."""

    DEFAULT_CSS = """
    SummaryCardsRow {
        height: 5;
        margin: 0 1 1 1;
        layout: horizontal;
    }
    SummaryCardsRow > MetricCard {
        width: 1fr;
        margin: 0 1;
    }
    """

    def __init__(
        self,
        total_events: int = 0,
        crit_high_alerts: int = 0,
        medium_alerts: int = 0,
        active_sources: int = 3,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.total_events = total_events
        self.crit_high_alerts = crit_high_alerts
        self.medium_alerts = medium_alerts
        self.active_sources = active_sources

    def compose(self) -> ComposeResult:
        yield MetricCard(
            title="TOTAL INGESTED EVENTS",
            value=f"{self.total_events:,}",
            color="#38bdf8",
            icon="📊",
            card_id="total-events",
        )
        yield MetricCard(
            title="CRITICAL / HIGH ALERTS",
            value=self.crit_high_alerts,
            color="#ef4444",
            icon="🚨",
            card_id="crit-high",
        )
        yield MetricCard(
            title="MEDIUM ALERTS",
            value=self.medium_alerts,
            color="#f59e0b",
            icon="⚡",
            card_id="med-alerts",
        )
        yield MetricCard(
            title="HEALTHY LOG SOURCES",
            value=f"{self.active_sources} / 3 Online",
            color="#00ff66",
            icon="📡",
            card_id="sources",
        )

    def update_metrics(
        self,
        total_events: int,
        crit_high: int,
        med: int,
        sources: int = 3,
    ) -> None:
        """Dynamically update all 4 metric cards."""
        self.total_events = total_events
        self.crit_high_alerts = crit_high
        self.medium_alerts = med
        self.active_sources = sources

        card_total = self.query_one("#card-total-events", MetricCard)
        card_crit = self.query_one("#card-crit-high", MetricCard)
        card_med = self.query_one("#card-med-alerts", MetricCard)
        card_src = self.query_one("#card-sources", MetricCard)

        card_total.set_value(f"{total_events:,}")
        card_crit.set_value(crit_high)
        card_med.set_value(med)
        card_src.set_value(f"{sources} / 3 Online")
