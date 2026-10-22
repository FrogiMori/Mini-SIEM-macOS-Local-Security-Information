"""
tui/components.py

Rich UI layout components for the Mini-SIEM Terminal User Interface.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tui.theme import (
    COLOR_ACCENT,
    COLOR_BORDER,
    COLOR_CRITICAL,
    COLOR_HIGH,
    COLOR_INFO,
    COLOR_LOW,
    COLOR_MEDIUM,
    COLOR_MUTED,
    COLOR_PURPLE,
    COLOR_TEXT,
    badge_rule,
    badge_severity,
    badge_status,
)

TABS = [
    ("1", "Overview", "overview"),
    ("2", "Alerts", "alerts"),
    ("3", "Events", "events"),
    ("4", "Timeline", "timeline"),
    ("5", "Simulate", "simulate"),
    ("6", "Collect", "collect"),
    ("7", "Report", "report"),
]


def render_header(
    system_info: dict,
    active_tab: str,
    status_msg: str = "SYSTEM ACTIVE",
) -> Panel:
    """Render the top SOC command bar."""
    host = system_info.get("hostname", "macOS-Host")
    os_ver = system_info.get("os_version", "macOS")
    arch = system_info.get("architecture", "arm64")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Header title text
    title_text = Text()
    title_text.append("🛡  MINI-SIEM ", style="bold #38bdf8")
    title_text.append("BLUE TEAM LAB", style="bold #e2e8f0")
    title_text.append(f"  |  Host: {host}", style="cyan")
    title_text.append(f" ({arch}/{os_ver})", style="dim")
    title_text.append(f"  |  {now_str}", style="dim green")

    # Tabs text
    tab_text = Text()
    for key, label, tab_id in TABS:
        if tab_id == active_tab:
            tab_text.append(f" [{key}] {label.upper()} ", style="bold white on #1d4ed8")
        else:
            tab_text.append(f" [{key}] {label} ", style="bold #94a3b8")
        tab_text.append(" ")

    tab_text.append(" [Q] Quit", style="bold red")

    combined = Text()
    combined.append_text(title_text)
    combined.append("\n")
    combined.append_text(tab_text)

    return Panel(
        combined,
        box=box.ROUNDED,
        border_style=COLOR_ACCENT,
        padding=(0, 1),
        subtitle=f"[dim italic]{status_msg}[/]",
        subtitle_align="right",
    )


def render_metrics_cards(stats: dict, sev_counts: dict) -> Table:
    """Render top metric cards for events, alerts by severity."""
    cards_table = Table.grid(expand=True)
    cards_table.add_column(ratio=1)
    cards_table.add_column(ratio=1)
    cards_table.add_column(ratio=1)
    cards_table.add_column(ratio=1)
    cards_table.add_column(ratio=1)
    cards_table.add_column(ratio=1)

    event_count = stats.get("event_count", 0)
    alert_count = stats.get("alert_count", 0)
    crit_count = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)
    med_count = sev_counts.get("medium", 0)
    low_count = sev_counts.get("low", 0)

    def _card(title: str, val: Any, color: str, icon: str = "") -> Panel:
        t = Text()
        t.append(f"{icon} {val}\n", style=f"bold {color}")
        t.append(title, style="dim white")
        return Panel(
            Align.center(t),
            border_style=color,
            box=box.ROUNDED,
            padding=(0, 1),
        )

    cards_table.add_row(
        _card("TOTAL EVENTS", f"{event_count:,}", "#38bdf8", "📊"),
        _card("TOTAL ALERTS", f"{alert_count:,}", "#c084fc", "🚨"),
        _card("CRITICAL", crit_count, COLOR_CRITICAL, "☠"),
        _card("HIGH RISK", high_count, COLOR_HIGH, "🔥"),
        _card("MEDIUM RISK", med_count, COLOR_MEDIUM, "⚡"),
        _card("LOW RISK", low_count, COLOR_LOW, "🛡"),
    )

    return cards_table


def render_alerts_table(
    alerts: list[dict],
    selected_idx: int = 0,
    max_rows: int = 12,
) -> Table:
    """Format alerts as a structured rich Table."""
    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style="bold #94a3b8",
        border_style=COLOR_BORDER,
        row_styles=["none", "dim"],
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Sev", justify="center", width=8)
    table.add_column("Conf", justify="center", width=6)
    table.add_column("Rule", justify="center", width=7)
    table.add_column("Created", style="dim", width=18)
    table.add_column("Alert Title", style="bold white", ratio=2)
    table.add_column("Process", style="cyan", width=16)
    table.add_column("Status", justify="center", width=12)

    if not alerts:
        table.add_row("—", "—", "—", "—", "—", "[dim]No alerts detected yet. Press [5] to run simulation or [6] to collect.[/]", "—", "—")
        return table

    start_idx = max(0, min(selected_idx - max_rows // 2, len(alerts) - max_rows))
    visible_alerts = alerts[start_idx : start_idx + max_rows]

    for i, alr in enumerate(visible_alerts, start=start_idx + 1):
        is_selected = (i - 1) == selected_idx
        prefix = "▶ " if is_selected else f"{i} "
        row_style = "on #1e293b" if is_selected else None

        sev = (alr.get("severity") or "low").lower()
        conf = (alr.get("confidence") or "?").upper()
        rule = alr.get("rule_id", "—")
        ts = (alr.get("created_at") or alr.get("timestamp") or "")[:19]
        title = alr.get("title") or "Untitled Alert"

        # Extract process from evidence if available
        ev = alr.get("evidence")
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except Exception:
                ev = {}
        proc = (ev or {}).get("process") or "—"
        stat = alr.get("status", "open")

        table.add_row(
            Text(prefix, style="bold yellow" if is_selected else "dim"),
            badge_severity(sev),
            Text(conf, style="dim cyan"),
            badge_rule(rule),
            Text(ts),
            Text(title[:60], style="bold white" if is_selected else "white"),
            Text(proc[:15], style="cyan"),
            badge_status(stat),
            style=row_style,
        )

    return table


def render_events_table(
    events: list[dict],
    selected_idx: int = 0,
    max_rows: int = 15,
) -> Table:
    """Format normalized events as a structured rich Table."""
    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style="bold #94a3b8",
        border_style=COLOR_BORDER,
        row_styles=["none", "dim"],
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Timestamp", style="dim", width=19)
    table.add_column("Type", width=8)
    table.add_column("Process", style="cyan", width=16)
    table.add_column("Source Subsystem", style="dim white", width=24)
    table.add_column("Normalized Message", style="white", ratio=3)

    if not events:
        table.add_row("—", "—", "—", "—", "—", "[dim]No events found matching criteria.[/]")
        return table

    start_idx = max(0, min(selected_idx - max_rows // 2, len(events) - max_rows))
    visible_events = events[start_idx : start_idx + max_rows]

    for i, evt in enumerate(visible_events, start=start_idx + 1):
        is_selected = (i - 1) == selected_idx
        prefix = "▶ " if is_selected else f"{i} "
        row_style = "on #1e293b" if is_selected else None

        ts = (evt.get("timestamp") or "")[:19]
        ev_type = evt.get("event_type") or "Info"
        type_style = "red" if ev_type in ("Error", "Fault") else "dim cyan"
        proc = evt.get("process") or "—"
        src = (evt.get("source") or "")[:22]
        msg = (evt.get("message") or "")[:90]

        table.add_row(
            Text(prefix, style="bold yellow" if is_selected else "dim"),
            Text(ts),
            Text(ev_type[:8], style=type_style),
            Text(proc[:15], style="bold cyan"),
            Text(src),
            Text(msg),
            style=row_style,
        )

    return table


def render_alert_detail_panel(alert: dict, triggering_event: dict | None = None) -> Panel:
    """Render full investigative detail view for a specific alert."""
    sev = (alert.get("severity") or "low").lower()
    conf = (alert.get("confidence") or "unknown").upper()
    rule = alert.get("rule_id", "—")
    title = alert.get("title", "Untitled Alert")
    desc = alert.get("description", "No description")
    rec_action = alert.get("recommended_action", "Investigate manually.")
    fp_notes = alert.get("false_positive_notes", "None documented.")
    created = alert.get("created_at", "—")

    # Clean description from internal metadata tags if present
    desc_clean = desc.split("\n\n[Confidence:")[0].strip()

    body = Text()
    body.append("ALERT INVESTIGATION DOSSIER\n", style="bold #38bdf8 underline")
    body.append(f"Title:       {title}\n", style="bold white")
    body.append(f"Rule ID:     {rule}   ", style="bold cyan")
    body.append(f"Severity:   {sev.upper()}   ", style=f"bold {COLOR_CRITICAL if sev=='critical' else COLOR_HIGH}")
    body.append(f"Confidence: {conf}   ", style="bold yellow")
    body.append(f"Created:    {created}\n\n", style="dim")

    body.append("DETECTION REASON & IMPACT:\n", style="bold #94a3b8")
    body.append(f"{desc_clean}\n\n", style="white")

    # Evidence
    ev = alert.get("evidence")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            ev = {"raw": ev}

    if isinstance(ev, dict) and ev:
        body.append("FORENSIC EVIDENCE EXTRACTED:\n", style="bold #94a3b8")
        for k, v in ev.items():
            body.append(f"  • {k}: ", style="dim cyan")
            body.append(f"{v}\n", style="bold white")
        body.append("\n")

    body.append("RECOMMENDED SOC RESPONSE (Level 1 Playbook):\n", style="bold #38bdf8")
    body.append(f"{rec_action}\n\n", style="green")

    body.append("FALSE POSITIVE NOTES & TUNING ADVICE:\n", style="bold #eab308")
    body.append(f"{fp_notes}\n", style="dim yellow")

    if triggering_event:
        body.append("\n" + "─" * 60 + "\n", style="dim")
        body.append("TRIGGERING EVENT INGESTED:\n", style="bold magenta")
        body.append(f"  PID: {triggering_event.get('process_id')} | Proc: {triggering_event.get('process')} | Source: {triggering_event.get('source')}\n", style="dim")
        body.append(f"  Raw: {(triggering_event.get('message') or '')[:300]}\n", style="dim white")

    return Panel(
        body,
        title=f"[bold red]🚨 ALERT #{alert.get('id', '?')}[/] - [white]{rule}[/]",
        box=box.ROUNDED,
        border_style=COLOR_CRITICAL if sev == "critical" else COLOR_HIGH,
        padding=(1, 2),
    )


def render_timeline_table(timeline_entries: list[dict], selected_idx: int = 0, max_rows: int = 15) -> Table:
    """Render unified event and alert forensic timeline."""
    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style="bold #94a3b8",
        border_style=COLOR_BORDER,
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Timestamp", style="dim", width=19)
    table.add_column("Kind", justify="center", width=8)
    table.add_column("Severity / Level", justify="center", width=14)
    table.add_column("Subject / Process", style="cyan", width=18)
    table.add_column("Event / Alert Title", style="white", ratio=3)

    if not timeline_entries:
        table.add_row("—", "—", "—", "—", "—", "[dim]No timeline entries recorded.[/]")
        return table

    start_idx = max(0, min(selected_idx - max_rows // 2, len(timeline_entries) - max_rows))
    visible = timeline_entries[start_idx : start_idx + max_rows]

    for i, item in enumerate(visible, start=start_idx + 1):
        is_selected = (i - 1) == selected_idx
        prefix = "▶ " if is_selected else f"{i} "
        row_style = "on #1e293b" if is_selected else None

        ts = (item.get("ts_sort") or "")[:19]
        kind = item.get("kind", "event")
        kind_badge = Text("ALERT", style="bold red") if kind == "alert" else Text("EVENT", style="dim cyan")
        sev = item.get("severity", "Info")
        proc = item.get("process") or "—"
        title = item.get("title") or ""

        table.add_row(
            Text(prefix, style="bold yellow" if is_selected else "dim"),
            Text(ts),
            kind_badge,
            Text(sev[:12], style="bold yellow" if kind == "alert" else "dim"),
            Text(proc[:16], style="bold cyan"),
            Text(title[:80], style="bold white" if is_selected else "white"),
            style=row_style,
        )

    return table


def render_footer(status_text: str = "", help_hint: str = "") -> Panel:
    """Render footer navigation bar."""
    text = Text()
    text.append(" [↑/↓ or j/k] Navigate  ", style="bold white")
    text.append(" [Enter] Inspect/Action  ", style="bold white")
    text.append(" [R] Refresh  ", style="bold cyan")
    text.append(" [/] Search/Filter  ", style="bold yellow")
    text.append(" [Esc] Back  ", style="dim")
    if help_hint:
        text.append(f" |  {help_hint}", style="italic dim")

    return Panel(
        text,
        box=box.ROUNDED,
        border_style=COLOR_BORDER,
        padding=(0, 1),
        subtitle=f"[bold #38bdf8]{status_text}[/]" if status_text else None,
        subtitle_align="right",
    )
