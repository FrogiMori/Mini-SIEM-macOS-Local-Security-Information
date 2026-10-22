"""
tui/widgets/event_dossier.py

Selected Event & Investigation Dossier Widget.
Displays:
  - Event ID, Timestamp, Source, Severity
  - Normalized fields (user, process, process_id, parent_process, category)
  - Original raw event data (formatted JSON)
  - Detection rule triggered (if any) and reason
  - Investigation triage notes & response playbook
"""

from __future__ import annotations

import json
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Static


class EventDossierPanel(Widget):
    """Investigation dossier showing details of a selected event or alert."""

    DEFAULT_CSS = """
    EventDossierPanel {
        height: 100%;
        background: #0b0f19;
        border: round #334155;
        padding: 1;
    }
    .dossier-scroll {
        height: 1fr;
    }
    .dossier-title {
        color: #00ff66;
        text-style: bold;
        margin-bottom: 1;
        border-bottom: solid #1e293b;
        padding-bottom: 1;
    }
    """

    def __init__(self, event_data: dict | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.event_data = event_data

    def compose(self) -> ComposeResult:
        yield Static("[bold #00ff66]🔍 SELECTED EVENT INVESTIGATION DOSSIER[/]", classes="dossier-title")
        with VerticalScroll(classes="dossier-scroll"):
            yield Static(self._build_content(), id="dossier-content")

    def set_event(self, event_data: dict | None) -> None:
        """Update dossier with newly selected event."""
        self.event_data = event_data
        try:
            content = self.query_one("#dossier-content", Static)
            content.update(self._build_content())
        except Exception:
            pass

    def _build_content(self) -> str:
        if not self.event_data:
            return (
                "[dim italic #64748b]Select any row in the Event Log Stream or Alerts Console "
                "(using keyboard arrows or Enter) to inspect forensic telemetry.[/]"
            )

        evt = self.event_data
        eid = evt.get("id") or "N/A"
        ts = evt.get("timestamp") or "Unknown"
        src = evt.get("source") or "Unknown"
        cat = evt.get("category") or "—"
        etype = evt.get("event_type") or "Info"
        user = evt.get("user") or "—"
        proc = evt.get("process") or "—"
        pid = evt.get("process_id") or "—"
        ppid = evt.get("parent_process") or "—"
        msg = evt.get("message") or "—"
        raw_str = evt.get("raw_data") or "{}"

        # Severity color
        sev_color = "#ef4444" if etype in ("Error", "Fault") else ("#f59e0b" if etype == "Default" else "#00ff66")

        lines = [
            f"[bold #f8fafc]EVENT ID:[/]       [bold cyan]#{eid}[/]   [bold #f8fafc]TIMESTAMP:[/] [dim]{ts}[/]",
            f"[bold #f8fafc]SOURCE:[/]         [bold #38bdf8]{src}[/]",
            f"[bold #f8fafc]CATEGORY:[/]       [dim white]{cat}[/]",
            f"[bold #f8fafc]EVENT TYPE:[/]     [bold {sev_color}]{etype}[/]",
            "",
            "[bold #94a3b8 underline]NORMALIZED IDENTITY & PROCESS EXECUTION:[/]",
            f" • User ID:       [bold white]{user}[/]",
            f" • Process:       [bold #00ff66]{proc}[/] (PID: {pid})",
            f" • Parent Process: [dim]{ppid}[/]",
            "",
            "[bold #94a3b8 underline]HUMAN READABLE LOG MESSAGE:[/]",
            f"[white]{msg}[/]",
            "",
        ]

        # Check for Alert / Detection Rule Match
        rule_id = evt.get("rule_id")
        rule_desc = evt.get("description")
        rec_action = evt.get("recommended_action")
        if rule_id:
            lines.extend([
                "[bold red underline]TRIGGERED DETECTION RULE:[/]",
                f" • Rule:   [bold cyan]{rule_id}[/] ([bold red]{evt.get('severity','?').upper()}[/])",
                f" • Title:  [bold white]{evt.get('title','—')}[/]",
                f" • Reason: [white]{rule_desc or '—'}[/]",
                "",
                "[bold #00ff66 underline]RECOMMENDED SOC PLAYBOOK (L1):[/]",
                f"[green]{rec_action or 'Investigate process and quarantine if malicious.'}[/]",
                "",
            ])

        # Raw Telemetry Preview (Safe formatting, redact if needed)
        try:
            raw_obj = json.loads(raw_str)
            formatted_json = json.dumps(raw_obj, indent=2, ensure_ascii=False)
        except Exception:
            formatted_json = raw_str

        # Truncate raw JSON preview to avoid lagging terminal
        if len(formatted_json) > 1200:
            formatted_json = formatted_json[:1200] + "\n... [truncated for display]"

        lines.extend([
            "[bold #94a3b8 underline]RAW TELEMETRY PAYLOAD:[/]",
            f"[dim #64748b]{formatted_json}[/]",
        ])

        return "\n".join(lines)
