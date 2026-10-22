"""
tui/theme.py

Styles, icons, and color palette for the Mini-SIEM Terminal User Interface.
"""

from rich.style import Style
from rich.text import Text

# Palette definitions
COLOR_BG = "#0d1117"
COLOR_SURFACE = "#161b22"
COLOR_BORDER = "#30363d"
COLOR_TEXT = "#c9d1d9"
COLOR_MUTED = "#8b949e"

COLOR_CRITICAL = "#ff4444"
COLOR_HIGH = "#ff8c00"
COLOR_MEDIUM = "#e3b341"
COLOR_LOW = "#3fb950"
COLOR_INFO = "#58a6ff"
COLOR_ACCENT = "#38bdf8"
COLOR_PURPLE = "#c084fc"

# Severities map
SEVERITY_COLORS = {
    "critical": COLOR_CRITICAL,
    "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM,
    "low": COLOR_LOW,
    "info": COLOR_INFO,
    "open": COLOR_CRITICAL,
    "investigating": COLOR_MEDIUM,
    "closed": COLOR_LOW,
}

SEVERITY_ICONS = {
    "critical": "☠ [bold red]CRIT[/]",
    "high": "🔥 [bold orange3]HIGH[/]",
    "medium": "⚡ [bold yellow]MED[/]",
    "low": "🛡 [bold green]LOW[/]",
    "info": "ℹ [bold cyan]INFO[/]",
}


def badge_severity(severity: str) -> Text:
    """Return a styled Rich Text badge for severity."""
    s = (severity or "low").lower()
    color = SEVERITY_COLORS.get(s, COLOR_MUTED)
    label = s.upper()
    return Text(f" {label} ", style=f"bold white on {color}")


def badge_rule(rule_id: str) -> Text:
    """Format Rule ID badge."""
    return Text(f"[{rule_id}]", style="bold cyan")


def badge_status(status: str) -> Text:
    """Format alert status badge."""
    st = (status or "open").lower()
    if st == "open":
        return Text("● OPEN", style="bold red")
    elif st == "investigating":
        return Text("◐ IN-REVIEW", style="bold yellow")
    return Text("○ CLOSED", style="dim green")
