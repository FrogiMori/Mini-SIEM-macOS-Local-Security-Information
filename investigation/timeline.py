"""
investigation/timeline.py

Builds forensic timelines and incident reports for Mini-SIEM.

Public API:
    build_timeline(events: list[dict], alerts: list[dict]) -> list[dict]
    generate_report(incident_id: int | None, events: list[dict],
                    alerts: list[dict], system_info: dict | None) -> str
    get_investigation_summary(limit_events: int = 500) -> dict
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Timeline builder
# ---------------------------------------------------------------------------

def build_timeline(events: list[dict], alerts: list[dict]) -> list[dict]:
    """
    Merge events and alerts into a unified chronological timeline.

    Each timeline entry has:
        ts_sort  – comparable timestamp string (for sorting)
        kind     – 'event' | 'alert'
        severity – severity level (alerts) or event_type (events)
        title    – short description
        detail   – full description or message
        source   – origin subsystem / rule_id
        process  – related process name (if available)
        raw      – the original dict
    """
    timeline: list[dict] = []

    for evt in events:
        ts = evt.get("timestamp") or ""
        timeline.append({
            "ts_sort":  ts,
            "kind":     "event",
            "severity": evt.get("event_type") or "Info",
            "title":    f"[{evt.get('process', '?')}] {(evt.get('message') or '')[:100]}",
            "detail":   evt.get("message") or "",
            "source":   evt.get("source") or "",
            "process":  evt.get("process"),
            "raw":      evt,
        })

    for alr in alerts:
        ts = alr.get("created_at") or alr.get("timestamp") or ""
        evidence = alr.get("evidence")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except (json.JSONDecodeError, ValueError):
                evidence = {"raw": evidence}

        timeline.append({
            "ts_sort":  ts,
            "kind":     "alert",
            "severity": alr.get("severity") or "medium",
            "title":    alr.get("title") or "Alert",
            "detail":   alr.get("description") or "",
            "source":   alr.get("rule_id") or "",
            "process":  (evidence or {}).get("process"),
            "raw":      alr,
        })

    # Sort chronologically
    timeline.sort(key=lambda x: x["ts_sort"] or "")
    return timeline


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_report(
    incident_id: int | None,
    events: list[dict],
    alerts: list[dict],
    system_info: dict | None = None,
) -> str:
    """
    Generate a plain-text incident report.

    Args:
        incident_id: Optional incident DB id (for reference).
        events:      List of related events.
        alerts:      List of related alerts.
        system_info: Optional dict from collect_system_info().

    Returns:
        Multi-line string report.
    """
    now = datetime.now(timezone.utc).isoformat()
    lines: list[str] = []

    def sep(char="─", width=72):
        lines.append(char * width)

    # Header
    sep("═")
    lines.append("  MINI-SIEM — INCIDENT INVESTIGATION REPORT")
    lines.append(f"  Generated : {now}")
    if incident_id:
        lines.append(f"  Incident  : #{incident_id}")
    sep("═")

    # System info
    if system_info:
        lines.append("")
        lines.append("SYSTEM INFORMATION")
        sep()
        for k, v in system_info.items():
            if v is not None:
                lines.append(f"  {k:<20} {v}")

    # Executive summary
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    sep()
    lines.append(f"  Events analysed : {len(events)}")
    lines.append(f"  Alerts generated: {len(alerts)}")

    by_sev: dict[str, int] = {}
    for alr in alerts:
        sev = (alr.get("severity") or "unknown").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1

    for sev in ("critical", "high", "medium", "low"):
        if sev in by_sev:
            lines.append(f"    {sev.upper():<10} {by_sev[sev]}")

    # Alerts detail
    lines.append("")
    lines.append("ALERTS")
    sep()

    sorted_alerts = sorted(
        alerts,
        key=lambda a: _SEVERITY_ORDER.get((a.get("severity") or "low").lower(), 99),
    )

    for i, alr in enumerate(sorted_alerts, 1):
        lines.append(f"\n  [{i}] [{alr.get('severity', '?').upper()}] {alr.get('title', 'Untitled')}")
        lines.append(f"      Rule      : {alr.get('rule_id', '?')}")
        lines.append(f"      Confidence: {alr.get('confidence', '?')}")
        lines.append(f"      Timestamp : {alr.get('created_at') or alr.get('timestamp', '?')}")

        desc = alr.get("description") or ""
        # Strip embedded metadata lines from description if present
        desc_clean = desc.split("\n\n[Confidence:")[0].strip()
        if desc_clean:
            for dline in _wrap(desc_clean, 64):
                lines.append(f"      {dline}")

        evidence = alr.get("evidence")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except (json.JSONDecodeError, ValueError):
                evidence = None
        if isinstance(evidence, dict):
            lines.append("      Evidence  :")
            for k, v in evidence.items():
                lines.append(f"        {k}: {v}")

        action = alr.get("recommended_action") or ""
        if action:
            lines.append("      Recommended Action:")
            for aline in _wrap(action, 64):
                lines.append(f"        {aline}")

        fp = alr.get("false_positive_notes") or ""
        if fp:
            lines.append("      False Positive Notes:")
            for fline in _wrap(fp, 64):
                lines.append(f"        {fline}")

    # Timeline snippet (first 20 entries)
    lines.append("")
    lines.append("TIMELINE (chronological, first 20 entries)")
    sep()
    timeline = build_timeline(events[:200], alerts)
    for entry in timeline[:20]:
        kind_tag = "ALERT" if entry["kind"] == "alert" else "EVENT"
        ts = (entry["ts_sort"] or "")[:19]
        lines.append(f"  {ts}  [{kind_tag}]  {entry['title'][:70]}")

    # Footer
    lines.append("")
    sep("═")
    lines.append("  NOTE: This report is for educational and training purposes.")
    lines.append("  Do not treat automated alerts as confirmed threats without")
    lines.append("  human review. False positives are expected in any SIEM.")
    sep("═")

    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    """Simple word-wrap."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            if current:
                lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    return lines or [""]


# ---------------------------------------------------------------------------
# High-level summary helper (used by dashboard and main.py)
# ---------------------------------------------------------------------------

def get_investigation_summary(limit_events: int = 500) -> dict:
    """
    Load recent events and alerts from the DB and return a summary dict
    suitable for the dashboard or CLI display.
    """
    from storage.database import get_events, get_alerts, get_alert_count_by_severity, get_db_stats

    try:
        stats = get_db_stats()
        events = get_events(limit=limit_events)
        alerts = get_alerts(limit=200)
        severity_counts = get_alert_count_by_severity()
        timeline = build_timeline(events[:100], alerts[:50])
    except Exception as exc:  # noqa: BLE001
        logger.error("get_investigation_summary error: %s", exc)
        return {"error": str(exc)}

    return {
        "stats": stats,
        "recent_events": events[:50],
        "alerts": alerts,
        "severity_counts": severity_counts,
        "timeline": timeline[:100],
    }
