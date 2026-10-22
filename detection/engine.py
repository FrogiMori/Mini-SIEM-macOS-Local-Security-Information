"""
detection/engine.py

Detection engine for Mini-SIEM.

Runs all detection rules against events retrieved from the database,
persists alerts, and returns the alert list.

Public API:
    run_detection(events: list[dict] | None = None) -> list[dict]
    run_detection_on_events(events: list[dict]) -> list[dict]
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def run_detection_on_events(events: list[dict]) -> list[dict]:
    """
    Run all detection rules against the provided event list.
    Does NOT write to the database — returns raw alert dicts.

    Args:
        events: List of normalized event dicts (may or may not have 'id').

    Returns:
        List of alert dicts with 'evidence' as a dict (not JSON string).
    """
    from detection.rules import PER_EVENT_RULES, rule_e_combined_indicators

    all_alerts: list[dict] = []

    for event in events:
        for rule_fn in PER_EVENT_RULES:
            try:
                alert = rule_fn(event)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Rule %s raised an exception: %s", rule_fn.__name__, exc)
                alert = None

            if alert is not None:
                all_alerts.append(alert)

        # Rule E: multi-indicator correlation after per-event rules
        try:
            e_alert = rule_e_combined_indicators(event, all_alerts)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Rule E raised an exception: %s", exc)
            e_alert = None

        if e_alert is not None:
            all_alerts.append(e_alert)

    logger.info("Detection engine: %d alert(s) from %d event(s)", len(all_alerts), len(events))
    return all_alerts


def run_detection(events: list[dict] | None = None) -> list[dict]:
    """
    Full detection pipeline:
      1. Load events from the database (or use the provided list).
      2. Run all detection rules.
      3. Persist new alerts to the database.
      4. Return the list of new alerts.

    Args:
        events: If provided, use these events instead of querying the DB.
                Events must already have an 'id' field (DB row id).

    Returns:
        List of newly inserted alert dicts.
    """
    from storage.database import get_events, insert_alert

    if events is None:
        events = get_events(limit=10_000)
        logger.info("Loaded %d events from database for detection", len(events))

    raw_alerts = run_detection_on_events(events)

    if not raw_alerts:
        logger.info("No alerts generated.")
        return []

    # Deduplicate: avoid re-alerting the same rule on the same event
    existing_keys: set[tuple] = _load_existing_alert_keys()

    new_alerts: list[dict] = []
    for alert in raw_alerts:
        key = (alert.get("rule_id"), alert.get("event_id"))
        if key in existing_keys:
            continue

        # Serialize evidence dict → JSON string for storage
        db_alert = _prepare_for_db(alert)
        try:
            alert_id = insert_alert(db_alert)
            alert["id"] = alert_id
            new_alerts.append(alert)
            existing_keys.add(key)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to insert alert %s: %s", alert.get("rule_id"), exc)

    logger.info(
        "Detection complete: %d new alert(s) (of %d generated, %d deduplicated)",
        len(new_alerts),
        len(raw_alerts),
        len(raw_alerts) - len(new_alerts),
    )
    return new_alerts


def _load_existing_alert_keys() -> set[tuple]:
    """Load (rule_id, event_id) pairs already in the database."""
    try:
        from storage.database import get_alerts
        alerts = get_alerts(limit=100_000)
        return {(a.get("rule_id"), a.get("event_id")) for a in alerts}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load existing alerts for deduplication: %s", exc)
        return set()


def _prepare_for_db(alert: dict) -> dict:
    """
    Convert an alert dict to the format expected by storage.database.insert_alert.
    All alert fields are passed directly; evidence dict is kept as a dict
    (insert_alert serializes it to JSON internally).
    """
    return {
        "rule_id":              alert["rule_id"],
        "severity":             alert["severity"],
        "confidence":           alert.get("confidence"),
        "title":                alert["title"],
        "description":          alert.get("description"),
        "evidence":             alert.get("evidence", {}),
        "recommended_action":   alert.get("recommended_action"),
        "false_positive_notes": alert.get("false_positive_notes"),
        "status":               alert.get("status", "open"),
        "event_id":             alert.get("event_id"),
    }
