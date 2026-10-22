"""
tui/state.py

Thread-safe Data Store and Service Layer for FrogiSIEM.
Manages database interaction, background ingestion, detection evaluation,
and state caching for the Textual TUI.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

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

logger = logging.getLogger("frogi-siem.state")


class FrogiSIEMState:
    """Central data repository and action executor for FrogiSIEM."""

    def __init__(self) -> None:
        init_database()
        self.system_info: dict = {}
        self.stats: dict = {}
        self.severity_counts: dict = {}
        self.events: list[dict] = []
        self.alerts: list[dict] = []
        self.timeline: list[dict] = []
        self.last_collection_time: str = "Never"
        self.last_eval_time: str = "Never"
        self.collector_status: str = "ONLINE"
        self.recent_errors: int = 0
        self.reload()

    def reload(self) -> None:
        """Fetch fresh metrics, events, and alerts from SQLite."""
        try:
            self.stats = get_db_stats()
            self.severity_counts = get_alert_count_by_severity()
            self.events = get_events(limit=300)
            self.alerts = get_alerts(limit=200)
            self.timeline = build_timeline(self.events[:150], self.alerts[:100])

            if not self.system_info:
                try:
                    self.system_info = collect_system_info()
                except Exception:
                    self.system_info = {
                        "hostname": "localhost",
                        "architecture": "arm64",
                        "os_version": "macOS",
                        "current_user": "analyst",
                    }

            if self.stats.get("last_event_ts"):
                self.last_collection_time = self.stats["last_event_ts"][:19]
            if self.alerts:
                self.last_eval_time = (self.alerts[0].get("created_at") or "")[:19]

        except Exception as exc:
            logger.error("State reload failed: %s", exc)
            self.recent_errors += 1

    def harvest_live_macos_telemetry(self, minutes: int = 1) -> tuple[int, int]:
        """
        Execute live macOS collection from ULS, processes, and LaunchItems.
        Returns: (events_inserted, alerts_generated)
        """
        self.collector_status = "COLLECTING"
        try:
            raw_data = collect_all(minutes=minutes)
            normalized: list[dict] = []

            for raw in raw_data.get("log_events", []):
                n = normalize_event(raw)
                if n:
                    normalized.append(n)

            for raw in raw_data.get("processes", []):
                n = normalize_process(raw)
                if n:
                    normalized.append(n)

            for raw in raw_data.get("launch_items", []):
                n = normalize_launch_item(raw)
                if n:
                    normalized.append(n)

            inserted = insert_events(normalized)
            new_alerts = run_detection()

            self.collector_status = "ONLINE"
            self.last_collection_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            self.last_eval_time = self.last_collection_time
            self.reload()

            return inserted, len(new_alerts)

        except Exception as exc:
            logger.error("Live collection failed: %s", exc)
            self.collector_status = "ERROR"
            self.recent_errors += 1
            self.reload()
            raise

    def execute_simulation(self) -> tuple[int, int]:
        """
        Inject synthetic attack fixtures and run rule correlation.
        Returns: (events_inserted, alerts_generated)
        """
        try:
            synthetic_events = get_sample_events()
            inserted = insert_events(synthetic_events)

            stored = get_events(limit=inserted + 100)
            alerts = run_detection(stored)

            self.last_eval_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            self.reload()

            return inserted, len(alerts)

        except Exception as exc:
            logger.error("Simulation failed: %s", exc)
            self.recent_errors += 1
            self.reload()
            raise

    def get_incident_report(self) -> str:
        """Generate forensic incident report text."""
        return generate_report(
            incident_id=None,
            events=self.events[:300],
            alerts=self.alerts[:100],
            system_info=self.system_info,
        )
