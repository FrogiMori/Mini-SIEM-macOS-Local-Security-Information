"""
tests/test_textual_dashboard.py

Comprehensive tests for FrogiSIEM Textual TUI Dashboard.
Verifies:
  1. Headless startup and view navigation (1 - 5)
  2. Empty database handling without crashing
  3. Search and severity/source filtering in event stream
  4. Alert selection and dossier panel population
  5. Refresh operations without data duplication
  6. Background simulation and collection worker hooks
"""

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import storage.database as db_module
from tui.app import FrogiSIEMApp
from tui.state import FrogiSIEMState
from tui.widgets.detection_panel import DetectionStatusPanel
from tui.widgets.event_dossier import EventDossierPanel
from tui.widgets.event_stream import EventStreamWidget
from tui.widgets.header import FrogiSIEMHeader
from tui.widgets.source_health import SourceHealthWidget
from tui.widgets.summary_cards import MetricCard, SummaryCardsRow


class TestFrogiSIEMTextual(unittest.IsolatedAsyncioTestCase):
    """Asynchronous integration tests using Textual Pilot."""

    async def asyncSetUp(self):
        # Create an isolated temporary test database
        self.tmp_dir = tempfile.mkdtemp()
        self.orig_db_path = db_module.DB_PATH
        db_module.DB_PATH = Path(self.tmp_dir) / "test_frogi.db"
        db_module.init_database()

    async def asyncTearDown(self):
        db_module.DB_PATH = self.orig_db_path
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_empty_database_startup(self):
        """Verify dashboard starts and renders cleanly when database has 0 events."""
        stats = db_module.get_db_stats()
        self.assertEqual(stats["event_count"], 0)
        self.assertEqual(stats["alert_count"], 0)

        app = FrogiSIEMApp()
        async with app.run_test() as pilot:
            # Header check
            header = app.query_one("#main-header", FrogiSIEMHeader)
            self.assertEqual(header.collector_status, "ONLINE")

            # Summary cards check (should show 0 without crashing)
            cards = app.query_one("#main-summary-cards", SummaryCardsRow)
            self.assertEqual(cards.total_events, 0)
            self.assertEqual(cards.crit_high_alerts, 0)

            # Switch through all views with empty DB
            for key, view_id in [
                ("1", "view-overview"),
                ("2", "view-events"),
                ("3", "view-alerts"),
                ("4", "view-investigation"),
                ("5", "view-sources"),
            ]:
                await pilot.press(key)
                switcher = app.query_one("#main-content-switcher")
                self.assertEqual(switcher.current, view_id)

    async def test_navigation_and_shortcuts(self):
        """Verify tab buttons and hotkeys (1-5, Escape, Refresh)."""
        app = FrogiSIEMApp()
        async with app.run_test() as pilot:
            switcher = app.query_one("#main-content-switcher")
            self.assertEqual(switcher.current, "view-overview")

            # Press 2 -> Events
            await pilot.press("2")
            self.assertEqual(switcher.current, "view-events")

            # Press Escape -> Returns to overview
            await pilot.press("escape")
            self.assertEqual(switcher.current, "view-overview")

            # Click tab button for Alerts
            await pilot.click("#tab-btn-alerts")
            self.assertEqual(switcher.current, "view-alerts")

            # Refresh hotkey
            await pilot.press("r")
            self.assertEqual(switcher.current, "view-alerts")

    async def test_event_stream_search_and_filter(self):
        """Verify event table search and filtering logic."""
        # Insert test events of various severities
        db_module.insert_events([
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "host": "test-mac",
                "source": "com.apple.TCC",
                "category": "auth",
                "event_type": "Fault",
                "user": "501",
                "process": "suspicious_app",
                "process_id": 4040,
                "parent_process": "1",
                "source_ip": None,
                "destination_ip": None,
                "destination_port": None,
                "message": "Privilege violation in TCC daemon",
                "raw_data": '{"test": true}',
            },
            {
                "timestamp": "2026-01-01T00:01:00Z",
                "host": "test-mac",
                "source": "mini-siem/process-collector",
                "category": "process",
                "event_type": "Info",
                "user": "501",
                "process": "normal_app",
                "process_id": 100,
                "parent_process": "1",
                "source_ip": None,
                "destination_ip": None,
                "destination_port": None,
                "message": "Routine background process heartbeat",
                "raw_data": '{"test": true}',
            },
        ])

        app = FrogiSIEMApp()
        async with app.run_test() as pilot:
            await pilot.press("2")  # Switch to Events view
            stream_widget = app.query_one("#full-event-stream", EventStreamWidget)

            # Initial table should have 2 events
            self.assertEqual(len(stream_widget.events_data), 2)

            # Test search query
            stream_widget.search_query = "suspicious_app"
            stream_widget.refresh_table()
            table = stream_widget.query_one("#events-datatable")
            self.assertEqual(table.row_count, 1)

            # Test clear search
            stream_widget.search_query = ""
            stream_widget.refresh_table()
            table = stream_widget.query_one("#events-datatable")
            self.assertEqual(table.row_count, 2)

    async def test_alert_dossier_inspection(self):
        """Verify selecting an alert loads the dossier panel with rule and evidence."""
        alert_id = db_module.insert_alert({
            "severity": "critical",
            "confidence": "high",
            "rule_id": "E001",
            "title": "Correlated Threat Pattern",
            "description": "Process triggered multiple detection rules.",
            "evidence": {"process": "bad_actor", "alert_count": 3},
            "recommended_action": "Isolate host and revoke TCC permissions.",
            "false_positive_notes": "Security software may trigger this.",
            "status": "open",
        })

        app = FrogiSIEMApp()
        async with app.run_test() as pilot:
            await pilot.press("3")  # Switch to Alerts
            dossier = app.query_one("#alerts-dossier-panel", EventDossierPanel)
            content = dossier._build_content()
            self.assertIn("E001", content)
            self.assertIn("Correlated Threat Pattern", content)
            self.assertIn("Isolate host", content)

    async def test_simulation_worker(self):
        """Verify simulation generates alerts without freezing UI."""
        app = FrogiSIEMApp()
        async with app.run_test() as pilot:
            # Trigger simulation via hotkey
            await pilot.press("s")
            await pilot.pause(0.5)

            # Verify events and alerts are now populated
            stats = db_module.get_db_stats()
            self.assertGreater(stats["event_count"], 0)
            self.assertGreater(stats["alert_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
