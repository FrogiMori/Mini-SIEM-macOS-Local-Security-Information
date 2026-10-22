"""
tests/test_tui.py

Unit tests for Mini-SIEM Terminal User Interface (TUI).
"""

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tui.app import FrogiSIEMApp
from tui.state import FrogiSIEMState
from tui.components import (
    render_alert_detail_panel,
    render_alerts_table,
    render_events_table,
    render_footer,
    render_header,
    render_metrics_cards,
    render_timeline_table,
)
from tui.theme import badge_rule, badge_severity, badge_status


class TestTUIComponents(unittest.TestCase):
    """Test individual rendering functions in tui.components."""

    def test_badges(self):
        b1 = badge_severity("critical")
        self.assertIn("CRITICAL", b1.plain)

        b2 = badge_severity("high")
        self.assertIn("HIGH", b2.plain)

        b3 = badge_rule("A001")
        self.assertIn("A001", b3.plain)

        b4 = badge_status("open")
        self.assertIn("OPEN", b4.plain)

    def test_render_header(self):
        info = {"hostname": "macbook-test", "os_version": "15.0", "architecture": "arm64"}
        panel = render_header(info, active_tab="overview", status_msg="TEST")
        self.assertIsNotNone(panel)

    def test_render_metrics_cards(self):
        stats = {"event_count": 100, "alert_count": 5}
        sevs = {"critical": 1, "high": 2, "medium": 1, "low": 1}
        cards = render_metrics_cards(stats, sevs)
        self.assertIsNotNone(cards)

    def test_render_alerts_table_empty(self):
        table = render_alerts_table([])
        self.assertIsNotNone(table)

    def test_render_alerts_table_populated(self):
        alerts = [{
            "id": 1,
            "severity": "high",
            "confidence": "medium",
            "rule_id": "A001",
            "created_at": "2026-01-01T00:00:00Z",
            "title": "Persistence Test",
            "status": "open",
            "evidence": {"process": "test_app"},
        }]
        table = render_alerts_table(alerts, selected_idx=0)
        self.assertIsNotNone(table)

    def test_render_events_table(self):
        events = [{
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "Default",
            "process": "launchd",
            "source": "com.apple.launchd",
            "message": "Loaded plist",
        }]
        table = render_events_table(events)
        self.assertIsNotNone(table)

    def test_render_alert_detail_panel(self):
        alert = {
            "id": 42,
            "severity": "critical",
            "confidence": "high",
            "rule_id": "E001",
            "title": "Correlated Attack",
            "description": "Multi-indicator match",
            "recommended_action": "Quarantine host",
            "false_positive_notes": "Unlikely benign",
            "created_at": "2026-01-01T00:00:00Z",
            "evidence": {"process": "malware", "alert_count": 3},
        }
        panel = render_alert_detail_panel(alert, triggering_event={"message": "Raw log line"})
        self.assertIsNotNone(panel)

    def test_render_timeline_table(self):
        timeline = [{
            "ts_sort": "2026-01-01T00:00:00Z",
            "kind": "alert",
            "severity": "critical",
            "process": "proc",
            "title": "Alert 1",
        }]
        table = render_timeline_table(timeline)
        self.assertIsNotNone(table)

    def test_render_footer(self):
        panel = render_footer(status_text="OK", help_hint="Help text")
        self.assertIsNotNone(panel)


class TestFrogiSIEMState(unittest.TestCase):
    """Test full FrogiSIEM state management and data operations."""

    def setUp(self):
        self.state = FrogiSIEMState()

    def test_init_state(self):
        self.assertIsNotNone(self.state.stats)
        self.assertIsInstance(self.state.alerts, list)
        self.assertIsInstance(self.state.events, list)
        self.assertIsInstance(self.state.timeline, list)
        self.assertEqual(self.state.collector_status, "ONLINE")

    def test_report_generation(self):
        rep = self.state.get_incident_report()
        self.assertIsInstance(rep, str)
        self.assertIn("INCIDENT INVESTIGATION REPORT", rep)

    def test_state_reload(self):
        self.state.reload()
        self.assertIsNotNone(self.state.stats)


if __name__ == "__main__":
    unittest.main(verbosity=2)
