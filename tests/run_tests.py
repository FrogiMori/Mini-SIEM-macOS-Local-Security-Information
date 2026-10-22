"""
tests/run_tests.py

Minimal test runner that works without pytest.
Uses Python's built-in unittest framework.

Run:
    python3 tests/run_tests.py
"""

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
import tempfile
import os


def _make_event(**kwargs) -> dict:
    base = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "host": "test-host",
        "source": "com.apple.test",
        "category": "test",
        "event_type": "Default",
        "user": "501",
        "process": "test_process",
        "process_id": 9999,
        "parent_process": None,
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "message": "A benign test log message",
        "raw_data": json.dumps({
            "processImagePath": "/Applications/TestApp.app/Contents/MacOS/TestApp",
        }),
    }
    base.update(kwargs)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Rule A Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestRuleA(unittest.TestCase):

    def setUp(self):
        from detection.rules import rule_a_persistence
        self.rule = rule_a_persistence

    def test_triggers_on_launch_agent_write(self):
        evt = _make_event(message=(
            "Load: /Users/testuser/Library/LaunchAgents/com.evil.plist "
            "created and installed"
        ))
        alert = self.rule(evt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "A001")
        self.assertEqual(alert["severity"], "high")

    def test_triggers_on_system_launch_daemon(self):
        evt = _make_event(message=(
            "/Library/LaunchDaemons/com.example.daemon.plist "
            "modified and loaded via launchctl"
        ))
        self.assertIsNotNone(self.rule(evt))

    def test_does_not_trigger_on_read_only_reference(self):
        evt = _make_event(message="Listing contents of /Library/LaunchAgents directory")
        self.assertIsNone(self.rule(evt))

    def test_does_not_trigger_on_unrelated_message(self):
        evt = _make_event(message="System idle. No events.")
        self.assertIsNone(self.rule(evt))

    def test_alert_has_required_fields(self):
        evt = _make_event(message=(
            "/Users/user/Library/LaunchAgents/x.plist created and installed"
        ))
        alert = self.rule(evt)
        self.assertIsNotNone(alert)
        for field in ("rule_id", "severity", "confidence", "title",
                      "description", "evidence", "recommended_action",
                      "false_positive_notes"):
            self.assertIn(field, alert, f"Missing field: {field}")


# ─────────────────────────────────────────────────────────────────────────────
# Rule B Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestRuleB(unittest.TestCase):

    def setUp(self):
        from detection.rules import rule_b_suspicious_executable
        self.rule = rule_b_suspicious_executable

    def _evt(self, path):
        return _make_event(raw_data=json.dumps({"processImagePath": path}))

    def test_triggers_on_downloads(self):
        alert = self.rule(self._evt("/Users/testuser/Downloads/malware"))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "B001")

    def test_triggers_on_tmp(self):
        self.assertIsNotNone(self.rule(self._evt("/tmp/dropper")))

    def test_triggers_on_desktop(self):
        self.assertIsNotNone(self.rule(self._evt("/Users/x/Desktop/script.sh")))

    def test_does_not_trigger_on_applications(self):
        self.assertIsNone(self.rule(self._evt("/Applications/Safari.app/Contents/MacOS/Safari")))

    def test_does_not_trigger_on_system_binaries(self):
        self.assertIsNone(self.rule(self._evt("/usr/bin/python3")))

    def test_does_not_trigger_when_no_path(self):
        self.assertIsNone(self.rule(_make_event(raw_data=json.dumps({}))))

    def test_does_not_trigger_on_invalid_raw_data(self):
        self.assertIsNone(self.rule(_make_event(raw_data="not-json")))

    def test_confidence_is_low(self):
        alert = self.rule(self._evt("/Users/user/Downloads/app"))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["confidence"], "low")


# ─────────────────────────────────────────────────────────────────────────────
# Rule C Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestRuleC(unittest.TestCase):

    def setUp(self):
        from detection.rules import rule_c_input_monitoring
        self.rule = rule_c_input_monitoring

    def test_triggers_on_cgeventtap(self):
        evt = _make_event(
            source="com.apple.security",
            message="CGEventTap created for kCGEventKeyDown by process 1234",
        )
        alert = self.rule(evt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "C001")
        self.assertEqual(alert["severity"], "high")

    def test_triggers_on_tcc_accessibility(self):
        evt = _make_event(
            source="com.apple.TCC",
            message="Access granted: kTCCServiceAccessibility for bundle com.example.app",
        )
        alert = self.rule(evt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["confidence"], "medium")

    def test_triggers_on_iohidmanager(self):
        evt = _make_event(message="IOHIDManager created for keyboard event monitoring")
        self.assertIsNotNone(self.rule(evt))

    def test_does_not_trigger_on_unrelated_message(self):
        evt = _make_event(message="User logged in successfully")
        self.assertIsNone(self.rule(evt))

    def test_confidence_lower_without_security_subsystem(self):
        evt = _make_event(source="com.example.app", message="CGEventTap created")
        alert = self.rule(evt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["confidence"], "low")


# ─────────────────────────────────────────────────────────────────────────────
# Rule D Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestRuleD(unittest.TestCase):

    def setUp(self):
        from detection.rules import rule_d_process_network
        self.rule = rule_d_process_network

    def test_triggers_on_suspicious_path_with_network(self):
        evt = _make_event(
            raw_data=json.dumps({"processImagePath": "/Users/x/Downloads/spy"}),
            message="TCP connect to 203.0.113.1:443 established",
        )
        alert = self.rule(evt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "D001")

    def test_does_not_trigger_on_safe_path_with_network(self):
        evt = _make_event(
            raw_data=json.dumps({"processImagePath": "/Applications/Firefox.app/Contents/MacOS/firefox"}),
            message="HTTP connect established",
        )
        self.assertIsNone(self.rule(evt))

    def test_does_not_trigger_without_network_keywords(self):
        evt = _make_event(
            raw_data=json.dumps({"processImagePath": "/tmp/payload"}),
            message="File read operation completed",
        )
        self.assertIsNone(self.rule(evt))


# ─────────────────────────────────────────────────────────────────────────────
# Rule E Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestRuleE(unittest.TestCase):

    def setUp(self):
        from detection.rules import rule_e_combined_indicators
        self.rule = rule_e_combined_indicators

    def test_triggers_with_two_prior_alerts(self):
        evt = _make_event(process="evil_process")
        prior = [
            {"rule_id": "A001", "evidence": {"process": "evil_process"}},
            {"rule_id": "B001", "evidence": {"process": "evil_process"}},
        ]
        alert = self.rule(evt, prior)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "E001")
        self.assertEqual(alert["severity"], "critical")

    def test_does_not_trigger_with_only_one_prior_alert(self):
        evt = _make_event(process="proc")
        prior = [{"rule_id": "A001", "evidence": {"process": "proc"}}]
        self.assertIsNone(self.rule(evt, prior))

    def test_does_not_trigger_for_different_processes(self):
        evt = _make_event(process="proc_a")
        prior = [
            {"rule_id": "A001", "evidence": {"process": "proc_b"}},
            {"rule_id": "B001", "evidence": {"process": "proc_b"}},
        ]
        self.assertIsNone(self.rule(evt, prior))

    def test_does_not_trigger_without_process(self):
        evt = _make_event(process=None)
        prior = [
            {"rule_id": "A001", "evidence": {"process": None}},
            {"rule_id": "B001", "evidence": {"process": None}},
        ]
        self.assertIsNone(self.rule(evt, prior))

    def test_triggered_rules_in_evidence(self):
        evt = _make_event(process="target")
        prior = [
            {"rule_id": "A001", "evidence": {"process": "target"}},
            {"rule_id": "C001", "evidence": {"process": "target"}},
        ]
        alert = self.rule(evt, prior)
        self.assertIsNotNone(alert)
        self.assertIn("A001", alert["evidence"]["triggered_rules"])


# ─────────────────────────────────────────────────────────────────────────────
# Detection Engine Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestDetectionEngine(unittest.TestCase):

    def test_engine_returns_alerts_for_sample_events(self):
        from detection.engine import run_detection_on_events
        from data.sample_events import get_sample_events
        events = get_sample_events()
        alerts = run_detection_on_events(events)
        self.assertGreaterEqual(len(alerts), 3)

    def test_engine_handles_empty_event_list(self):
        from detection.engine import run_detection_on_events
        self.assertEqual(run_detection_on_events([]), [])

    def test_engine_handles_malformed_events(self):
        from detection.engine import run_detection_on_events
        malformed = [
            {},
            {"message": None, "raw_data": "not-json"},
        ]
        alerts = run_detection_on_events(malformed)
        self.assertIsInstance(alerts, list)

    def test_benign_event_no_high_confidence_alert(self):
        from detection.engine import run_detection_on_events
        benign = [_make_event(
            message="User logged in",
            source="com.apple.loginwindow",
            raw_data=json.dumps({
                "processImagePath": "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
            }),
        )]
        alerts = run_detection_on_events(benign)
        high_conf = [a for a in alerts if a.get("confidence") in ("high", "medium")]
        self.assertEqual(len(high_conf), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Risk Scoring Stability
# ─────────────────────────────────────────────────────────────────────────────
class TestRiskScoring(unittest.TestCase):

    def test_persistence_severity_stable(self):
        from detection.rules import rule_a_persistence
        evt = _make_event(message="/Users/u/Library/LaunchAgents/x.plist created and installed")
        for _ in range(5):
            alert = rule_a_persistence(evt)
            self.assertIsNotNone(alert)
            self.assertEqual(alert["severity"], "high")

    def test_input_monitoring_severity_stable(self):
        from detection.rules import rule_c_input_monitoring
        evt = _make_event(source="com.apple.TCC", message="kTCCServiceListenEvent granted")
        for _ in range(5):
            alert = rule_c_input_monitoring(evt)
            self.assertIsNotNone(alert)
            self.assertEqual(alert["severity"], "high")


# ─────────────────────────────────────────────────────────────────────────────
# Parser Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestParser(unittest.TestCase):

    def test_normalize_event_basic(self):
        from parser.macos import normalize_event
        raw = {
            "timestamp": "2026-01-01T00:00:00Z",
            "processImagePath": "/usr/bin/python3",
            "processID": 100,
            "userID": 501,
            "subsystem": "com.apple.test",
            "messageType": "Info",
            "eventMessage": "Test",
        }
        result = normalize_event(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["process"], "python3")
        self.assertEqual(result["process_id"], 100)

    def test_normalize_event_handles_empty(self):
        from parser.macos import normalize_event
        self.assertIsNotNone(normalize_event({}))

    def test_normalize_event_handles_none(self):
        from parser.macos import normalize_event
        self.assertIsNone(normalize_event(None))

    def test_normalize_process(self):
        from parser.macos import normalize_process
        raw = {"pid": 42, "ppid": 1, "user": "root", "cpu_pct": "0.1", "mem_pct": "0.5", "command": "bash"}
        result = normalize_process(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["process"], "bash")

    def test_normalize_launch_item(self):
        from parser.macos import normalize_launch_item
        raw = {
            "path": "/Library/LaunchAgents/com.test.plist",
            "directory": "/Library/LaunchAgents",
            "filename": "com.test.plist",
            "label": "com.test",
            "program_args": ["/usr/local/bin/test"],
            "run_at_load": True,
            "collected_at": "2026-01-01T00:00:00+00:00",
        }
        result = normalize_launch_item(raw)
        self.assertIsNotNone(result)
        self.assertIn("run_at_load=True", result["message"])


# ─────────────────────────────────────────────────────────────────────────────
# Storage Tests (temp DB)
# ─────────────────────────────────────────────────────────────────────────────
class TestStorage(unittest.TestCase):

    def setUp(self):
        import storage.database as db_module
        self._orig_path = db_module.DB_PATH
        self._tmp = tempfile.mkdtemp()
        db_module.DB_PATH = Path(self._tmp) / "test.db"
        db_module.init_database()
        self.db = db_module

    def tearDown(self):
        self.db.DB_PATH = self._orig_path
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _sample_event(self):
        return {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "host": "test", "source": "test", "category": "test",
            "event_type": "Info", "user": "501", "process": "test",
            "process_id": 1, "parent_process": None,
            "source_ip": None, "destination_ip": None, "destination_port": None,
            "message": "Hello", "raw_data": "{}",
        }

    def test_insert_and_retrieve(self):
        count = self.db.insert_events([self._sample_event()])
        self.assertEqual(count, 1)
        events = self.db.get_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["message"], "Hello")

    def test_empty_batch_returns_zero(self):
        self.assertEqual(self.db.insert_events([]), 0)

    def test_db_stats_empty(self):
        stats = self.db.get_db_stats()
        self.assertEqual(stats["event_count"], 0)
        self.assertEqual(stats["alert_count"], 0)

    def test_insert_alert(self):
        self.db.insert_events([self._sample_event()])
        events = self.db.get_events(limit=1)
        alert = {
            "severity": "high",
            "confidence": "medium",
            "rule_id": "A001",
            "title": "Test Alert",
            "description": "Test desc",
            "evidence": {"process": "test"},
            "recommended_action": "Do something",
            "false_positive_notes": "Maybe benign",
            "event_id": events[0]["id"],
        }
        aid = self.db.insert_alert(alert)
        self.assertIsNotNone(aid)
        alerts = self.db.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "A001")


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestTimeline(unittest.TestCase):

    def test_build_timeline_merges(self):
        from investigation.timeline import build_timeline
        events = [{"timestamp": "2026-01-01T01:00:00Z", "process": "p",
                   "message": "m", "event_type": "Info", "source": "s"}]
        alerts = [{"created_at": "2026-01-01T00:30:00Z", "severity": "high",
                   "title": "Alert", "description": "d", "rule_id": "A001",
                   "evidence": {"process": "p"}}]
        tl = build_timeline(events, alerts)
        self.assertEqual(len(tl), 2)
        self.assertEqual(tl[0]["kind"], "alert")  # earlier

    def test_build_timeline_empty(self):
        from investigation.timeline import build_timeline
        self.assertEqual(build_timeline([], []), [])

    def test_generate_report_returns_string(self):
        from investigation.timeline import generate_report
        report = generate_report(None, [], [], None)
        self.assertIn("MINI-SIEM", report)

    def test_generate_report_with_alerts(self):
        from investigation.timeline import generate_report
        alerts = [{
            "severity": "high", "confidence": "medium", "rule_id": "A001",
            "title": "Test Alert", "description": "Desc", "created_at": "2026-01-01",
            "recommended_action": "Do something", "false_positive_notes": "Benign",
            "evidence": {"process": "p"},
        }]
        report = generate_report(1, [], alerts, None)
        self.assertIn("Test Alert", report)
        self.assertIn("A001", report)


# ─────────────────────────────────────────────────────────────────────────────
# Collector Parser Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestCollectorParser(unittest.TestCase):

    def test_parse_logs_empty(self):
        from collector.macos import parse_logs
        self.assertEqual(parse_logs(""), [])

    def test_parse_logs_no_json(self):
        from collector.macos import parse_logs
        self.assertEqual(parse_logs("Not JSON"), [])

    def test_parse_logs_valid_array(self):
        from collector.macos import parse_logs
        raw = json.dumps([{"timestamp": "t", "eventMessage": "Hello"}])
        events = parse_logs(raw)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["eventMessage"], "Hello")

    def test_parse_logs_partial_json(self):
        from collector.macos import parse_logs
        raw = '[{"timestamp":"t1","eventMessage":"ok"},{"timestamp":"t2","eventMe'
        events = parse_logs(raw)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["eventMessage"], "ok")


# ─────────────────────────────────────────────────────────────────────────────
# Sample Events Tests
# ─────────────────────────────────────────────────────────────────────────────
class TestSampleEvents(unittest.TestCase):

    def test_sample_events_returns_list(self):
        from data.sample_events import get_sample_events
        events = get_sample_events()
        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)

    def test_sample_events_have_required_fields(self):
        from data.sample_events import get_sample_events
        for evt in get_sample_events():
            self.assertIn("timestamp", evt)
            self.assertIn("message", evt)
            self.assertIn("raw_data", evt)

    def test_simulation_generates_alerts(self):
        from data.sample_events import get_sample_events
        from detection.engine import run_detection_on_events
        events = get_sample_events()
        alerts = run_detection_on_events(events)
        self.assertGreater(len(alerts), 0)

    def test_benign_sample_event_not_alerted(self):
        """The Finder move event (S6) should not trigger any rule."""
        from data.sample_events import get_sample_events
        from detection.engine import run_detection_on_events
        events = get_sample_events()
        # S6 is the Finder event — message is "File moved: ..."
        finder_events = [e for e in events if e.get("process") == "Finder"]
        self.assertGreater(len(finder_events), 0, "Expected Finder event in samples")
        alerts = run_detection_on_events(finder_events)
        self.assertEqual(len(alerts), 0, f"Finder event should not alert, but got: {alerts}")


if __name__ == "__main__":
    from tests.test_tui import TestTUIComponents, TestTUIApplication

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    for cls in [
        TestRuleA, TestRuleB, TestRuleC, TestRuleD, TestRuleE,
        TestDetectionEngine, TestRiskScoring,
        TestParser, TestStorage, TestTimeline,
        TestCollectorParser, TestSampleEvents,
        TestTUIComponents, TestTUIApplication,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
