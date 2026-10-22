"""
tests/test_detection.py

Unit tests for detection rules and engine.

Run:
    python3 -m pytest tests/ -v
"""

import json
import sys
from pathlib import Path

# Ensure project root is importable
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from detection.rules import (
    rule_a_persistence,
    rule_b_suspicious_executable,
    rule_c_input_monitoring,
    rule_d_process_network,
    rule_e_combined_indicators,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**kwargs) -> dict:
    """Create a minimal valid event dict, overrideable via kwargs."""
    base = {
        "timestamp":        "2026-01-01T00:00:00+00:00",
        "host":             "test-host",
        "source":           "com.apple.test",
        "category":         "test",
        "event_type":       "Default",
        "user":             "501",
        "process":          "test_process",
        "process_id":       9999,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message":          "A benign test log message",
        "raw_data":         json.dumps({
            "processImagePath": "/Applications/TestApp.app/Contents/MacOS/TestApp",
        }),
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Rule A — Persistence
# ---------------------------------------------------------------------------

class TestRuleA:

    def test_triggers_on_launch_agent_write(self):
        evt = _make_event(
            source="com.apple.launchd",
            message=(
                "Load: /Users/testuser/Library/LaunchAgents/com.evil.plist "
                "created and installed"
            ),
        )
        alert = rule_a_persistence(evt)
        assert alert is not None
        assert alert["rule_id"] == "A001"
        assert alert["severity"] == "high"

    def test_triggers_on_system_launch_daemon(self):
        evt = _make_event(
            message=(
                "/Library/LaunchDaemons/com.example.daemon.plist "
                "modified and loaded via launchctl"
            ),
        )
        alert = rule_a_persistence(evt)
        assert alert is not None
        assert alert["rule_id"] == "A001"

    def test_does_not_trigger_on_read_only_reference(self):
        evt = _make_event(
            message="Listing contents of /Library/LaunchAgents directory",
        )
        # No write-like keyword → should NOT fire
        alert = rule_a_persistence(evt)
        assert alert is None

    def test_does_not_trigger_on_unrelated_message(self):
        evt = _make_event(message="System idle. No events.")
        alert = rule_a_persistence(evt)
        assert alert is None

    def test_alert_has_required_fields(self):
        evt = _make_event(
            message=(
                "/Users/user/Library/LaunchAgents/x.plist "
                "created and installed"
            ),
        )
        alert = rule_a_persistence(evt)
        assert alert is not None
        for field in ("rule_id", "severity", "confidence", "title",
                      "description", "evidence", "recommended_action",
                      "false_positive_notes"):
            assert field in alert, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# Rule B — Suspicious executable path
# ---------------------------------------------------------------------------

class TestRuleB:

    def _evt_with_path(self, path: str) -> dict:
        return _make_event(
            raw_data=json.dumps({"processImagePath": path}),
            process=path.split("/")[-1],
        )

    def test_triggers_on_downloads(self):
        evt = self._evt_with_path("/Users/testuser/Downloads/malware")
        alert = rule_b_suspicious_executable(evt)
        assert alert is not None
        assert alert["rule_id"] == "B001"
        assert alert["severity"] == "medium"

    def test_triggers_on_desktop(self):
        evt = self._evt_with_path("/Users/testuser/Desktop/script.sh")
        alert = rule_b_suspicious_executable(evt)
        assert alert is not None

    def test_triggers_on_tmp(self):
        evt = self._evt_with_path("/tmp/dropper")
        alert = rule_b_suspicious_executable(evt)
        assert alert is not None

    def test_does_not_trigger_on_applications(self):
        evt = self._evt_with_path("/Applications/Safari.app/Contents/MacOS/Safari")
        alert = rule_b_suspicious_executable(evt)
        assert alert is None

    def test_does_not_trigger_on_system_binaries(self):
        evt = self._evt_with_path("/usr/bin/python3")
        alert = rule_b_suspicious_executable(evt)
        assert alert is None

    def test_does_not_trigger_when_no_path(self):
        evt = _make_event(raw_data=json.dumps({}))
        alert = rule_b_suspicious_executable(evt)
        assert alert is None

    def test_does_not_trigger_on_invalid_raw_data(self):
        evt = _make_event(raw_data="not-json")
        alert = rule_b_suspicious_executable(evt)
        assert alert is None

    def test_confidence_is_low(self):
        evt = self._evt_with_path("/Users/user/Downloads/app")
        alert = rule_b_suspicious_executable(evt)
        assert alert["confidence"] == "low"


# ---------------------------------------------------------------------------
# Rule C — Input monitoring
# ---------------------------------------------------------------------------

class TestRuleC:

    def test_triggers_on_cgeventtap(self):
        evt = _make_event(
            source="com.apple.security",
            message="CGEventTap created for kCGEventKeyDown by process 1234",
        )
        alert = rule_c_input_monitoring(evt)
        assert alert is not None
        assert alert["rule_id"] == "C001"
        assert alert["severity"] == "high"

    def test_triggers_on_tcc_accessibility(self):
        evt = _make_event(
            source="com.apple.TCC",
            message="Access granted: kTCCServiceAccessibility for bundle com.example.app",
        )
        alert = rule_c_input_monitoring(evt)
        assert alert is not None
        assert alert["confidence"] == "medium"  # security subsystem → medium

    def test_triggers_on_iohidmanager(self):
        evt = _make_event(
            message="IOHIDManager created for keyboard event monitoring",
        )
        alert = rule_c_input_monitoring(evt)
        assert alert is not None

    def test_does_not_trigger_on_unrelated_message(self):
        evt = _make_event(message="User logged in successfully")
        alert = rule_c_input_monitoring(evt)
        assert alert is None

    def test_confidence_lower_without_security_subsystem(self):
        evt = _make_event(
            source="com.example.app",
            message="CGEventTap created",
        )
        alert = rule_c_input_monitoring(evt)
        assert alert is not None
        assert alert["confidence"] == "low"

    def test_false_positive_notes_present(self):
        evt = _make_event(message="AXObserver registered for accessibility")
        alert = rule_c_input_monitoring(evt)
        if alert:
            assert len(alert.get("false_positive_notes", "")) > 10


# ---------------------------------------------------------------------------
# Rule D — Process + network correlation
# ---------------------------------------------------------------------------

class TestRuleD:

    def test_triggers_on_suspicious_path_with_network(self):
        evt = _make_event(
            raw_data=json.dumps({"processImagePath": "/Users/testuser/Downloads/spy"}),
            message="TCP connect to 203.0.113.1:443 established",
        )
        alert = rule_d_process_network(evt)
        assert alert is not None
        assert alert["rule_id"] == "D001"

    def test_does_not_trigger_on_safe_path_with_network(self):
        evt = _make_event(
            raw_data=json.dumps({"processImagePath": "/Applications/Firefox.app/Contents/MacOS/firefox"}),
            message="HTTP connect established",
        )
        alert = rule_d_process_network(evt)
        assert alert is None

    def test_does_not_trigger_on_suspicious_path_without_network(self):
        evt = _make_event(
            raw_data=json.dumps({"processImagePath": "/tmp/payload"}),
            message="File read operation completed",
        )
        alert = rule_d_process_network(evt)
        assert alert is None


# ---------------------------------------------------------------------------
# Rule E — Combined indicators
# ---------------------------------------------------------------------------

class TestRuleE:

    def test_triggers_when_multiple_rules_fire_for_same_process(self):
        process_name = "evil_process"
        evt = _make_event(process=process_name)

        prior_alerts = [
            {"rule_id": "A001", "evidence": {"process": process_name}},
            {"rule_id": "B001", "evidence": {"process": process_name}},
        ]
        alert = rule_e_combined_indicators(evt, prior_alerts)
        assert alert is not None
        assert alert["rule_id"] == "E001"
        assert alert["severity"] == "critical"

    def test_does_not_trigger_with_only_one_prior_alert(self):
        evt = _make_event(process="proc")
        prior_alerts = [
            {"rule_id": "A001", "evidence": {"process": "proc"}},
        ]
        alert = rule_e_combined_indicators(evt, prior_alerts)
        assert alert is None

    def test_does_not_trigger_for_different_processes(self):
        evt = _make_event(process="proc_a")
        prior_alerts = [
            {"rule_id": "A001", "evidence": {"process": "proc_b"}},
            {"rule_id": "B001", "evidence": {"process": "proc_b"}},
        ]
        alert = rule_e_combined_indicators(evt, prior_alerts)
        assert alert is None

    def test_does_not_trigger_without_process(self):
        evt = _make_event(process=None)
        prior_alerts = [
            {"rule_id": "A001", "evidence": {"process": None}},
            {"rule_id": "B001", "evidence": {"process": None}},
        ]
        alert = rule_e_combined_indicators(evt, prior_alerts)
        assert alert is None

    def test_triggered_rules_list_in_evidence(self):
        evt = _make_event(process="target")
        prior_alerts = [
            {"rule_id": "A001", "evidence": {"process": "target"}},
            {"rule_id": "C001", "evidence": {"process": "target"}},
        ]
        alert = rule_e_combined_indicators(evt, prior_alerts)
        assert alert is not None
        assert "A001" in alert["evidence"]["triggered_rules"]
        assert "C001" in alert["evidence"]["triggered_rules"]


# ---------------------------------------------------------------------------
# Engine integration (no DB)
# ---------------------------------------------------------------------------

class TestDetectionEngine:

    def test_engine_returns_alerts_for_sample_events(self):
        from detection.engine import run_detection_on_events
        from data.sample_events import get_sample_events

        events = get_sample_events()
        alerts = run_detection_on_events(events)
        # Sample data is crafted to produce at least 3 alerts
        assert len(alerts) >= 3

    def test_engine_handles_empty_event_list(self):
        from detection.engine import run_detection_on_events
        alerts = run_detection_on_events([])
        assert alerts == []

    def test_engine_handles_malformed_event(self):
        from detection.engine import run_detection_on_events
        # Malformed events should not crash the engine
        malformed = [
            None,
            {},
            {"message": None, "raw_data": "not-json"},
            {"timestamp": "bad", "raw_data": json.dumps({"processImagePath": "/tmp/x"})},
        ]
        # Filter out None (engine expects dicts)
        alerts = run_detection_on_events([e for e in malformed if isinstance(e, dict)])
        assert isinstance(alerts, list)  # should not raise

    def test_benign_event_does_not_trigger_high_confidence(self):
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
        assert len(high_conf) == 0

    def test_no_duplicate_rules_on_same_event(self):
        from detection.engine import run_detection_on_events
        evt = _make_event(
            source="com.apple.TCC",
            message="kTCCServiceAccessibility granted",
        )
        alerts = run_detection_on_events([evt])
        rule_ids = [a["rule_id"] for a in alerts]
        # Should not have duplicates from the same rule
        assert len(rule_ids) == len(set(rule_ids)) or \
               all(rule_ids.count(r) == 1 for r in rule_ids)


# ---------------------------------------------------------------------------
# Risk scoring stability
# ---------------------------------------------------------------------------

class TestRiskScoring:

    def test_persistence_alert_severity_is_stable(self):
        """Same input should always produce same severity."""
        evt = _make_event(
            message="/Users/user/Library/LaunchAgents/x.plist created and installed"
        )
        results = [rule_a_persistence(evt) for _ in range(5)]
        severities = [r["severity"] for r in results if r]
        assert all(s == "high" for s in severities)

    def test_input_monitoring_severity_is_stable(self):
        evt = _make_event(
            source="com.apple.TCC",
            message="kTCCServiceListenEvent granted",
        )
        results = [rule_c_input_monitoring(evt) for _ in range(5)]
        severities = [r["severity"] for r in results if r]
        assert all(s == "high" for s in severities)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParser:

    def test_normalize_event_returns_schema(self):
        from parser.macos import normalize_event
        raw = {
            "timestamp": "2026-01-01T00:00:00Z",
            "processImagePath": "/usr/bin/python3",
            "processID": 100,
            "userID": 501,
            "subsystem": "com.apple.test",
            "category": "test",
            "messageType": "Info",
            "eventMessage": "Test message",
        }
        result = normalize_event(raw)
        assert result is not None
        assert result["process"] == "python3"
        assert result["process_id"] == 100
        assert result["user"] == "501"
        assert "raw_data" in result

    def test_normalize_event_handles_empty_dict(self):
        from parser.macos import normalize_event
        result = normalize_event({})
        assert result is not None  # should not raise

    def test_normalize_event_handles_none(self):
        from parser.macos import normalize_event
        result = normalize_event(None)
        assert result is None

    def test_normalize_process_returns_schema(self):
        from parser.macos import normalize_process
        raw = {"pid": 42, "ppid": 1, "user": "root", "cpu_pct": "0.1", "mem_pct": "0.5", "command": "bash"}
        result = normalize_process(raw)
        assert result is not None
        assert result["process"] == "bash"
        assert result["process_id"] == 42

    def test_normalize_launch_item_returns_schema(self):
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
        assert result is not None
        assert "run_at_load=True" in result["message"]


# ---------------------------------------------------------------------------
# Storage tests (in-memory / temp DB)
# ---------------------------------------------------------------------------

class TestStorage:

    def _temp_db(self, tmp_path):
        """Return a test database path."""
        import storage.database as db_module
        original = db_module.DB_PATH
        db_module.DB_PATH = tmp_path / "test_siem.db"
        return original

    def test_init_database_creates_tables(self, tmp_path):
        import storage.database as db_module
        orig = db_module.DB_PATH
        db_module.DB_PATH = tmp_path / "test.db"
        try:
            db_module.init_database()
            conn = db_module.get_connection()
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = {r[0] for r in tables}
            assert "events" in table_names
            assert "alerts" in table_names
            conn.close()
        finally:
            db_module.DB_PATH = orig

    def test_insert_and_retrieve_event(self, tmp_path):
        import storage.database as db_module
        orig = db_module.DB_PATH
        db_module.DB_PATH = tmp_path / "test.db"
        try:
            db_module.init_database()
            evt = {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "host": "test", "source": "test", "category": "test",
                "event_type": "Info", "user": "501", "process": "test",
                "process_id": 1, "parent_process": None,
                "source_ip": None, "destination_ip": None, "destination_port": None,
                "message": "Hello World", "raw_data": "{}",
            }
            count = db_module.insert_events([evt])
            assert count == 1

            events = db_module.get_events(limit=10)
            assert len(events) == 1
            assert events[0]["message"] == "Hello World"
        finally:
            db_module.DB_PATH = orig

    def test_insert_empty_batch_returns_zero(self, tmp_path):
        import storage.database as db_module
        orig = db_module.DB_PATH
        db_module.DB_PATH = tmp_path / "test.db"
        try:
            db_module.init_database()
            count = db_module.insert_events([])
            assert count == 0
        finally:
            db_module.DB_PATH = orig

    def test_db_stats_on_empty_db(self, tmp_path):
        import storage.database as db_module
        orig = db_module.DB_PATH
        db_module.DB_PATH = tmp_path / "test.db"
        try:
            db_module.init_database()
            stats = db_module.get_db_stats()
            assert stats["event_count"] == 0
            assert stats["alert_count"] == 0
        finally:
            db_module.DB_PATH = orig


# ---------------------------------------------------------------------------
# Timeline tests
# ---------------------------------------------------------------------------

class TestTimeline:

    def test_build_timeline_merges_events_and_alerts(self):
        from investigation.timeline import build_timeline
        events = [
            {"timestamp": "2026-01-01T01:00:00Z", "process": "proc", "message": "msg",
             "event_type": "Info", "source": "test"},
        ]
        alerts = [
            {"created_at": "2026-01-01T00:30:00Z", "severity": "high",
             "title": "Test Alert", "description": "desc", "rule_id": "A001",
             "evidence": {"process": "proc"}},
        ]
        timeline = build_timeline(events, alerts)
        assert len(timeline) == 2
        assert timeline[0]["kind"] == "alert"  # earlier timestamp
        assert timeline[1]["kind"] == "event"

    def test_build_timeline_handles_empty_inputs(self):
        from investigation.timeline import build_timeline
        assert build_timeline([], []) == []
        assert build_timeline([], [{"created_at": "2026-01-01", "severity": "low",
                                     "title": "x", "rule_id": "A001", "evidence": {}}]) != []

    def test_generate_report_returns_string(self):
        from investigation.timeline import generate_report
        report = generate_report(None, [], [], None)
        assert isinstance(report, str)
        assert "MINI-SIEM" in report

    def test_generate_report_with_alerts(self):
        from investigation.timeline import generate_report
        alerts = [
            {"severity": "high", "confidence": "medium", "rule_id": "A001",
             "title": "Test Alert", "description": "Desc", "created_at": "2026-01-01",
             "recommended_action": "Do something", "false_positive_notes": "Maybe benign",
             "evidence": {"process": "test_proc"}},
        ]
        report = generate_report(1, [], alerts, None)
        assert "Test Alert" in report
        assert "A001" in report


# ---------------------------------------------------------------------------
# Collector tests (unit-level — no actual subprocess calls)
# ---------------------------------------------------------------------------

class TestCollectorParser:

    def test_parse_logs_handles_empty_string(self):
        from collector.macos import parse_logs
        assert parse_logs("") == []

    def test_parse_logs_handles_no_json(self):
        from collector.macos import parse_logs
        assert parse_logs("Not JSON at all") == []

    def test_parse_logs_parses_valid_array(self):
        from collector.macos import parse_logs
        raw = json.dumps([
            {"timestamp": "2026-01-01", "eventMessage": "Hello"},
            {"timestamp": "2026-01-01", "eventMessage": "World"},
        ])
        events = parse_logs(raw)
        assert len(events) == 2
        assert events[0]["eventMessage"] == "Hello"

    def test_parse_logs_handles_partial_json(self):
        from collector.macos import parse_logs
        # Truncated array — should fall back to streaming parser
        raw = '[{"timestamp":"t1","eventMessage":"ok"},{"timestamp":"t2","eventMe'
        events = parse_logs(raw)
        # At least the first valid object should parse
        assert len(events) >= 1
        assert events[0]["eventMessage"] == "ok"
