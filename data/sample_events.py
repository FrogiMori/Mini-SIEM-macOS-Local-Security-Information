"""
data/sample_events.py

Safe simulation data for Mini-SIEM testing.

These are SYNTHETIC events that mimic what a real SIEM might collect.
They do NOT:
  - Capture real keystrokes
  - Modify any system configuration
  - Drop executable files
  - Establish network connections
  - Represent real incidents on this machine

Scenarios:
  S1 - LaunchAgent persistence (Rule A)
  S2 - Executable from suspicious path (Rule B)
  S3 - Accessibility / Input monitoring keyword (Rule C)
  S4 - Network activity from suspicious path (Rule D)
  S5 - Combined indicators for same process (Rule E)
  S6 - Benign event (should NOT trigger alerts)
  S7 - Malformed event (should be handled gracefully)
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone, timedelta

_HOSTNAME = socket.gethostname()


def _ts(offset_minutes: int = 0) -> str:
    """Return an ISO UTC timestamp offset by N minutes from now."""
    dt = datetime.now(timezone.utc) - timedelta(minutes=abs(offset_minutes))
    return dt.isoformat()


def get_sample_events() -> list[dict]:
    """
    Return a list of normalized event dicts (ready to insert into the DB).

    All events use the canonical SIEM schema.
    """
    events: list[dict] = []

    # ------------------------------------------------------------------
    # S1 — LaunchAgent persistence
    # Simulates a log entry about a plist being loaded in ~/Library/LaunchAgents
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(15),
        "host":             _HOSTNAME,
        "source":           "com.apple.launchd",
        "category":         "service",
        "event_type":       "Default",
        "user":             "501",
        "process":          "launchd",
        "process_id":       1,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message": (
            "Load: /Users/testuser/Library/LaunchAgents/com.example.updater.plist "
            "created and installed successfully. RunAtLoad=true"
        ),
        "raw_data": json.dumps({
            "timestamp": _ts(15),
            "processImagePath": "/sbin/launchd",
            "processID": 1,
            "subsystem": "com.apple.launchd",
            "category": "service",
            "messageType": "Default",
            "eventMessage": (
                "Load: /Users/testuser/Library/LaunchAgents/com.example.updater.plist "
                "created and installed successfully. RunAtLoad=true"
            ),
        }),
    })

    # ------------------------------------------------------------------
    # S2 — Executable from suspicious path (Downloads folder)
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(14),
        "host":             _HOSTNAME,
        "source":           "com.apple.kernel",
        "category":         "exec",
        "event_type":       "Default",
        "user":             "501",
        "process":          "suspicious_app",
        "process_id":       4242,
        "parent_process":   "Finder",
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message":          "Process launched from user Downloads directory",
        "raw_data": json.dumps({
            "timestamp": _ts(14),
            "processImagePath": "/Users/testuser/Downloads/suspicious_app",
            "processID": 4242,
            "subsystem": "com.apple.kernel",
            "category": "exec",
            "messageType": "Default",
            "eventMessage": "Process launched from user Downloads directory",
        }),
    })

    # ------------------------------------------------------------------
    # S3 — Accessibility / Input monitoring keyword (TCC grant)
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(13),
        "host":             _HOSTNAME,
        "source":           "com.apple.TCC",
        "category":         "access",
        "event_type":       "Default",
        "user":             "501",
        "process":          "tccd",
        "process_id":       333,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message": (
            "Access granted: kTCCServiceAccessibility "
            "for bundle com.example.suspicious_app "
            "by user 501"
        ),
        "raw_data": json.dumps({
            "timestamp": _ts(13),
            "processImagePath": "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
            "processID": 333,
            "subsystem": "com.apple.TCC",
            "category": "access",
            "messageType": "Default",
            "eventMessage": (
                "Access granted: kTCCServiceAccessibility "
                "for bundle com.example.suspicious_app "
                "by user 501"
            ),
        }),
    })

    # ------------------------------------------------------------------
    # S4 — Network activity from suspicious path process
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(12),
        "host":             _HOSTNAME,
        "source":           "com.apple.network",
        "category":         "connection",
        "event_type":       "Default",
        "user":             "501",
        "process":          "suspicious_app",
        "process_id":       4242,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message":          "TCP connect to 203.0.113.42:443 established",
        "raw_data": json.dumps({
            "timestamp": _ts(12),
            "processImagePath": "/Users/testuser/Downloads/suspicious_app",
            "processID": 4242,
            "subsystem": "com.apple.network",
            "category": "connection",
            "messageType": "Default",
            "eventMessage": "TCP connect to 203.0.113.42:443 established",
        }),
    })

    # ------------------------------------------------------------------
    # S5 — Combined indicators (same process as S2/S4 — will trigger Rule E)
    # This event itself is benign but tips the process over the multi-rule threshold
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(11),
        "host":             _HOSTNAME,
        "source":           "com.apple.sandbox",
        "category":         "violation",
        "event_type":       "Error",
        "user":             "501",
        "process":          "suspicious_app",
        "process_id":       4242,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message":          "Sandbox violation: suspicious_app attempted to access /etc/passwd",
        "raw_data": json.dumps({
            "timestamp": _ts(11),
            "processImagePath": "/Users/testuser/Downloads/suspicious_app",
            "processID": 4242,
            "subsystem": "com.apple.sandbox",
            "category": "violation",
            "messageType": "Error",
            "eventMessage": "Sandbox violation: suspicious_app attempted to access /etc/passwd",
        }),
    })

    # ------------------------------------------------------------------
    # S6 — Benign event: normal Finder operation (should NOT trigger any rule)
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(10),
        "host":             _HOSTNAME,
        "source":           "com.apple.finder",
        "category":         "files",
        "event_type":       "Info",
        "user":             "501",
        "process":          "Finder",
        "process_id":       1234,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message":          "File moved: /Users/testuser/Documents/report.pdf",
        "raw_data": json.dumps({
            "timestamp": _ts(10),
            "processImagePath": "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "processID": 1234,
            "subsystem": "com.apple.finder",
            "category": "files",
            "messageType": "Info",
            "eventMessage": "File moved: /Users/testuser/Documents/report.pdf",
        }),
    })

    # ------------------------------------------------------------------
    # S7 — LaunchDaemon with IOHIDManager (Rule A + C correlation)
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(9),
        "host":             _HOSTNAME,
        "source":           "com.apple.IOKit",
        "category":         "hid",
        "event_type":       "Default",
        "user":             "0",
        "process":          "hidd",
        "process_id":       88,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message": (
            "IOHIDManager created by process at "
            "/Library/LaunchDaemons/com.unknown.monitor.plist "
            "installed via bootstrap"
        ),
        "raw_data": json.dumps({
            "timestamp": _ts(9),
            "processImagePath": "/usr/libexec/hidd",
            "processID": 88,
            "subsystem": "com.apple.IOKit",
            "category": "hid",
            "messageType": "Default",
            "eventMessage": (
                "IOHIDManager created by process at "
                "/Library/LaunchDaemons/com.unknown.monitor.plist "
                "installed via bootstrap"
            ),
        }),
    })

    # ------------------------------------------------------------------
    # S8 — CGEventTap creation (strong Rule C indicator)
    # ------------------------------------------------------------------
    events.append({
        "timestamp":        _ts(8),
        "host":             _HOSTNAME,
        "source":           "com.apple.security",
        "category":         "eventTap",
        "event_type":       "Default",
        "user":             "501",
        "process":          "suspicious_app",
        "process_id":       4242,
        "parent_process":   None,
        "source_ip":        None,
        "destination_ip":   None,
        "destination_port": None,
        "message": (
            "CGEventTap created: kCGEventKeyDown, kCGEventKeyUp "
            "by process suspicious_app (4242)"
        ),
        "raw_data": json.dumps({
            "timestamp": _ts(8),
            "processImagePath": "/Users/testuser/Downloads/suspicious_app",
            "processID": 4242,
            "subsystem": "com.apple.security",
            "category": "eventTap",
            "messageType": "Default",
            "eventMessage": (
                "CGEventTap created: kCGEventKeyDown, kCGEventKeyUp "
                "by process suspicious_app (4242)"
            ),
        }),
    })

    return events


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    events = get_sample_events()
    print(f"Generated {len(events)} sample events")
    for i, e in enumerate(events, 1):
        print(f"\n[{i}] {e['timestamp'][:19]} | {e['process']} | {e['message'][:80]}")
