"""
detection/rules.py

Detection rules for Mini-SIEM Blue Team Lab.

Each rule is a function that accepts a normalized event dict and returns
an alert dict (or None if the rule does not trigger).

Alert schema:
    event_id           int   – DB row id of the triggering event (set by engine)
    timestamp          str   – ISO timestamp of the triggering event
    rule_id            str   – unique rule identifier
    severity           str   – critical / high / medium / low
    confidence         str   – high / medium / low
    title              str   – short human-readable summary
    description        str   – full explanation of why the rule fired
    evidence           dict  – key facts extracted from the event
    recommended_action str   – SOC response suggestion
    false_positive_notes str – common benign reasons this could fire
"""

from __future__ import annotations

import re
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Directories where LaunchAgents/LaunchDaemons live
PERSISTENCE_DIRS: list[str] = [
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
]
USER_PERSISTENCE_PATTERN = re.compile(r"^/Users/[^/]+/Library/LaunchAgents/")

# Suspicious path prefixes for executables
SUSPICIOUS_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"^/tmp/"),
    re.compile(r"^/var/tmp/"),
    re.compile(r"^/private/tmp/"),
    re.compile(r"^/Users/[^/]+/Downloads/"),
    re.compile(r"^/Users/[^/]+/Desktop/"),
]

# Accessibility / Input-monitoring related log keywords
INPUT_MONITORING_KEYWORDS: list[str] = [
    "kTCCServiceAccessibility",
    "kTCCServiceListenEvent",
    "kTCCServicePostEvent",
    "InputMonitor",
    "accessibility grant",
    "AXObserver",
    "CGEventTap",
    "CGEventPost",
    "IOHIDManager",
]

# Apple security subsystems
SECURITY_SUBSYSTEMS: list[str] = [
    "com.apple.TCC",
    "com.apple.security",
    "com.apple.sandbox",
    "com.apple.privacy",
]

NETWORK_KEYWORDS: list[str] = [
    "connect", "socket", "tcp", "udp", "dns", "resolve",
    "http", "https", "download", "upload", "transfer",
]

WRITE_KEYWORDS: list[str] = [
    "created", "modified", "written", "installed", "added",
    "launchctl", "load", "bootstrap", "plist",
]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_alert(
    *,
    rule_id: str,
    severity: str,
    confidence: str,
    title: str,
    description: str,
    evidence: dict,
    recommended_action: str,
    false_positive_notes: str,
    event: dict,
) -> dict:
    """Construct a fully-populated alert dict from a triggering event."""
    return {
        "event_id": event.get("id"),
        "timestamp": event.get("timestamp"),
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommended_action": recommended_action,
        "false_positive_notes": false_positive_notes,
        "status": "open",
    }


def _get_image_path(event: dict) -> str:
    """Extract processImagePath from raw_data JSON."""
    raw = event.get("raw_data") or ""
    try:
        raw_dict = json.loads(raw)
        return raw_dict.get("processImagePath", "")
    except (json.JSONDecodeError, ValueError):
        return ""


# ---------------------------------------------------------------------------
# Rule A — Persistence
# ---------------------------------------------------------------------------

def rule_a_persistence(event: dict) -> Optional[dict]:
    """
    Trigger when a log message references a LaunchAgent or LaunchDaemon
    directory combined with write-like activity keywords.

    Severity: high | Confidence: medium
    """
    msg = (event.get("message") or "").lower()
    raw = (event.get("raw_data") or "").lower()
    combined = msg + " " + raw

    matched_dir: Optional[str] = None
    for d in PERSISTENCE_DIRS:
        if d.lower() in combined:
            matched_dir = d
            break

    if matched_dir is None:
        orig = (event.get("message") or "") + " " + (event.get("raw_data") or "")
        m = USER_PERSISTENCE_PATTERN.search(orig)
        if m:
            matched_dir = m.group(0)

    if matched_dir is None:
        return None

    if not any(kw in combined for kw in WRITE_KEYWORDS):
        return None

    return _make_alert(
        rule_id="A001",
        severity="high",
        confidence="medium",
        title="Persistence location activity detected",
        description=(
            f"A log event references the persistence directory '{matched_dir}'. "
            "Changes to LaunchAgent/LaunchDaemon plists are a common persistence "
            "technique used by both legitimate software and malware."
        ),
        evidence={
            "matched_directory": matched_dir,
            "process": event.get("process"),
            "message_excerpt": (event.get("message") or "")[:200],
        },
        recommended_action=(
            "1. Identify which plist file changed and who owns it. "
            "2. Review the ProgramArguments key in the plist. "
            "3. Verify the binary it references is signed by a trusted developer. "
            "4. If unknown, quarantine and investigate the binary."
        ),
        false_positive_notes=(
            "Legitimate software installers (Homebrew, software updaters, "
            "developer tools) routinely install LaunchAgents. Correlate with "
            "recent user-initiated installs before escalating."
        ),
        event=event,
    )


# ---------------------------------------------------------------------------
# Rule B — Suspicious executable path
# ---------------------------------------------------------------------------

def rule_b_suspicious_executable(event: dict) -> Optional[dict]:
    """
    Trigger when a process runs from a suspicious filesystem location.

    Severity: medium | Confidence: low
    """
    image_path = _get_image_path(event)
    if not image_path:
        return None

    matched_pattern: Optional[str] = None
    for pat in SUSPICIOUS_PATH_PATTERNS:
        if pat.search(image_path):
            matched_pattern = pat.pattern
            break

    if matched_pattern is None:
        return None

    process = event.get("process") or "unknown"

    return _make_alert(
        rule_id="B001",
        severity="medium",
        confidence="low",
        title=f"Executable running from suspicious path: {image_path[:80]}",
        description=(
            f"Process '{process}' is running from an unusual filesystem location "
            f"(matched pattern: {matched_pattern}). Attackers frequently drop and "
            "execute payloads from writable directories."
        ),
        evidence={
            "image_path": image_path,
            "process": process,
            "pid": event.get("process_id"),
        },
        recommended_action=(
            "1. Determine how the binary arrived in this location. "
            "2. Check the binary's code signature with `codesign -dv <path>`. "
            "3. Compute its hash and check against threat intel. "
            "4. Review recent downloads/browser history."
        ),
        false_positive_notes=(
            "Developers routinely execute scripts from ~/Downloads or ~/Desktop. "
            "Homebrew, npm, and pip may place executables in temp directories "
            "during build processes."
        ),
        event=event,
    )


# ---------------------------------------------------------------------------
# Rule C — Input monitoring / Accessibility risk
# ---------------------------------------------------------------------------

def rule_c_input_monitoring(event: dict) -> Optional[dict]:
    """
    Trigger when a log event contains keywords associated with Accessibility
    or Input Monitoring — mechanisms that could enable keylogging.

    This detects CAPABILITY, not confirmed keylogging behaviour.

    Severity: high | Confidence: medium (security source) or low (other)
    """
    msg = (event.get("message") or "")
    raw = (event.get("raw_data") or "")
    combined = msg + " " + raw

    matched_keyword: Optional[str] = None
    for kw in INPUT_MONITORING_KEYWORDS:
        if kw.lower() in combined.lower():
            matched_keyword = kw
            break

    if matched_keyword is None:
        return None

    source = (event.get("source") or "").lower()
    is_security_source = any(s.lower() in source for s in SECURITY_SUBSYSTEMS)
    confidence = "medium" if is_security_source else "low"

    return _make_alert(
        rule_id="C001",
        severity="high",
        confidence=confidence,
        title=f"Input monitoring / Accessibility keyword: {matched_keyword}",
        description=(
            f"A log event from subsystem '{event.get('source', 'unknown')}' "
            f"contains '{matched_keyword}', associated with macOS Accessibility "
            "or Input Monitoring capabilities. These APIs can observe keyboard "
            "input. This is a CAPABILITY indicator, NOT confirmed keylogging."
        ),
        evidence={
            "matched_keyword": matched_keyword,
            "source": event.get("source"),
            "process": event.get("process"),
            "message_excerpt": msg[:300],
        },
        recommended_action=(
            "1. Identify which process triggered this event. "
            "2. Check System Settings → Privacy & Security → Accessibility "
            "   and Input Monitoring for unexpected entries. "
            "3. Verify the process's purpose and code signature. "
            "4. If unexpected, revoke the permission and investigate."
        ),
        false_positive_notes=(
            "Screen readers, text expanders (TextExpander, Espanso), automation "
            "tools (Keyboard Maestro, BetterTouchTool), and IDE plugins legitimately "
            "use these APIs. Accessibility permission alone is NOT evidence of malice."
        ),
        event=event,
    )


# ---------------------------------------------------------------------------
# Rule D — Process + network correlation
# ---------------------------------------------------------------------------

def rule_d_process_network(event: dict) -> Optional[dict]:
    """
    Trigger when a log event indicates network activity from a process
    running in a suspicious filesystem location.

    Severity: medium | Confidence: low
    """
    msg = (event.get("message") or "").lower()
    has_network_kw = any(kw in msg for kw in NETWORK_KEYWORDS)
    if not has_network_kw:
        return None

    image_path = _get_image_path(event)
    is_suspicious_path = image_path and any(
        pat.search(image_path) for pat in SUSPICIOUS_PATH_PATTERNS
    )
    if not is_suspicious_path:
        return None

    process = event.get("process") or "unknown"

    return _make_alert(
        rule_id="D001",
        severity="medium",
        confidence="low",
        title=f"Network activity from suspicious path process: {process}",
        description=(
            f"Process '{process}' running from an unusual path "
            "appears to be performing network operations. Combining suspicious "
            "path + network activity raises investigation priority."
        ),
        evidence={
            "process": process,
            "image_path": image_path,
            "network_keyword": next((kw for kw in NETWORK_KEYWORDS if kw in msg), None),
            "message_excerpt": (event.get("message") or "")[:200],
        },
        recommended_action=(
            "1. Capture network connections with `lsof -i` or `netstat -an`. "
            "2. Identify the remote IP and check against threat intel. "
            "3. Review the process binary and its code signature. "
            "4. Consider blocking outbound connections if malicious."
        ),
        false_positive_notes=(
            "Developer tools, build systems, and package managers frequently "
            "make network connections from non-standard paths during builds."
        ),
        event=event,
    )


# ---------------------------------------------------------------------------
# Rule E — Combined indicators
# ---------------------------------------------------------------------------

def rule_e_combined_indicators(event: dict, prior_alerts: list[dict]) -> Optional[dict]:
    """
    Elevate severity when the same process has triggered multiple independent
    rules in a single collection run.

    Severity: critical | Confidence: medium
    """
    process = event.get("process")
    if not process:
        return None

    process_alerts = [
        a for a in prior_alerts
        if a.get("evidence", {}).get("process") == process
        and a.get("rule_id") != "E001"
    ]

    if len(process_alerts) < 2:
        return None

    rule_ids = sorted({a["rule_id"] for a in process_alerts})

    return _make_alert(
        rule_id="E001",
        severity="critical",
        confidence="medium",
        title=f"Multiple indicators for process '{process}'",
        description=(
            f"Process '{process}' triggered {len(process_alerts)} independent "
            f"detection rules ({', '.join(rule_ids)}). Multiple correlated "
            "indicators significantly increase the likelihood of malicious activity."
        ),
        evidence={
            "process": process,
            "triggered_rules": rule_ids,
            "alert_count": len(process_alerts),
        },
        recommended_action=(
            "1. Immediately review all events for this process. "
            "2. Isolate the process if actively harmful. "
            "3. Preserve evidence: snapshot memory, save logs. "
            "4. Escalate to Tier-2 if activity is confirmed malicious."
        ),
        false_positive_notes=(
            "Security tools, monitoring agents, and some developer utilities "
            "legitimately match multiple rules. Always cross-reference with "
            "recently installed software before escalating."
        ),
        event=event,
    )


# ---------------------------------------------------------------------------
# Rule registry (ordered — per-event rules)
# ---------------------------------------------------------------------------

PER_EVENT_RULES = [
    rule_a_persistence,
    rule_b_suspicious_executable,
    rule_c_input_monitoring,
    rule_d_process_network,
]
