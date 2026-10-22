# Mini-SIEM Blue Team Lab

A lightweight, educational SIEM (Security Information and Event Management) system for macOS, designed for Blue Team SOC Level 1 practice on Apple Silicon (M1/M2/M3).

> **Disclaimer**: This is a learning and investigation-support tool. It does NOT claim to detect all keyloggers or malware. All alerts require human review. False positives are expected and documented.

---

## Architecture

```
mini-siem/
├── collector/          # macOS data collection (ULS logs, processes, LaunchItems)
│   └── macos.py
├── parser/             # Event normalization to canonical schema
│   └── macos.py
├── detection/          # Detection rules and engine
│   ├── rules.py        # Rule A–E implementations
│   └── engine.py       # Runs rules, persists alerts, deduplicates
├── storage/            # SQLite storage layer
│   └── database.py
├── investigation/      # Timeline builder and report generator
│   └── timeline.py
├── dashboard/          # Flask web UI (localhost only)
│   └── app.py
├── data/               # Sample/simulation events
│   └── sample_events.py
├── tests/              # Unit tests (53 tests, no external deps)
│   ├── run_tests.py    # stdlib unittest runner
│   └── test_detection.py  # pytest-compatible test file
├── main.py             # CLI entry point
├── requirements.txt
└── pyproject.toml
```

---

## Requirements

- **macOS** (tested on Apple Silicon M1, macOS 15+)
- **Python 3.10+** (system Python from Homebrew recommended)
- **Flask** (`pip3 install flask` or `brew install python` includes it)

No other external packages required. All storage uses Python's built-in `sqlite3`.

---

## Quick Start

```bash
# 1. Clone / enter the project
cd /Users/nam/Cyber_sec/mini-siem

# 2. Initialize the database
python3 main.py init

# 3. Load simulation data and run detection (safe, no real system changes)
python3 main.py simulate

# 4. View investigation report in the terminal
python3 main.py investigate

# 5. Start the web dashboard
python3 main.py dashboard
# Open http://127.0.0.1:5000 in your browser
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `python3 main.py init` | Initialize SQLite database |
| `python3 main.py collect [N]` | Collect last N minutes of macOS logs + processes + LaunchItems |
| `python3 main.py detect` | Run detection rules on stored events |
| `python3 main.py simulate` | Load safe synthetic events and run detection |
| `python3 main.py investigate [id]` | Print forensic timeline and report |
| `python3 main.py run [N]` | Full pipeline: collect → store → detect |
| `python3 main.py dashboard` | Start Flask dashboard at http://127.0.0.1:5000 |

---

## Detection Rules

| Rule | ID | Severity | What it detects |
|------|----|----------|-----------------|
| **Persistence** | A001 | High | Activity in LaunchAgent/LaunchDaemon directories |
| **Suspicious Path** | B001 | Medium | Executables running from Downloads, Desktop, /tmp |
| **Input Monitoring** | C001 | High | Accessibility/TCC grants, CGEventTap, IOHIDManager, AXObserver |
| **Network Correlation** | D001 | Medium | Network activity from suspicious-path processes |
| **Combined Indicators** | E001 | Critical | Same process triggering 2+ independent rules |

Each alert includes:
- `severity` + `confidence` (independently assessed)
- `evidence` dict with key facts
- `recommended_action` for SOC triage
- `false_positive_notes` explaining common benign triggers

---

## Running Tests

```bash
# No external dependencies required
python3 tests/run_tests.py

# If pytest is installed:
python3 -m pytest tests/test_detection.py -v
```

**53 tests covering:**
- All 5 detection rules (true positive + false positive cases)
- Detection engine (empty input, malformed events, deduplication)
- Parser normalization (ULS events, processes, LaunchItems)
- Storage layer (insert, retrieve, stats)
- Timeline and report generation
- Simulation data integrity

---

## Data Sources

| Source | Method | Privilege required |
|--------|--------|-------------------|
| Unified Logging System | `log show --style json` | None (unprivileged) |
| Running processes | `ps -eo pid,ppid,...` | None |
| LaunchAgents/Daemons | `plistlib.load()` on readable plists | None (user-owned) |
| System metadata | `sw_vers`, `uname`, `sysctl` | None |

### macOS Security Limitations

- **TCC (Transparency, Consent, and Control)**: Full Disk Access is NOT required for user-owned LaunchAgents or ULS events that don't involve protected paths.
- **SIP (System Integrity Protection)**: `/System/Library/Launch*` plists may be unreadable — this is expected and handled gracefully.
- **Input Monitoring list**: macOS does NOT expose a programmatic API to list all apps with Input Monitoring permission. This SIEM detects relevant log events from `com.apple.TCC`, not direct permission queries.
- **Keylogging detection**: We detect *capability signals* (Accessibility grants, CGEventTap creation), NOT confirmed keylogging behaviour. A positive alert means "investigate further," not "confirmed threat."

---

## Dashboard

Start with `python3 main.py dashboard` or `python3 dashboard/app.py`.

Features:
- **Overview**: event counts, alert severity breakdown, action buttons
- **Alerts**: filterable table with severity/confidence, links to detail view
- **Alert Detail**: full description, evidence, recommended action, false positive notes
- **Events**: searchable event table with process/message filters
- **Timeline**: merged chronological view of events and alerts
- **Report**: auto-generated plain-text investigation report
- **Simulate**: one-click simulation data load from the UI

> **Security**: The dashboard binds only to `127.0.0.1:5000`. It is not accessible from other machines on the network.

---

## Simulation Scenarios

| Scenario | Rule Triggered | Notes |
|----------|---------------|-------|
| S1 — LaunchAgent installed | A001 (High) | `launchctl load` for user plist |
| S2 — Binary from Downloads | B001 (Medium) | `processImagePath` in suspicious dir |
| S3 — TCC Accessibility grant | C001 (High/Medium) | `kTCCServiceAccessibility` keyword |
| S4 — Network from Downloads binary | D001 (Medium) | Path + network correlation |
| S5 — Combined (same process) | E001 (Critical) | B001 + C001 + D001 for `suspicious_app` |
| S6 — Finder file move | **None** | Benign event, confirms no false positive |
| S7 — LaunchDaemon + IOHIDManager | A001 + C001 + E001 | Multi-rule correlation |
| S8 — CGEventTap from Downloads | C001 + E001 | High-confidence input monitoring |

---

## Example Alert

```
[CRITICAL/medium] [E001] Multiple indicators for process 'suspicious_app'

Description:
  Process 'suspicious_app' triggered 3 independent detection rules
  (B001, C001, D001). Multiple correlated indicators significantly
  increase the likelihood of malicious activity.

Evidence:
  process:         suspicious_app
  triggered_rules: ['B001', 'C001', 'D001']
  alert_count:     5

Recommended Action:
  1. Immediately review all events for this process.
  2. Isolate the process if actively harmful.
  3. Preserve evidence: snapshot memory, save logs.
  4. Escalate to Tier-2 if activity is confirmed malicious.

False Positive Notes:
  Security tools, monitoring agents, and some developer utilities
  legitimately match multiple rules. Always cross-reference with
  recently installed software before escalating.
```

---

## Keylogger Detection Limitations

True keylogger detection on modern macOS is fundamentally limited by the OS security model:

1. **No direct API** to list which apps have Input Monitoring permission programmatically.
2. **CGEventTap events** in ULS are not always logged at the default log level — `log show` may miss them unless the tap was denied.
3. **Kernel extensions** required for deep monitoring are blocked by SIP and require user approval.
4. **Sandboxed keyloggers** using legitimate Accessibility APIs look identical to screen readers in log data.

**What we CAN detect**: TCC permission changes, launchctl loading unknown plists, processes running from unusual paths, and combinations of these signals.

---

## Next Steps

1. **Scheduled collection**: `crontab` or a LaunchAgent to run `python3 main.py collect` every 5 minutes
2. **Alert deduplication**: Time-window based (suppress same rule/process within N minutes)
3. **Threat intel enrichment**: Hash lookups via VirusTotal API for process binaries
4. **codesign verification**: Use `codesign -dv` on flagged binaries for signature checks
5. **Network events**: Integrate `lsof -i` snapshots for live connection correlation
6. **Notification**: macOS `osascript` notification on critical alerts
7. **Export**: STIX/TAXII or CSV export for sharing with other tools
8. **MITRE ATT&CK mapping**: Tag each rule with the corresponding ATT&CK technique ID

---

## Files Created/Modified

| File | Status | Description |
|------|--------|-------------|
| `main.py` | Modified | Added simulate, investigate, dashboard commands |
| `collector/macos.py` | Modified | Added process + LaunchItem collectors, collect_all() |
| `parser/macos.py` | Modified | Added normalize_process(), normalize_launch_item() |
| `storage/database.py` | Modified | Added confidence/evidence/action columns, get_db_stats(), migrations |
| `detection/rules.py` | Created | Rules A001–E001 with full alert schema |
| `detection/engine.py` | Created | Detection engine with deduplication |
| `investigation/timeline.py` | Created | Timeline builder and report generator |
| `dashboard/app.py` | Created | Flask web UI (localhost:5000) |
| `data/sample_events.py` | Created | 8 safe synthetic simulation scenarios |
| `data/__init__.py` | Created | Package marker |
| `tests/run_tests.py` | Created | 53 unit tests (stdlib unittest) |
| `tests/test_detection.py` | Created | pytest-compatible test file |
| `requirements.txt` | Modified | Updated with actual dependencies |
| `pyproject.toml` | Created | pytest configuration |
