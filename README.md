# Mini-SIEM Blue Team Lab

A lightweight, educational SIEM (Security Information and Event Management) system for macOS, designed for Blue Team SOC Level 1 practice on Apple Silicon (M1/M2/M3).

> **Disclaimer**: This is a learning and investigation-support tool. It does NOT claim to detect all keyloggers or malware. All alerts require human review. False positives are expected and documented.

---

## Architecture

```
mini-siem/
├── tui/                # Interactive SOC Level 1 Terminal User Interface (Rich-based)
│   ├── app.py          # Main TUI event loop, screens, and navigation
│   ├── components.py   # Layouts, metrics cards, tables, dossier panels
│   └── theme.py        # Cyber/SOC color palette and badges
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
├── tests/              # Unit tests (67 tests, no external deps)
│   ├── run_tests.py    # stdlib unittest runner
│   ├── test_detection.py  # Detection engine & rules tests
│   └── test_tui.py     # TUI components & interaction tests
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

# 2. Launch the interactive SOC Terminal User Interface (TUI)
python3 main.py tui

# Or run via CLI commands:
python3 main.py init          # Initialize database
python3 main.py simulate      # Load safe attack simulation
python3 main.py investigate   # View forensic report in terminal
python3 main.py dashboard     # Open web UI (http://127.0.0.1:5000)
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `python3 main.py tui` | **Interactive SOC Terminal User Interface** (keyboard-driven console) |
| `python3 main.py init` | Initialize SQLite database |
| `python3 main.py collect [N]` | Collect last N minutes of macOS logs + processes + LaunchItems |
| `python3 main.py detect` | Run detection rules on stored events |
| `python3 main.py simulate` | Load safe synthetic events and run detection |
| `python3 main.py investigate [id]` | Print forensic timeline and report |
| `python3 main.py run [N]` | Full pipeline: collect → store → detect |
| `python3 main.py dashboard` | Start Flask dashboard at http://127.0.0.1:5000 |

---

## FrogiSIEM Terminal User Interface (TUI Dashboard)

FrogiSIEM features a full-screen, keyboard-driven Terminal User Interface built with **Textual** and **Rich** following a dark SOC aesthetic:
- **Background**: Near-black (`#07090e` / `#0d1117`)
- **Primary Accent**: Neon Green (`#00ff66` / `#10b981`)
- **Alert Colors**: Critical/Red (`#ef4444`), Medium/Amber (`#f59e0b`), Info/Blue (`#38bdf8`)
- **Responsive Layout**: Adapts dynamically to Mac terminal windows with zero horizontal jitter.

### 5 Dedicated Investigation Screens

1. **[1] Overview Dashboard**:
   - Header with Host identity, arm64 Apple Silicon telemetry, and collector health.
   - 4 Summary Cards: Real count of Total Events, Critical/High Alerts, Medium Alerts, and Online Sensors.
   - Split layout: Live recent event stream preview alongside active detection engine status and rule registry.
2. **[2] Interactive Event Stream**:
   - DataTable of normalized security events with keyboard arrow navigation.
   - Search bar (`/`) filtering by description, process name, or subsystem.
   - Severity and Source filter dropdowns.
   - Side dossier updating dynamically on row selection with normalized identity, process PID, and raw JSON.
3. **[3] Alerts Triage Console**:
   - All correlated threat alerts with color-coded severity badges and confidence ratings.
   - Detailed Threat Investigation Dossier displaying triggering reasons, evidence chips, and Level 1 SOC response playbooks.
4. **[4] Investigation & Timeline**:
   - Chronological forensic timeline correlating system events and alert triggers.
   - Integrated Forensic Incident Report viewer.
5. **[5] Sensors & Collector Health**:
   - Health diagnostics for macOS Unified Logging System (`log show`), Process Telemetry (`ps`), and LaunchItems (`plistlib`).
   - One-key triggers: `[C]` for live 1-minute collection, `[S]` for safe attack simulation suite.

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1`–`5` | Switch directly between the 5 dashboard views |
| `↑` / `↓` | Navigate rows in DataTables |
| `Enter` | Inspect selected event or alert in full detail dossier |
| `/` | Focus search bar in Events view |
| `R` | Non-blocking data reload and sensor check |
| `C` | Trigger live macOS telemetry collection (runs in background worker) |
| `S` | Trigger safe attack simulation (runs in background worker) |
| `Esc` | Return to Overview screen |
| `Q` | Safely exit FrogiSIEM |

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
# Run complete test suite (70 tests, including async Textual TUI tests)
python3 tests/run_tests.py

# Or run with pytest:
pytest tests/ -v
```

**70 tests covering:**
- All 5 detection rules (true positive + false positive cases)
- Detection engine (empty input, malformed events, deduplication)
- Parser normalization (ULS events, processes, LaunchItems)
- Storage layer (insert, retrieve, stats, empty DB safety)
- Timeline and report generation
- Simulation data integrity
- Textual TUI asynchronous pilot tests (views, search, filters, dossiers, background workers)

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
