# 🛡️ Mini SIEM (macOS Local Security Information & Event Management)

A lightweight, local Security Information and Event Management (SIEM) system designed specifically for macOS. It collects system and security telemetry directly from the macOS Unified Logging System (ULS), normalizes raw logs into standard security events, stores them in SQLite, runs rule-based threat detection, correlates alerts into security incidents, and provides forensic timelines and a local dashboard.

---

## 🎯 1. Target & Objectives of this Project

### Why Mini SIEM?
Enterprise SIEM solutions (like Splunk, Elastic SIEM, Microsoft Sentinel, or IBM QRadar) are complex, cloud-heavy, and resource-intensive, requiring Docker, Elasticsearch, Kafka, or cluster infrastructure. 

**Mini SIEM** is built with a different goal:
- **Zero Cloud / 100% Local**: Runs entirely on a MacBook without sending sensitive telemetry to third parties.
- **Mac-Native Forensic Telemetry**: Directly taps into macOS Unified Logging (`log show`) to capture real OS-level authentication, process, and sandbox events.
- **Educational & Defensive**: Built for security enthusiasts, blue teamers, and threat hunters to understand how SIEM architectures operate under the hood: telemetry collection, parsing/normalization, detection engineering, event correlation, and incident triage.
- **Zero Heavy Dependencies**: Pure Python 3 + SQLite + minimal web server (`FastAPI`/`uvicorn`).

> ⚠️ **Security Scope**: This project is exclusively for monitoring, detection, incident response, forensic analysis, and local threat hunting. It contains no exploit code or unauthorized activity.

---

## 🏗️ 2. Technology Stack

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Telemetry Source** | macOS Unified Logging System (`log show`) | High-fidelity Apple OS events (kernel, sandbox, auth, audit). |
| **Backend Core** | Python 3 (standard library focused) | Portable, fast to develop, clean data structures. |
| **Storage Engine** | SQLite 3 (WAL mode enabled) | Zero-configuration, ACID compliant, persistent, blazing fast local reads. |
| **API Layer** | FastAPI + Uvicorn | High-performance, asynchronous REST API serving JSON. |
| **Frontend** | Vanilla HTML5, CSS3, JavaScript | Lightweight, zero-build-step dashboard for rapid triage and visualization. |
| **Unit Testing** | `pytest` | Automated verification with mock events (no live log dependency for tests). |

---

## 🔄 3. Architecture & Data Flow

```
┌────────────────────────────────────────────────────────┐
│             macOS Unified Logging System               │
│                  (log show CLI)                        │
└──────────────────────────┬─────────────────────────────┘
                           │ Raw JSON stream
                           ▼
┌────────────────────────────────────────────────────────┐
│                   Collector Layer                      │
│                (collector/macos.py)                    │
│   • Subprocess execution & streaming JSON decoding     │
│   • Fault tolerance against truncated logs             │
└──────────────────────────┬─────────────────────────────┘
                           │ Raw Event Dicts
                           ▼
┌────────────────────────────────────────────────────────┐
│               Parser / Normalizer Layer                │
│                 (parser/macos.py)                      │
│   • Schema mapping to canonical SIEM model             │
│   • Preserves original raw_data for forensics          │
└──────────────────────────┬─────────────────────────────┘
                           │ Normalized Event Objects
                           ▼
┌────────────────────────────────────────────────────────┐
│                    SQLite Database                     │
│                 (storage/database.py)                  │
│   • events, alerts, incidents, incident_events         │
│   • WAL journal mode + indexed lookup columns          │
└──────────────────────────┬─────────────────────────────┘
                           │ Polled / Event Stream
                           ▼
┌────────────────────────────────────────────────────────┐
│                Detection Engine (Rules)                │
│                 (detection/engine.py)                  │
│   • Time-window aggregation & threshold counting       │
│   • Generates structured Alerts                        │
└──────────────────────────┬─────────────────────────────┘
                           │ Alerts
                           ▼
┌────────────────────────────────────────────────────────┐
│              Correlation & Investigation               │
│          (investigation/correlation.py & timeline.py)  │
│   • Groups alerts into high-level Incidents            │
│   • Constructs sorted forensic chronological timelines │
└──────────────────────────┬─────────────────────────────┘
                           │ REST API
                           ▼
┌────────────────────────────────────────────────────────┐
│               FastAPI Server & Dashboard               │
│           (api/server.py & dashboard/index.html)       │
│   • Metrics, event search, alert triage, timeline view │
└────────────────────────────────────────────────────────┘
```

---

## 🧠 4. Core Logic & How Each Layer Works

### A. Telemetry Collection (`collector/macos.py`)
- Executes macOS native `log show --last <N>m --style json`.
- Implements dual-strategy decoding:
  1. **Fast-path**: Attempts batch `json.loads` for maximum throughput.
  2. **Streaming fallback**: Uses `json.JSONDecoder().raw_decode` to parse object-by-object, gracefully recovering if OS log messages contain malformed boundaries or non-JSON headers.

### B. Normalization (`parser/macos.py`)
Raw macOS log records contain dozens of OS-internal keys (`processImageUUID`, `machTimestamp`, `senderProgramCounter`, etc.). The parser strips noise and projects them into a uniform schema:
- `timestamp`: Formatted event timestamp.
- `host`: Local hostname.
- `source`: Subsystem or sender library (e.g. `com.apple.securityd`, `Sandbox`).
- `category` & `event_type`: Log category and severity (`Default`, `Info`, `Error`, `Fault`).
- `user`: User ID (`userID`).
- `process` & `process_id`: Binary executable name and PID.
- `message`: Human-readable log message.
- `raw_data`: Full untouched original JSON string (critical for forensic non-repudiation).

### C. Storage Schema (`storage/database.py`)
Four interconnected relational tables:
1. `events`: Flattened security and system telemetry with B-tree indexes on `timestamp`, `process`, and `event_type`.
2. `alerts`: Security findings flagged by detection rules (`severity`, `rule_id`, `status`).
3. `incidents`: Aggregated attack patterns or suspicious sessions.
4. `incident_events`: Many-to-many junction table associating forensic events with incidents.

### D. Detection Engine (`detection/engine.py` & rules)
Reads JSON detection definitions and evaluates events:
- **Brute Force Detection**: Flags high volume of authentication failures within rolling time windows (e.g., 5 failures in 60s).
- **Suspicious Process Lineage**: Detects anomalous parent-child relationships or suspicious execution paths.
- **Unusual Activity / Network Telemetry**: Identifies irregular connections or burst behaviors.

### E. Correlation & Forensic Timeline (`investigation/`)
- Aggregates related alerts sharing common pivots (same host, user, or time window) into unified **Incidents**.
- Reconstructs a chronological, millisecond-accurate timeline illustrating the attacker/process journey (e.g., *Failed Logins → Sudo Privilege → Process Spawn*).

---

## 📁 5. Project Directory Structure

```
mini-siem/
├── collector/
│   ├── __init__.py
│   └── macos.py                 # macOS log show collector & JSON stream parser
├── parser/
│   ├── __init__.py
│   └── macos.py                 # Telemetry normalizer
├── storage/
│   ├── __init__.py
│   └── database.py              # SQLite schema, WAL mode, queries & inserts
├── detection/
│   ├── __init__.py
│   ├── engine.py                # Rule evaluation engine
│   └── rules/                   # Detection rule JSON definitions
│       ├── brute_force.json
│       ├── suspicious_process.json
│       └── unusual_network.json
├── investigation/
│   ├── __init__.py
│   ├── timeline.py              # Forensic timeline generator
│   └── correlation.py           # Multi-event correlation into incidents
├── api/
│   ├── __init__.py
│   └── server.py                # FastAPI endpoints
├── dashboard/
│   ├── index.html               # Main SIEM dashboard overview
│   ├── events.html              # Searchable event log explorer
│   ├── alerts.html              # Alert triage table
│   ├── incidents.html           # Incident manager
│   ├── investigation.html       # Forensic timeline view
│   ├── css/style.css
│   └── js/app.js
├── tests/
│   ├── test_collector.py
│   ├── test_parser.py
│   ├── test_database.py
│   └── test_detection.py
├── data/
│   └── siem.db                  # Local SQLite database (git-ignored)
├── main.py                      # CLI entrypoint for orchestrating the SIEM
├── requirements.txt             # Minimal dependencies (fastapi, uvicorn, pytest)
├── .gitignore
└── README.md
```

---

## 🚀 6. Installation & Quickstart

### Prerequisites
- macOS (tested on macOS Ventura, Sonoma, Sequoia)
- Python 3.10+

### Setup Environment
```bash
# Navigate to the workspace
cd /Users/nam/Cyber_sec

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install requirements
cd mini-siem
pip install -r requirements.txt
```

---

## 💻 7. CLI Usage

Run tasks directly from the `mini-siem` directory:

### 1. Initialize the Database
Creates the tables and indexes in `data/siem.db`:
```bash
python3 main.py init
```

### 2. Collect Real macOS Logs
Harvests the last 1 minute (or N minutes) of telemetry, normalizes it, and saves it to SQLite:
```bash
# Collect last 1 minute
python3 main.py collect 1

# Collect last 5 minutes
python3 main.py collect 5
```

### 3. Run the Full End-to-End Pipeline
Runs initialization, log collection, parsing, detection, and correlation in one command:
```bash
python3 main.py run 1
```

---

## 🔍 8. Example Forensic Investigation Scenario

1. **Detection**: `brute_force.json` rule matches repeated `Failed to authenticate` messages from `loginwindow` or `sshd`.
2. **Alert Raised**: An alert of severity `HIGH` titled `Possible brute-force activity` is stored.
3. **Correlation**: Correlation engine links the failed attempts and subsequent successful process spawn into a single `Incident`.
4. **Timeline**: The analyst inspects the chronological forensic timeline:
   ```text
   2026-10-03 00:30:10 | com.apple.authd | Authentication failure (user: admin)
   2026-10-03 00:30:12 | com.apple.authd | Authentication failure (user: admin)
   2026-10-03 00:30:15 | com.apple.authd | Authentication failure (user: admin)
   2026-10-03 00:30:18 | com.apple.authd | Authentication failure (user: admin)
   2026-10-03 00:30:20 | com.apple.authd | Authentication failure (user: admin)
   --> ALERT TRIGGERED: Possible brute-force activity
   2026-10-03 00:30:35 | com.apple.authd | Authentication success (user: admin)
   2026-10-03 00:30:40 | kernel          | Process spawned: /bin/zsh (PID: 4921)
   ```

---

## ⚠️ 9. Limitations & Future Roadmap

- **Log Volume**: A busy Mac generates ~10,000–50,000 log events per minute. Bulk batch insertions (`executemany`) and filtering flags are recommended for longer time windows.
- **Parent Process IDs**: macOS Unified Logging does not always expose PPID in standard log format; future versions can enrich this via Endpoint Security Framework (ESF) or `ps`/`libproc` hooks.
- **Network Telemetry**: Unified Logging logs system network calls; integration with local packet statistics or network extension logs is planned for future phases.
