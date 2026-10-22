"""
storage/database.py

SQLite storage layer for Mini-SIEM.

Database file: data/siem.db  (resolved relative to the project root)

Tables:
    events, alerts, incidents, incident_events

Public API:
    init_database()
    get_connection() -> sqlite3.Connection
    insert_event(event: dict) -> int
    insert_events(events: list[dict]) -> int
    get_events(limit, offset, filters) -> list[dict]
    insert_alert(alert: dict) -> int
    get_alerts(limit, offset, severity_filter) -> list[dict]
    get_alert_count_by_severity() -> dict
    insert_incident(incident: dict) -> int
    add_event_to_incident(incident_id, event_id)
    get_db_stats() -> dict
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_BASE_DIR = Path(__file__).resolve().parent.parent   # mini-siem/
DB_PATH = _BASE_DIR / "data" / "siem.db"


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """Open a WAL-mode SQLite connection with row_factory = dict-like."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT,
    host             TEXT,
    source           TEXT,
    category         TEXT,
    event_type       TEXT,
    user             TEXT,
    process          TEXT,
    process_id       INTEGER,
    parent_process   TEXT,
    source_ip        TEXT,
    destination_ip   TEXT,
    destination_port INTEGER,
    message          TEXT,
    raw_data         TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    confidence  TEXT,
    rule_id     TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    description TEXT,
    evidence    TEXT,
    recommended_action   TEXT,
    false_positive_notes TEXT,
    status      TEXT    NOT NULL DEFAULT 'open',
    event_id    INTEGER REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    event_id    INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (incident_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_process    ON events(process);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_category   ON events(category);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id    ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents(status);
"""

# Migration: add new columns to existing alerts table if they don't exist
_MIGRATIONS = [
    "ALTER TABLE alerts ADD COLUMN confidence TEXT",
    "ALTER TABLE alerts ADD COLUMN evidence TEXT",
    "ALTER TABLE alerts ADD COLUMN recommended_action TEXT",
    "ALTER TABLE alerts ADD COLUMN false_positive_notes TEXT",
]


def init_database() -> None:
    """Create all tables and indexes. Apply migrations for existing DBs."""
    try:
        conn = get_connection()
        conn.executescript(_SCHEMA)
        conn.commit()

        # Run migrations (ignore errors for columns that already exist)
        for migration in _MIGRATIONS:
            try:
                conn.execute(migration)
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Column already exists — expected on re-init

        conn.close()
        logger.info("Database initialized at %s", DB_PATH)
    except sqlite3.Error as exc:
        logger.error("Database initialization failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def insert_event(event: dict) -> int:
    """Insert a single normalized event. Returns the new row id."""
    return insert_events([event])


def insert_events(events: list) -> int:
    """
    Insert a batch of normalized events inside a single transaction.
    Returns the number of rows successfully inserted.
    """
    if not events:
        return 0

    sql = """
        INSERT INTO events (
            timestamp, host, source, category, event_type,
            user, process, process_id, parent_process,
            source_ip, destination_ip, destination_port,
            message, raw_data
        ) VALUES (
            :timestamp, :host, :source, :category, :event_type,
            :user, :process, :process_id, :parent_process,
            :source_ip, :destination_ip, :destination_port,
            :message, :raw_data
        )
    """
    try:
        conn = get_connection()
        with conn:
            cursor = conn.executemany(sql, events)
            count = cursor.rowcount
        conn.close()
        return count
    except sqlite3.Error as exc:
        logger.error("insert_events failed: %s", exc)
        raise


def get_events(
    limit: int = 100,
    offset: int = 0,
    filters: dict | None = None,
) -> list:
    """
    Retrieve events from the database.

    filters keys: source, category, event_type, process, search (substring on message)
    """
    where_clauses: list[str] = []
    params: list = []

    if filters:
        for col in ("source", "category", "event_type", "process"):
            val = filters.get(col)
            if val:
                where_clauses.append(f"{col} = ?")
                params.append(val)
        if filters.get("search"):
            where_clauses.append("message LIKE ?")
            params.append(f"%{filters['search']}%")
        if filters.get("since"):
            where_clauses.append("timestamp >= ?")
            params.append(filters["since"])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"SELECT * FROM events {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_events(filters: dict | None = None) -> int:
    """Return the total count of events matching the given filters."""
    where_clauses: list[str] = []
    params: list = []

    if filters:
        for col in ("source", "category", "event_type", "process"):
            val = filters.get(col)
            if val:
                where_clauses.append(f"{col} = ?")
                params.append(val)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"SELECT COUNT(*) FROM events {where_sql}"

    conn = get_connection()
    row = conn.execute(sql, params).fetchone()
    conn.close()
    return row[0] if row else 0


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def insert_alert(alert: dict) -> int:
    """
    Insert an alert into the alerts table.

    Required: severity, rule_id, title
    Optional: confidence, description, evidence (dict or str), recommended_action,
              false_positive_notes, status, event_id
    """
    import json as _json

    now = datetime.now(timezone.utc).isoformat()

    evidence = alert.get("evidence")
    if isinstance(evidence, dict):
        evidence = _json.dumps(evidence, ensure_ascii=False)

    sql = """
        INSERT INTO alerts (
            created_at, severity, confidence, rule_id, title,
            description, evidence, recommended_action, false_positive_notes,
            status, event_id
        ) VALUES (
            :created_at, :severity, :confidence, :rule_id, :title,
            :description, :evidence, :recommended_action, :false_positive_notes,
            :status, :event_id
        )
    """
    row = {
        "created_at":           now,
        "severity":             alert["severity"],
        "confidence":           alert.get("confidence"),
        "rule_id":              alert["rule_id"],
        "title":                alert["title"],
        "description":          alert.get("description"),
        "evidence":             evidence,
        "recommended_action":   alert.get("recommended_action"),
        "false_positive_notes": alert.get("false_positive_notes"),
        "status":               alert.get("status", "open"),
        "event_id":             alert.get("event_id"),
    }
    try:
        conn = get_connection()
        cursor = conn.execute(sql, row)
        conn.commit()
        row_id = cursor.lastrowid
        conn.close()
        logger.warning(
            "ALERT [%s/%s] %s — rule %s",
            alert["severity"].upper(),
            alert.get("confidence", "?"),
            alert["title"][:80],
            alert["rule_id"],
        )
        return row_id
    except sqlite3.Error as exc:
        logger.error("insert_alert failed: %s", exc)
        raise


def get_alerts(
    limit: int = 100,
    offset: int = 0,
    severity_filter: str | None = None,
    status_filter: str | None = None,
) -> list:
    """Return alerts ordered by creation time descending."""
    where_clauses: list[str] = []
    params: list = []

    if severity_filter:
        where_clauses.append("severity = ?")
        params.append(severity_filter)
    if status_filter:
        where_clauses.append("status = ?")
        params.append(status_filter)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"SELECT * FROM alerts {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert_count_by_severity() -> dict:
    """Return {severity: count} for all alerts."""
    sql = "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    conn = get_connection()
    rows = conn.execute(sql).fetchall()
    conn.close()
    return {r["severity"]: r["cnt"] for r in rows}


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def insert_incident(incident: dict) -> int:
    """Insert an incident. Required: severity, title."""
    now = datetime.now(timezone.utc).isoformat()
    sql = """
        INSERT INTO incidents (created_at, updated_at, severity, title, description, status)
        VALUES (:created_at, :updated_at, :severity, :title, :description, :status)
    """
    row = {
        "created_at":  now,
        "updated_at":  now,
        "severity":    incident["severity"],
        "title":       incident["title"],
        "description": incident.get("description"),
        "status":      incident.get("status", "open"),
    }
    try:
        conn = get_connection()
        cursor = conn.execute(sql, row)
        conn.commit()
        row_id = cursor.lastrowid
        conn.close()
        return row_id
    except sqlite3.Error as exc:
        logger.error("insert_incident failed: %s", exc)
        raise


def add_event_to_incident(incident_id: int, event_id: int) -> None:
    """Link an event to an incident. Silently ignores duplicate links."""
    sql = "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)"
    try:
        conn = get_connection()
        conn.execute(sql, [incident_id, event_id])
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        logger.error("add_event_to_incident failed: %s", exc)
        raise


def get_incidents(limit: int = 50, offset: int = 0) -> list:
    """Return incidents ordered by creation time descending."""
    sql = "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ? OFFSET ?"
    conn = get_connection()
    rows = conn.execute(sql, [limit, offset]).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_incident_events(incident_id: int) -> list:
    """Return events linked to a given incident."""
    sql = """
        SELECT e.*
        FROM events e
        JOIN incident_events ie ON ie.event_id = e.id
        WHERE ie.incident_id = ?
        ORDER BY e.timestamp ASC
    """
    conn = get_connection()
    rows = conn.execute(sql, [incident_id]).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_db_stats() -> dict:
    """Return high-level statistics about the database."""
    conn = get_connection()
    event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    last_event_ts = conn.execute(
        "SELECT MAX(timestamp) FROM events"
    ).fetchone()[0]
    open_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
    ).fetchone()[0]
    conn.close()

    return {
        "event_count":    event_count,
        "alert_count":    alert_count,
        "incident_count": incident_count,
        "open_alerts":    open_alerts,
        "last_event_ts":  last_event_ts,
        "db_path":        str(DB_PATH),
    }


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    init_database()
    stats = get_db_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
