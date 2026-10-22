"""
storage/database.py

SQLite storage layer for Mini-SIEM.

Database file: data/siem.db  (resolved relative to this file's location,
so it works regardless of which directory the caller runs from)

Tables:
    events, alerts, incidents, incident_events

Public API:
    init_database()
    get_connection() -> sqlite3.Connection
    insert_event(event: dict) -> int
    get_events(limit, offset, filters) -> list[dict]
    insert_alert(alert: dict) -> int
    get_alerts(limit, offset) -> list[dict]
    insert_incident(incident: dict) -> int
    add_event_to_incident(incident_id, event_id)
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Always store the DB next to the data/ directory that sits beside this file
_BASE_DIR = Path(__file__).resolve().parent.parent   # mini-siem/
DB_PATH = _BASE_DIR / "data" / "siem.db"


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """
    Open and return a SQLite connection to the SIEM database.

    The data/ directory is created automatically if it does not exist.
    The connection has row_factory set so rows are returned as dicts.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # safer for concurrent reads
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
    rule_id     TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    description TEXT,
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
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents(status);
"""


def init_database() -> None:
    """Create all tables and indexes if they don't exist yet."""
    try:
        conn = get_connection()
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()
        logger.info("Database initialized at %s", DB_PATH)
    except sqlite3.Error as exc:
        logger.error("Database connection failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def insert_event(event: dict) -> int:
    """
    Insert a single normalized event into the events table.
    """
    return insert_events([event])


def insert_events(events: list) -> int:
    """
    Insert a batch of normalized events inside a single transaction.

    Args:
        events: List of event dicts matching the canonical schema.

    Returns:
        Number of events successfully inserted.
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
        logger.error("Database connection failed (insert_events): %s", exc)
        raise


def get_events(
    limit: int = 100,
    offset: int = 0,
    filters: dict | None = None,
) -> list:
    """
    Retrieve events from the database.

    Args:
        limit:   Max rows to return.
        offset:  Row offset for pagination.
        filters: Optional dict with keys: source, category, event_type, process.
                 Only non-None values are applied as WHERE clauses.

    Returns:
        List of row dicts.
    """
    where_clauses = []
    params: list = []

    if filters:
        for col in ("source", "category", "event_type", "process"):
            val = filters.get(col)
            if val is not None:
                where_clauses.append(f"{col} = ?")
                params.append(val)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"SELECT * FROM events {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def insert_alert(alert: dict) -> int:
    """
    Insert an alert.

    Required keys: severity, rule_id, title
    Optional keys: description, status (default 'open'), event_id
    """
    now = datetime.now(timezone.utc).isoformat()
    sql = """
        INSERT INTO alerts (created_at, severity, rule_id, title, description, status, event_id)
        VALUES (:created_at, :severity, :rule_id, :title, :description, :status, :event_id)
    """
    row = {
        "created_at":  now,
        "severity":    alert["severity"],
        "rule_id":     alert["rule_id"],
        "title":       alert["title"],
        "description": alert.get("description"),
        "status":      alert.get("status", "open"),
        "event_id":    alert.get("event_id"),
    }
    try:
        conn = get_connection()
        cursor = conn.execute(sql, row)
        conn.commit()
        row_id = cursor.lastrowid
        conn.close()
        logger.warning(
            "ALERT: Detection rule %s matched — %s [%s]",
            alert["rule_id"], alert["title"], alert["severity"].upper(),
        )
        return row_id
    except sqlite3.Error as exc:
        logger.error("Database connection failed (insert_alert): %s", exc)
        raise


def get_alerts(limit: int = 100, offset: int = 0) -> list:
    """Return alerts ordered by creation time descending."""
    sql = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?"
    conn = get_connection()
    rows = conn.execute(sql, [limit, offset]).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def insert_incident(incident: dict) -> int:
    """
    Insert an incident.

    Required keys: severity, title
    Optional keys: description, status (default 'open')
    """
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
        logger.error("Database connection failed (insert_incident): %s", exc)
        raise


def add_event_to_incident(incident_id: int, event_id: int) -> None:
    """Link an event to an incident. Silently ignores duplicate links."""
    sql = """
        INSERT OR IGNORE INTO incident_events (incident_id, event_id)
        VALUES (?, ?)
    """
    try:
        conn = get_connection()
        conn.execute(sql, [incident_id, event_id])
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        logger.error("Database connection failed (add_event_to_incident): %s", exc)
        raise


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    init_database()
    print(f"Database initialized at {DB_PATH}")
    print(f"Events in DB : {len(get_events(limit=1_000_000))}")
    print(f"Alerts in DB : {len(get_alerts(limit=1_000_000))}")
