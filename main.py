"""
main.py — Mini-SIEM CLI entry point

Usage:
    python3 main.py init                   Initialize the database
    python3 main.py collect                Collect + normalize + store (last 1 min)
    python3 main.py collect <N>            Collect last N minutes of logs
    python3 main.py detect                 Run detection engine on stored events
    python3 main.py simulate               Load safe simulation data and run detection
    python3 main.py investigate            Show timeline and report for latest data
    python3 main.py investigate <id>       Show forensic timeline for incident <id>
    python3 main.py run [<N>]             Full pipeline: collect → store → detect
    python3 main.py dashboard              Start the web dashboard (http://127.0.0.1:5000)
"""

import sys
import logging
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from collector.macos import collect_all
from parser.macos import normalize_event, normalize_process, normalize_launch_item
from storage.database import (
    init_database, insert_events, get_events, get_alerts, get_db_stats,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mini-siem")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init():
    """Initialize the SQLite database (idempotent)."""
    init_database()
    stats = get_db_stats()
    print(f"Database initialized at {stats['db_path']}")
    print(f"  Events : {stats['event_count']}")
    print(f"  Alerts : {stats['alert_count']}")


def cmd_collect(minutes: int = 1):
    """Collect macOS logs + processes + LaunchItems, normalize, and store."""
    logger.info("Starting collection (last %d min)", minutes)
    init_database()

    data = collect_all(minutes=minutes)
    events: list[dict] = []

    for raw in data.get("log_events", []):
        n = normalize_event(raw)
        if n:
            events.append(n)

    for raw in data.get("processes", []):
        n = normalize_process(raw)
        if n:
            events.append(n)

    for raw in data.get("launch_items", []):
        n = normalize_launch_item(raw)
        if n:
            events.append(n)

    skipped = (
        len(data.get("log_events", [])) +
        len(data.get("processes", [])) +
        len(data.get("launch_items", []))
    ) - len(events)

    # Batch insert
    inserted = 0
    for i in range(0, len(events), 2000):
        batch = events[i:i + 2000]
        try:
            inserted += insert_events(batch)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Batch insert failed: %s", exc)

    sys_info = data.get("system_info", {})
    print(f"\nCollection complete:")
    print(f"  Host         : {sys_info.get('hostname', '?')}")
    print(f"  OS           : {sys_info.get('os_version', '?')}")
    print(f"  Architecture : {sys_info.get('architecture', '?')}")
    print(f"  Log events   : {len(data.get('log_events', []))}")
    print(f"  Processes    : {len(data.get('processes', []))}")
    print(f"  Launch items : {len(data.get('launch_items', []))}")
    print(f"  Stored       : {inserted} events  (skipped: {skipped})")


def cmd_detect():
    """Run detection engine on all stored events."""
    from detection.engine import run_detection

    init_database()
    logger.info("Running detection engine...")
    alerts = run_detection()

    if not alerts:
        print("No new alerts generated.")
        return

    print(f"\n{'─'*60}")
    print(f"  {len(alerts)} new alert(s):")
    print(f"{'─'*60}")

    for alr in alerts:
        sev = (alr.get("severity") or "?").upper()
        conf = (alr.get("confidence") or "?")
        rule = alr.get("rule_id") or "?"
        title = alr.get("title") or "?"
        print(f"  [{sev}/{conf}] [{rule}] {title}")

    print(f"{'─'*60}")
    print(f"  Use `python3 main.py investigate` or start the dashboard to see details.")


def cmd_simulate():
    """Load safe simulation data and run detection."""
    from data.sample_events import get_sample_events
    from detection.engine import run_detection_on_events

    init_database()
    events = get_sample_events()
    count = insert_events(events)
    print(f"Loaded {count} simulation events into database.")

    # Fetch back (with IDs) then detect
    stored = get_events(limit=len(events) + 200)
    alerts = run_detection_on_events(stored)

    # Persist alerts
    from storage.database import insert_alert
    from detection.engine import _prepare_for_db, _load_existing_alert_keys
    existing = _load_existing_alert_keys()
    new_count = 0
    for alr in alerts:
        key = (alr.get("rule_id"), alr.get("event_id"))
        if key not in existing:
            try:
                insert_alert(_prepare_for_db(alr))
                new_count += 1
                existing.add(key)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to persist alert: %s", exc)

    print(f"\nSimulation complete:")
    print(f"  Events stored  : {count}")
    print(f"  Alerts found   : {len(alerts)}")
    print(f"  Alerts stored  : {new_count}")

    print(f"\nSample alerts:")
    for alr in alerts[:5]:
        sev = (alr.get("severity") or "?").upper()
        print(f"  [{sev}] [{alr.get('rule_id')}] {alr.get('title', '')}")


def cmd_investigate(incident_id: int | None = None):
    """Build and print a forensic timeline / report."""
    from investigation.timeline import generate_report, build_timeline
    from collector.macos import collect_system_info

    init_database()
    events = get_events(limit=500)
    alerts = get_alerts(limit=200)

    try:
        sys_info = collect_system_info()
    except Exception:
        sys_info = None

    report = generate_report(incident_id, events, alerts, sys_info)
    print(report)


def cmd_run(minutes: int = 1):
    """Full pipeline: init → collect → detect."""
    cmd_init()
    cmd_collect(minutes)
    cmd_detect()


def cmd_dashboard():
    """Start the Flask web dashboard."""
    import subprocess, sys as _sys
    dashboard_script = _HERE / "dashboard" / "app.py"
    print("Starting dashboard at http://127.0.0.1:5000 ...")
    try:
        subprocess.run([_sys.executable, str(dashboard_script)])
    except KeyboardInterrupt:
        print("\nDashboard stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    if not args or args[0] == "init":
        cmd_init()

    elif args[0] == "collect":
        minutes = int(args[1]) if len(args) > 1 else 1
        cmd_collect(minutes)

    elif args[0] == "detect":
        cmd_detect()

    elif args[0] == "simulate":
        cmd_simulate()

    elif args[0] == "investigate":
        incident_id = int(args[1]) if len(args) > 1 else None
        cmd_investigate(incident_id)

    elif args[0] == "run":
        minutes = int(args[1]) if len(args) > 1 else 1
        cmd_run(minutes)

    elif args[0] == "dashboard":
        cmd_dashboard()

    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
