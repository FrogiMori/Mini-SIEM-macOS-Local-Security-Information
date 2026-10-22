"""
main.py — Mini-SIEM CLI entry point

Usage:
    python3 main.py init          Initialize the database
    python3 main.py collect       Collect + normalize + store logs (last 1 min)
    python3 main.py collect <N>   Collect last N minutes
    python3 main.py detect        Run detection engine (Phase 2)
    python3 main.py investigate <incident_id>   Show forensic timeline (Phase 3)
    python3 main.py run           Full pipeline: collect → normalize → store → detect → correlate
"""

import sys
import logging
from pathlib import Path

# ── Ensure sub-packages are importable when running as `python3 main.py` ──
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from collector.macos import collect_logs, parse_logs
from parser.macos import normalize_event
from storage.database import init_database, insert_event, insert_events, get_events

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mini-siem")


# ── Commands ─────────────────────────────────────────────────────────────

def cmd_init():
    """Initialize the SQLite database (idempotent)."""
    init_database()
    print("Database initialized.")


def cmd_collect(minutes: int = 1):
    """Collect macOS logs, normalize, and store in the database in fast batches."""
    logger.info("Collector started")

    raw_logs = collect_logs(minutes)
    raw_events = parse_logs(raw_logs)
    logger.info("Collected %d raw events", len(raw_events))

    normalized_events = []
    skipped = 0

    for raw in raw_events:
        normalized = normalize_event(raw)
        if normalized is None:
            skipped += 1
            continue
        normalized_events.append(normalized)

    # Insert in batches for maximum SQLite throughput
    inserted = 0
    batch_size = 2000
    for i in range(0, len(normalized_events), batch_size):
        batch = normalized_events[i : i + batch_size]
        try:
            count = insert_events(batch)
            inserted += count
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to insert event batch: %s", exc)
            skipped += len(batch)

    logger.info("Inserted %d events", inserted)
    if skipped:
        logger.warning("Malformed/failed events skipped: %d event(s)", skipped)

    print(f"Collected {len(raw_events)} events — inserted {inserted}, skipped {skipped}")


def cmd_detect():
    """Run detection engine (implemented in Phase 2)."""
    print("Detection engine not yet implemented (Phase 2).")


def cmd_investigate(incident_id: int):
    """Show forensic timeline for an incident (implemented in Phase 3)."""
    print(f"Investigation for incident {incident_id} not yet implemented (Phase 3).")


def cmd_run(minutes: int = 1):
    """Full pipeline: collect → normalize → store → detect → correlate."""
    cmd_init()
    cmd_collect(minutes)
    cmd_detect()


# ── Entry point ────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args or args[0] == "init":
        cmd_init()

    elif args[0] == "collect":
        minutes = int(args[1]) if len(args) > 1 else 1
        cmd_collect(minutes)

    elif args[0] == "detect":
        cmd_detect()

    elif args[0] == "investigate":
        if len(args) < 2:
            print("Usage: python3 main.py investigate <incident_id>")
            sys.exit(1)
        cmd_investigate(int(args[1]))

    elif args[0] == "run":
        minutes = int(args[1]) if len(args) > 1 else 1
        cmd_run(minutes)

    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
