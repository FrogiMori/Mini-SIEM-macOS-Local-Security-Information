"""
parser/macos.py

Normalizes raw macOS data into the canonical Mini-SIEM event schema.

Handles three source types:
  - ULS log events    (from collector.macos.parse_logs)
  - Process snapshots (from collector.macos.collect_processes)
  - LaunchItem plists (from collector.macos.collect_launch_items)

Public API:
    normalize_event(raw_event: dict) -> dict | None
    normalize_process(raw_proc: dict, host: str | None = None) -> dict | None
    normalize_launch_item(raw_item: dict, host: str | None = None) -> dict | None
"""

from __future__ import annotations

import json
import socket
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_HOSTNAME = socket.gethostname()


def _safe_get(d: dict, *keys, default=None):
    """Return the value for the first key that exists and is non-empty."""
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            return v
    return default


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# ULS log event normalizer
# ---------------------------------------------------------------------------

def normalize_event(raw_event: dict) -> dict | None:
    """
    Convert a raw macOS Unified Log event dict into the Mini-SIEM schema.

    Canonical schema fields:
        timestamp, host, source, category, event_type, user, process,
        process_id, parent_process, source_ip, destination_ip,
        destination_port, message, raw_data
    """
    if not isinstance(raw_event, dict):
        return None

    try:
        image_path = _safe_get(raw_event, "processImagePath") or ""
        process_name = image_path.split("/")[-1] if image_path else None

        user_id = raw_event.get("userID")
        user = str(user_id) if user_id is not None else None

        return {
            "timestamp":        _safe_get(raw_event, "timestamp"),
            "host":             _HOSTNAME,
            "source":           _safe_get(raw_event, "subsystem", "senderImagePath"),
            "category":         _safe_get(raw_event, "category"),
            "event_type":       _safe_get(raw_event, "messageType"),
            "user":             user,
            "process":          process_name,
            "process_id":       raw_event.get("processID"),
            "parent_process":   None,           # Not available in macOS ULS
            "source_ip":        None,           # Not available in macOS ULS
            "destination_ip":   None,           # Not available in macOS ULS
            "destination_port": None,           # Not available in macOS ULS
            "message":          _safe_get(raw_event, "eventMessage"),
            "raw_data":         json.dumps(raw_event, ensure_ascii=False),
        }

    except Exception as exc:  # noqa: BLE001
        logger.warning("normalize_event: skipped malformed event: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Process snapshot normalizer
# ---------------------------------------------------------------------------

def normalize_process(raw_proc: dict, host: str | None = None) -> dict | None:
    """
    Convert a process dict (from collect_processes) into the SIEM schema.

    Maps: pid → process_id, command → process + message, user → user.
    """
    if not isinstance(raw_proc, dict):
        return None

    try:
        pid = raw_proc.get("pid")
        command = raw_proc.get("command") or ""
        process_name = command.split("/")[-1].split()[0] if command else None

        return {
            "timestamp":        _now_iso(),
            "host":             host or _HOSTNAME,
            "source":           "mini-siem/process-collector",
            "category":         "process_snapshot",
            "event_type":       "Info",
            "user":             raw_proc.get("user"),
            "process":          process_name,
            "process_id":       pid,
            "parent_process":   str(raw_proc.get("ppid")) if raw_proc.get("ppid") else None,
            "source_ip":        None,
            "destination_ip":   None,
            "destination_port": None,
            "message":          (
                f"Process {process_name} (PID {pid}) "
                f"cpu={raw_proc.get('cpu_pct','?')}% "
                f"mem={raw_proc.get('mem_pct','?')}%"
            ),
            "raw_data":         json.dumps(raw_proc, ensure_ascii=False),
        }

    except Exception as exc:  # noqa: BLE001
        logger.warning("normalize_process: skipped malformed proc: %s", exc)
        return None


# ---------------------------------------------------------------------------
# LaunchItem normalizer
# ---------------------------------------------------------------------------

def normalize_launch_item(raw_item: dict, host: str | None = None) -> dict | None:
    """
    Convert a LaunchItem dict (from collect_launch_items) into the SIEM schema.

    The 'message' field summarises the plist label and program args.
    """
    if not isinstance(raw_item, dict):
        return None

    try:
        label = raw_item.get("label") or raw_item.get("filename") or "unknown"
        args = raw_item.get("program_args") or []
        args_str = " ".join(str(a) for a in args[:5]) if args else "(unknown)"

        return {
            "timestamp":        raw_item.get("collected_at") or _now_iso(),
            "host":             host or _HOSTNAME,
            "source":           "mini-siem/launch-item-collector",
            "category":         "launch_item",
            "event_type":       "Info",
            "user":             None,
            "process":          label,
            "process_id":       None,
            "parent_process":   None,
            "source_ip":        None,
            "destination_ip":   None,
            "destination_port": None,
            "message":          (
                f"LaunchItem '{label}' in {raw_item.get('directory', '?')}: "
                f"run_at_load={raw_item.get('run_at_load')} "
                f"args={args_str}"
            ),
            "raw_data":         json.dumps(raw_item, ensure_ascii=False),
        }

    except Exception as exc:  # noqa: BLE001
        logger.warning("normalize_launch_item: skipped malformed item: %s", exc)
        return None
