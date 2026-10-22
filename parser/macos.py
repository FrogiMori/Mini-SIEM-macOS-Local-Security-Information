"""
parser/macos.py

Normalizes raw macOS Unified Log events (dicts from collector/macos.py)
into the canonical Mini-SIEM event schema.

Internal API:
    normalize_event(raw_event: dict) -> dict
"""

import json
import socket
import logging

logger = logging.getLogger(__name__)

# Hostname is constant for the life of the process
_HOSTNAME = socket.gethostname()


def _safe_get(d: dict, *keys, default=None):
    """Return the first key that exists and is not None/empty, else default."""
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            return v
    return default


def normalize_event(raw_event: dict) -> dict:
    """
    Convert a raw macOS Unified Log event dict into the Mini-SIEM schema.

    Fields that are missing or empty in the source are set to None rather
    than raising an exception.

    Normalized schema:
        timestamp        str   - ISO-like timestamp from the OS
        host             str   - hostname of this machine
        source           str   - subsystem identifier (e.g. com.apple.security)
        category         str   - log category within the subsystem
        event_type       str   - messageType (Default / Info / Error / Fault)
        user             str   - numeric uid as string (macOS logs don't expose username)
        process          str   - short process name derived from processImagePath
        process_id       int   - PID
        parent_process   str   - always None in ULS (parent PID not exposed)
        source_ip        str   - None (not present in ULS events)
        destination_ip   str   - None (not present in ULS events)
        destination_port int   - None (not present in ULS events)
        message          str   - human-readable event message
        raw_data         str   - original event as JSON string
    """
    try:
        # Derive short process name from full image path
        image_path = _safe_get(raw_event, "processImagePath") or ""
        process_name = image_path.split("/")[-1] if image_path else None

        # uid from userID field (int → str so it fits a "user" text column)
        user_id = raw_event.get("userID")
        user = str(user_id) if user_id is not None else None

        normalized = {
            "timestamp":        _safe_get(raw_event, "timestamp"),
            "host":             _HOSTNAME,
            "source":           _safe_get(raw_event, "subsystem", "senderImagePath"),
            "category":         _safe_get(raw_event, "category"),
            "event_type":       _safe_get(raw_event, "messageType"),
            "user":             user,
            "process":          process_name,
            "process_id":       raw_event.get("processID"),
            "parent_process":   None,   # Not available in macOS ULS
            "source_ip":        None,   # Not available in macOS ULS
            "destination_ip":   None,   # Not available in macOS ULS
            "destination_port": None,   # Not available in macOS ULS
            "message":          _safe_get(raw_event, "eventMessage"),
            "raw_data":         json.dumps(raw_event, ensure_ascii=False),
        }

        return normalized

    except Exception as exc:  # noqa: BLE001
        logger.warning("Malformed event skipped during normalization: %s", exc)
        return None
