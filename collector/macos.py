"""
collector/macos.py

Collects security/system logs from macOS Unified Logging System
using the `log show` command.

Internal API:
    collect_logs(minutes=1) -> str
    parse_logs(raw_logs: str) -> list[dict]

Run standalone:
    python3 collector/macos.py
"""

import subprocess
import json
import logging

logger = logging.getLogger(__name__)


def collect_logs(minutes: int = 1) -> str:
    """
    Call `log show --last <minutes>m --style json` and return raw stdout.

    Args:
        minutes: How many past minutes of logs to retrieve.

    Returns:
        Raw JSON string from the `log` command.

    Raises:
        RuntimeError: If the log command exits with a non-zero status.
    """
    cmd = [
        "log", "show",
        "--last", f"{minutes}m",
        "--style", "json",
    ]

    logger.info("Collector started: running `%s`", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "`log` command not found. This collector requires macOS."
        )

    if result.returncode != 0:
        raise RuntimeError(
            f"`log show` failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    logger.info("Collector finished: received %d bytes", len(result.stdout))
    return result.stdout


def parse_logs(raw_logs: str) -> list:
    """
    Parse raw output from `log show --style json` into a list of event dicts.

    The `log` command sometimes emits partial JSON or prepends non-JSON
    header text, so we scan for the opening `[` and parse from there.
    Malformed entries are skipped with a warning rather than crashing.

    Args:
        raw_logs: Raw string output from collect_logs().

    Returns:
        List of raw event dicts as returned by the OS.
    """
    events = []

    # Find the start of the JSON array
    start = raw_logs.find("[")
    if start == -1:
        logger.warning("No JSON array found in log output — 0 events parsed")
        return events

    json_text = raw_logs[start:]

    # Try fast-path: the whole thing is valid JSON
    try:
        data = json.loads(json_text)
        if isinstance(data, list):
            logger.info("Parsed %d events (fast path)", len(data))
            return data
    except json.JSONDecodeError:
        pass

    # Slow-path: stream-decode object-by-object in case output is truncated
    decoder = json.JSONDecoder()
    pos = 0
    skipped = 0

    # skip the leading `[`
    pos = json_text.find("{")

    while pos < len(json_text):
        try:
            obj, next_pos = decoder.raw_decode(json_text, pos)
            if isinstance(obj, dict):
                events.append(obj)
            pos = next_pos
            # skip whitespace and comma between objects
            while pos < len(json_text) and json_text[pos] in " \t\n\r,]":
                pos += 1
        except json.JSONDecodeError:
            skipped += 1
            pos += 1

    if skipped:
        logger.warning("Malformed event skipped: %d chunk(s) could not be decoded", skipped)

    logger.info("Parsed %d events (streaming path)", len(events))
    return events


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    raw = collect_logs(minutes)
    events = parse_logs(raw)

    print(f"Collected {len(events)} events")

    # Print a small sample so the user can inspect the schema
    for evt in events[:3]:
        print(json.dumps(evt, indent=2))
