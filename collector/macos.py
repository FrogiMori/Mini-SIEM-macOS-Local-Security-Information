"""
collector/macos.py

Collects security-relevant data from macOS using only read-only,
unprivileged sources:

  1. Unified Logging System (log show)
  2. Running processes (ps)
  3. LaunchAgent / LaunchDaemon plist inventory
  4. Basic system metadata (hostname, OS version, uptime)

All collection functions handle permission errors, timeouts, and missing
data gracefully — they never crash the pipeline.

Public API:
    collect_logs(minutes=1) -> str
    parse_logs(raw_logs: str) -> list[dict]
    collect_all(minutes=1) -> dict[str, list[dict] | dict]
    collect_processes() -> list[dict]
    collect_launch_items() -> list[dict]
    collect_system_info() -> dict
"""

import subprocess
import json
import plistlib
import logging
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Unified Logging
# ---------------------------------------------------------------------------

def collect_logs(minutes: int = 1) -> str:
    """
    Call `log show --last <minutes>m --style json` and return raw stdout.
    Returns empty string on any error so the caller can still continue.
    """
    cmd = ["log", "show", "--last", f"{minutes}m", "--style", "json"]
    logger.info("Collector: running `%s`", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        logger.error("`log` command not found. This collector requires macOS.")
        return ""
    except subprocess.TimeoutExpired:
        logger.error("`log show` timed out after 60 s — returning empty output.")
        return ""

    if result.returncode != 0:
        logger.error("`log show` failed (exit %d): %s", result.returncode, result.stderr.strip()[:300])
        return ""

    logger.info("Collector: received %d bytes from log show", len(result.stdout))
    return result.stdout


def parse_logs(raw_logs: str) -> list:
    """
    Parse raw output from `log show --style json` into a list of event dicts.

    The `log` command sometimes emits partial JSON or prepends non-JSON
    header text. We scan for the opening `[` and parse from there.
    """
    events: list = []

    if not raw_logs:
        return events

    start = raw_logs.find("[")
    if start == -1:
        logger.warning("No JSON array found in log output — 0 events parsed")
        return events

    json_text = raw_logs[start:]

    # Fast path: valid JSON array
    try:
        data = json.loads(json_text)
        if isinstance(data, list):
            logger.info("Parsed %d events (fast path)", len(data))
            return data
    except json.JSONDecodeError:
        pass

    # Slow path: stream-decode object by object
    decoder = json.JSONDecoder()
    pos = json_text.find("{")
    skipped = 0

    while pos < len(json_text):
        try:
            obj, next_pos = decoder.raw_decode(json_text, pos)
            if isinstance(obj, dict):
                events.append(obj)
            pos = next_pos
            while pos < len(json_text) and json_text[pos] in " \t\n\r,]":
                pos += 1
        except json.JSONDecodeError:
            skipped += 1
            pos += 1

    if skipped:
        logger.warning("Malformed event chunks skipped: %d", skipped)

    logger.info("Parsed %d events (streaming path)", len(events))
    return events


# ---------------------------------------------------------------------------
# Process list
# ---------------------------------------------------------------------------

def collect_processes() -> list:
    """
    Return a list of running processes via `ps`.

    Each dict contains: pid, ppid, user, cpu, mem, command, exe_path.
    Never returns None — empty list on error.
    """
    cmd = ["ps", "-eo", "pid,ppid,user,%cpu,%mem,comm"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            logger.warning("ps failed: %s", result.stderr.strip())
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.error("collect_processes error: %s", exc)
        return []

    processes: list = []
    lines = result.stdout.strip().splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        pid_str, ppid_str, user, cpu, mem, command = parts
        try:
            pid = int(pid_str)
            ppid = int(ppid_str)
        except ValueError:
            continue

        processes.append({
            "pid": pid,
            "ppid": ppid,
            "user": user,
            "cpu_pct": cpu,
            "mem_pct": mem,
            "command": command.strip(),
        })

    logger.info("Collected %d processes", len(processes))
    return processes


# ---------------------------------------------------------------------------
# LaunchAgent / LaunchDaemon inventory
# ---------------------------------------------------------------------------

_LAUNCH_DIRS: list[Path] = [
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
    Path("/System/Library/LaunchAgents"),
    Path("/System/Library/LaunchDaemons"),
    Path.home() / "Library" / "LaunchAgents",
]


def collect_launch_items() -> list:
    """
    Scan LaunchAgent/LaunchDaemon directories and return plist metadata.

    For each plist we record:
        path, label, program_args, run_at_load, start_interval,
        modified_at, readable (bool), parse_error (str|None)

    Does not load or execute any plist entries.
    """
    items: list = []

    for directory in _LAUNCH_DIRS:
        if not directory.exists():
            continue

        try:
            plist_files = list(directory.glob("*.plist"))
        except PermissionError:
            logger.warning("Permission denied reading directory: %s", directory)
            continue

        for plist_path in plist_files:
            item: dict = {
                "path": str(plist_path),
                "directory": str(directory),
                "filename": plist_path.name,
                "readable": False,
                "parse_error": None,
                "label": None,
                "program_args": None,
                "run_at_load": None,
                "start_interval": None,
                "modified_at": None,
                "collected_at": datetime.now(timezone.utc).isoformat(),
            }

            try:
                stat = plist_path.stat()
                item["modified_at"] = datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat()
                item["size_bytes"] = stat.st_size
            except OSError:
                pass

            try:
                with open(plist_path, "rb") as f:
                    data = plistlib.load(f)
                item["readable"] = True
                item["label"] = data.get("Label")
                args = data.get("ProgramArguments") or []
                item["program_args"] = args[:10] if args else None
                item["run_at_load"] = data.get("RunAtLoad")
                item["start_interval"] = data.get("StartInterval")
            except PermissionError:
                item["parse_error"] = "Permission denied"
            except Exception as exc:  # noqa: BLE001
                item["parse_error"] = str(exc)[:200]

            items.append(item)

    logger.info("Collected %d LaunchAgent/LaunchDaemon entries", len(items))
    return items


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------

def collect_system_info() -> dict:
    """
    Gather basic, non-sensitive system metadata.

    Returns a dict with: hostname, os_version, architecture, uptime_seconds,
    current_user, collected_at.
    """
    info: dict = {
        "hostname": socket.gethostname(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "os_version": None,
        "architecture": None,
        "uptime_seconds": None,
        "current_user": os.environ.get("USER") or os.environ.get("LOGNAME"),
    }

    # OS version
    try:
        result = subprocess.run(
            ["sw_vers", "-productVersion"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            info["os_version"] = result.stdout.strip()
    except Exception:  # noqa: BLE001
        pass

    # Architecture
    try:
        result = subprocess.run(
            ["uname", "-m"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            info["architecture"] = result.stdout.strip()
    except Exception:  # noqa: BLE001
        pass

    # Uptime in seconds
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # kern.boottime output: { sec = 1234567890, usec = 0 } Mon Jan 1 00:00:00 2024
            import re
            m = re.search(r"sec\s*=\s*(\d+)", result.stdout)
            if m:
                boot_epoch = int(m.group(1))
                uptime = int(datetime.now(timezone.utc).timestamp()) - boot_epoch
                info["uptime_seconds"] = uptime
    except Exception:  # noqa: BLE001
        pass

    return info


# ---------------------------------------------------------------------------
# Unified collection entry point
# ---------------------------------------------------------------------------

def collect_all(minutes: int = 1) -> dict:
    """
    Run all collectors and return a combined result dict:
        {
            "system_info": dict,
            "log_events":  list[dict],   (raw ULS events)
            "processes":   list[dict],
            "launch_items": list[dict],
        }
    """
    logger.info("Starting full collection (last %d min of logs)", minutes)

    system_info = collect_system_info()
    raw_logs = collect_logs(minutes)
    log_events = parse_logs(raw_logs)
    processes = collect_processes()
    launch_items = collect_launch_items()

    logger.info(
        "Collection complete — log_events=%d, processes=%d, launch_items=%d",
        len(log_events), len(processes), len(launch_items),
    )

    return {
        "system_info": system_info,
        "log_events": log_events,
        "processes": processes,
        "launch_items": launch_items,
    }


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    result = collect_all(minutes)

    print(f"\n=== System Info ===")
    for k, v in result["system_info"].items():
        print(f"  {k}: {v}")

    print(f"\n=== Log Events: {len(result['log_events'])} ===")
    for evt in result["log_events"][:2]:
        print(json.dumps(evt, indent=2))

    print(f"\n=== Processes: {len(result['processes'])} ===")
    for proc in result["processes"][:5]:
        print(f"  PID={proc['pid']}  {proc['command'][:60]}")

    print(f"\n=== Launch Items: {len(result['launch_items'])} ===")
    for item in result["launch_items"][:3]:
        print(f"  {item['path']}  label={item['label']}")
