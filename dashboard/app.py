"""
dashboard/app.py

Mini-SIEM web dashboard — Flask-based, localhost only.

Start:
    python3 dashboard/app.py
    # Then open http://127.0.0.1:5000

Features:
  - Overview: event count, alert severity breakdown, collector status
  - Alerts table with severity colour-coding and filter
  - Timeline view
  - Alert detail modal
  - Simulate button (loads demo data from data/sample_events.json)
  - Run collection / detection from the UI
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from flask import Flask, jsonify, render_template_string, request, redirect, url_for

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)   # session cookie key — not stored anywhere


# ---------------------------------------------------------------------------
# HTML templates (inline — no external files required)
# ---------------------------------------------------------------------------

_BASE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mini-SIEM Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
    --critical: #ff4444; --high: #ff8c00;
    --medium: #e3b341; --low: #3fb950; --info: #58a6ff;
    --accent: #1f6feb;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'SF Mono', 'Consolas', monospace; font-size: 13px; }
  a { color: var(--info); text-decoration: none; }
  a:hover { text-decoration: underline; }
  nav { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 20px; display: flex; align-items: center; gap: 20px; }
  nav .logo { font-size: 16px; font-weight: bold; color: var(--info); }
  nav a { color: var(--muted); }
  nav a:hover { color: var(--text); }
  .main { padding: 20px; max-width: 1400px; margin: 0 auto; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card .val { font-size: 28px; font-weight: bold; margin-bottom: 4px; }
  .card .lbl { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
  .card.critical .val { color: var(--critical); }
  .card.high .val     { color: var(--high); }
  .card.medium .val   { color: var(--medium); }
  .card.low .val      { color: var(--low); }
  .card.info .val     { color: var(--info); }
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .section h2 { font-size: 14px; color: var(--muted); text-transform: uppercase; letter-spacing: .07em; margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  td { padding: 7px 8px; border-bottom: 1px solid #21262d; vertical-align: top; }
  tr:hover td { background: #1c2128; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .badge.critical { background: #3d0000; color: var(--critical); }
  .badge.high     { background: #3d1a00; color: var(--high); }
  .badge.medium   { background: #3d2e00; color: var(--medium); }
  .badge.low      { background: #0d2b0d; color: var(--low); }
  .badge.event    { background: #0d1f3d; color: var(--info); }
  .badge.alert    { background: #2d0d2d; color: #c678dd; }
  .btn { display: inline-block; padding: 7px 16px; border-radius: 6px; border: 1px solid var(--border); cursor: pointer; font-size: 12px; color: var(--text); background: var(--surface); text-decoration: none; }
  .btn:hover { background: #21262d; }
  .btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  .btn.primary:hover { background: #388bfd; }
  .btn.danger  { background: #3d0000; border-color: var(--critical); color: var(--critical); }
  .btn.danger:hover { background: #500000; }
  .toolbar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
  select, input[type=text] { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 6px; font-size: 12px; }
  .timeline { list-style: none; padding: 0; }
  .timeline li { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid #21262d; }
  .timeline .ts { color: var(--muted); min-width: 160px; font-size: 11px; }
  .timeline .title { flex: 1; }
  .flash { padding: 10px 16px; border-radius: 6px; margin-bottom: 12px; background: #1f2d1f; border: 1px solid var(--low); color: var(--low); }
  .flash.error { background: #2d1010; border-color: var(--critical); color: var(--critical); }
  .mono { font-family: 'SF Mono', 'Consolas', monospace; font-size: 11px; }
  .detail-box { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-top: 8px; white-space: pre-wrap; word-break: break-all; font-size: 11px; max-height: 300px; overflow-y: auto; }
</style>
</head>
<body>
<nav>
  <span class="logo">🛡 Mini-SIEM</span>
  <a href="/">Overview</a>
  <a href="/alerts">Alerts</a>
  <a href="/events">Events</a>
  <a href="/timeline">Timeline</a>
  <a href="/report">Report</a>
</nav>
<div class="main">
{% if flash_msg %}
  <div class="flash {{ flash_cls }}">{{ flash_msg }}</div>
{% endif %}
{{ content }}
</div>
</body>
</html>"""


def _render(content: str, flash_msg: str = "", flash_cls: str = "") -> str:
    from storage.database import get_db_stats
    try:
        stats = get_db_stats()
    except Exception:
        stats = {}
    return render_template_string(
        _BASE_HTML,
        content=content,
        flash_msg=flash_msg,
        flash_cls=flash_cls,
        stats=stats,
    )


def _sev_badge(sev: str) -> str:
    s = (sev or "low").lower()
    return f'<span class="badge {s}">{s}</span>'


def _kind_badge(kind: str) -> str:
    return f'<span class="badge {kind}">{kind}</span>'


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def overview():
    from storage.database import get_db_stats, get_alert_count_by_severity
    try:
        stats = get_db_stats()
        sev_counts = get_alert_count_by_severity()
    except Exception as exc:
        return _render(f'<div class="flash error">Database error: {exc}</div>')

    cards_html = f"""
<div class="cards">
  <div class="card info">
    <div class="val">{stats.get('event_count', 0)}</div>
    <div class="lbl">Total Events</div>
  </div>
  <div class="card {'critical' if sev_counts.get('critical', 0) else 'low'}">
    <div class="val">{sev_counts.get('critical', 0)}</div>
    <div class="lbl">Critical Alerts</div>
  </div>
  <div class="card {'high' if sev_counts.get('high', 0) else 'low'}">
    <div class="val">{sev_counts.get('high', 0)}</div>
    <div class="lbl">High Alerts</div>
  </div>
  <div class="card medium">
    <div class="val">{sev_counts.get('medium', 0)}</div>
    <div class="lbl">Medium Alerts</div>
  </div>
  <div class="card low">
    <div class="val">{sev_counts.get('low', 0)}</div>
    <div class="lbl">Low Alerts</div>
  </div>
  <div class="card info">
    <div class="val">{stats.get('open_alerts', 0)}</div>
    <div class="lbl">Open Alerts</div>
  </div>
</div>
"""

    last_ts = stats.get("last_event_ts") or "—"
    db_path = stats.get("db_path") or "—"

    actions_html = f"""
<div class="section">
  <h2>Actions</h2>
  <div class="toolbar">
    <form method="post" action="/action/collect" style="display:inline">
      <button class="btn primary" type="submit">▶ Collect (1 min)</button>
    </form>
    <form method="post" action="/action/detect" style="display:inline">
      <button class="btn" type="submit">🔍 Run Detection</button>
    </form>
    <form method="post" action="/action/simulate" style="display:inline">
      <button class="btn danger" type="submit">🧪 Load Simulation Data</button>
    </form>
  </div>
  <p style="color:var(--muted); margin-top:8px; font-size:11px;">
    Last event: {last_ts} &nbsp;|&nbsp; DB: {db_path}
  </p>
</div>
"""

    content = cards_html + actions_html
    return _render(content)


@app.route("/alerts")
def alerts_view():
    from storage.database import get_alerts

    sev_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    offset = (page - 1) * per_page

    alerts = get_alerts(
        limit=per_page,
        offset=offset,
        severity_filter=sev_filter or None,
        status_filter=status_filter or None,
    )

    rows = ""
    for alr in alerts:
        sev = (alr.get("severity") or "low").lower()
        conf = alr.get("confidence") or "?"
        ts = (alr.get("created_at") or "")[:19]
        rule = alr.get("rule_id") or ""
        title = alr.get("title") or ""
        aid = alr.get("id")
        rows += f"""
<tr>
  <td>{_sev_badge(sev)}</td>
  <td style="color:var(--muted)">{conf}</td>
  <td style="color:var(--muted)">{ts}</td>
  <td><code>{rule}</code></td>
  <td><a href="/alerts/{aid}">{title[:80]}</a></td>
  <td style="color:var(--muted)">{alr.get('status','')}</td>
</tr>"""

    filter_form = f"""
<div class="toolbar">
  <form method="get" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center">
    <select name="severity">
      <option value="">All severities</option>
      {''.join(f'<option value="{s}" {"selected" if sev_filter==s else ""}>{s}</option>' for s in ['critical','high','medium','low'])}
    </select>
    <select name="status">
      <option value="">All statuses</option>
      {''.join(f'<option value="{s}" {"selected" if status_filter==s else ""}>{s}</option>' for s in ['open','closed','investigating'])}
    </select>
    <button class="btn" type="submit">Filter</button>
    <a class="btn" href="/alerts">Reset</a>
  </form>
</div>"""

    content = f"""
<div class="section">
  <h2>Alerts ({len(alerts)} shown)</h2>
  {filter_form}
  <table>
    <thead><tr><th>Severity</th><th>Confidence</th><th>Timestamp</th><th>Rule</th><th>Title</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
    return _render(content)


@app.route("/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    from storage.database import get_alerts, get_events

    alerts = get_alerts(limit=100_000)
    alr = next((a for a in alerts if a.get("id") == alert_id), None)
    if not alr:
        return _render('<div class="flash error">Alert not found.</div>')

    sev = (alr.get("severity") or "low").lower()
    ts = (alr.get("created_at") or "")[:19]

    # Parse evidence
    evidence = alr.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (json.JSONDecodeError, ValueError):
            evidence = {"raw": evidence}

    evidence_html = ""
    if isinstance(evidence, dict):
        rows_ev = "".join(
            f"<tr><td style='color:var(--muted);width:160px'>{k}</td><td>{v}</td></tr>"
            for k, v in evidence.items()
        )
        evidence_html = f"<table>{rows_ev}</table>"

    # Linked event
    linked_event_html = ""
    event_id = alr.get("event_id")
    if event_id:
        evts = get_events(limit=1, filters={})
        # fetch by id — simple approach
        from storage.database import get_connection
        conn = get_connection()
        row = conn.execute("SELECT * FROM events WHERE id = ?", [event_id]).fetchone()
        conn.close()
        if row:
            evt = dict(row)
            linked_event_html = f"""
<div class="section">
  <h2>Triggering Event</h2>
  <table>
    <tr><td style='color:var(--muted);width:140px'>Timestamp</td><td>{evt.get('timestamp','')}</td></tr>
    <tr><td style='color:var(--muted)'>Process</td><td>{evt.get('process','')}</td></tr>
    <tr><td style='color:var(--muted)'>Source</td><td>{evt.get('source','')}</td></tr>
    <tr><td style='color:var(--muted)'>Message</td><td>{(evt.get('message') or '')[:400]}</td></tr>
  </table>
</div>"""

    # Description (strip embedded metadata)
    desc = (alr.get("description") or "").split("\n\n[Confidence:")[0].strip()
    action = alr.get("recommended_action") or ""
    fp_notes = alr.get("false_positive_notes") or ""

    content = f"""
<div class="section">
  <h2>Alert #{alert_id} — {_sev_badge(sev)} &nbsp; <span style="color:var(--muted)">Confidence: {alr.get('confidence','?')}</span></h2>
  <h3 style="margin:12px 0 8px;font-size:16px">{alr.get('title','')}</h3>
  <table style="margin-bottom:12px">
    <tr><td style='color:var(--muted);width:140px'>Rule ID</td><td><code>{alr.get('rule_id','')}</code></td></tr>
    <tr><td style='color:var(--muted)'>Timestamp</td><td>{ts}</td></tr>
    <tr><td style='color:var(--muted)'>Status</td><td>{alr.get('status','')}</td></tr>
    <tr><td style='color:var(--muted)'>Event ID</td><td>{event_id or '—'}</td></tr>
  </table>

  <h4 style="color:var(--muted);margin-bottom:6px">Description</h4>
  <div class="detail-box">{desc}</div>

  <h4 style="color:var(--muted);margin:12px 0 6px">Evidence</h4>
  {evidence_html or '<span style="color:var(--muted)">—</span>'}

  <h4 style="color:var(--muted);margin:12px 0 6px">Recommended Action</h4>
  <div class="detail-box">{action or '—'}</div>

  <h4 style="color:var(--muted);margin:12px 0 6px">False Positive Notes</h4>
  <div class="detail-box">{fp_notes or '—'}</div>
</div>
{linked_event_html}
<a class="btn" href="/alerts" style="margin-top:8px">← Back to Alerts</a>
"""
    return _render(content)


@app.route("/events")
def events_view():
    from storage.database import get_events

    search = request.args.get("search", "")
    proc_filter = request.args.get("process", "")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 100

    filters = {}
    if search:
        filters["search"] = search
    if proc_filter:
        filters["process"] = proc_filter

    events = get_events(limit=per_page, offset=(page - 1) * per_page, filters=filters)

    rows = ""
    for evt in events:
        ts = (evt.get("timestamp") or "")[:19]
        ev_type = evt.get("event_type") or ""
        src = (evt.get("source") or "")[:40]
        proc = evt.get("process") or ""
        msg = (evt.get("message") or "")[:120]
        cat = evt.get("category") or ""
        rows += f"""
<tr>
  <td style="color:var(--muted)">{ts}</td>
  <td>{_sev_badge(ev_type) if ev_type in ('Error','Fault') else f'<span style="color:var(--muted)">{ev_type}</span>'}</td>
  <td style="color:var(--info)">{proc}</td>
  <td style="color:var(--muted);font-size:11px">{src}</td>
  <td style="font-size:11px">{msg}</td>
</tr>"""

    filter_form = f"""
<div class="toolbar">
  <form method="get" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center">
    <input type="text" name="search" placeholder="Search message..." value="{search}" style="width:220px">
    <input type="text" name="process" placeholder="Process name..." value="{proc_filter}" style="width:150px">
    <button class="btn" type="submit">Filter</button>
    <a class="btn" href="/events">Reset</a>
  </form>
  <span style="color:var(--muted);margin-left:auto">Page {page}</span>
  {f'<a class="btn" href="/events?search={search}&process={proc_filter}&page={page+1}">Next →</a>' if len(events) == per_page else ''}
</div>"""

    content = f"""
<div class="section">
  <h2>Events ({len(events)} shown)</h2>
  {filter_form}
  <table>
    <thead><tr><th>Timestamp</th><th>Type</th><th>Process</th><th>Source</th><th>Message</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
    return _render(content)


@app.route("/timeline")
def timeline_view():
    from storage.database import get_events, get_alerts
    from investigation.timeline import build_timeline

    events = get_events(limit=200)
    alerts = get_alerts(limit=100)
    timeline = build_timeline(events, alerts)[:150]

    rows = ""
    for entry in timeline:
        ts = (entry["ts_sort"] or "")[:19]
        kind = entry["kind"]
        sev = entry["severity"]
        title = entry["title"][:100]
        proc = entry.get("process") or "—"
        kind_b = _kind_badge(kind)
        sev_b = _sev_badge(sev) if kind == "alert" else f'<span style="color:var(--muted);font-size:11px">{sev}</span>'
        rows += f"""
<tr>
  <td style="color:var(--muted);font-size:11px">{ts}</td>
  <td>{kind_b}</td>
  <td>{sev_b}</td>
  <td style="color:var(--info)">{proc}</td>
  <td style="font-size:11px">{title}</td>
</tr>"""

    content = f"""
<div class="section">
  <h2>Timeline ({len(timeline)} entries)</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Kind</th><th>Severity/Type</th><th>Process</th><th>Title</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
    return _render(content)


@app.route("/report")
def report_view():
    from storage.database import get_events, get_alerts
    from investigation.timeline import generate_report
    from collector.macos import collect_system_info

    events = get_events(limit=500)
    alerts = get_alerts(limit=200)
    try:
        sys_info = collect_system_info()
    except Exception:
        sys_info = None

    report_text = generate_report(None, events, alerts, sys_info)

    content = f"""
<div class="section">
  <h2>Incident Investigation Report</h2>
  <div class="toolbar">
    <a class="btn" href="/report" onclick="return true">↻ Refresh</a>
  </div>
  <div class="detail-box" style="max-height:600px">{report_text}</div>
</div>"""
    return _render(content)


# ---------------------------------------------------------------------------
# Action endpoints (POST)
# ---------------------------------------------------------------------------

@app.route("/action/collect", methods=["POST"])
def action_collect():
    try:
        from collector.macos import collect_all
        from parser.macos import normalize_event, normalize_process, normalize_launch_item
        from storage.database import init_database, insert_events

        init_database()
        data = collect_all(minutes=1)

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

        count = insert_events(events)
        flash = f"Collected and stored {count} events."
        flash_cls = ""
    except Exception as exc:  # noqa: BLE001
        flash = f"Collection error: {exc}"
        flash_cls = "error"

    return redirect(url_for("overview") + f"?flash={flash}&cls={flash_cls}")


@app.route("/action/detect", methods=["POST"])
def action_detect():
    try:
        from storage.database import init_database
        from detection.engine import run_detection

        init_database()
        alerts = run_detection()
        flash = f"Detection complete: {len(alerts)} new alert(s)."
        flash_cls = ""
    except Exception as exc:  # noqa: BLE001
        flash = f"Detection error: {exc}"
        flash_cls = "error"

    return redirect(url_for("alerts_view") + f"?flash={flash}&cls={flash_cls}")


@app.route("/action/simulate", methods=["POST"])
def action_simulate():
    try:
        from storage.database import init_database, insert_events
        from detection.engine import run_detection
        import data.sample_events as sample_module

        init_database()
        events = sample_module.get_sample_events()
        count = insert_events(events)

        # Re-fetch to get IDs, then run detection
        from storage.database import get_events
        stored = get_events(limit=len(events) + 100)
        alerts = run_detection(stored)

        flash = f"Simulation loaded {count} sample events → {len(alerts)} alert(s) generated."
        flash_cls = ""
    except Exception as exc:  # noqa: BLE001
        flash = f"Simulation error: {exc}"
        flash_cls = "error"

    return redirect(url_for("overview") + f"?flash={flash}&cls={flash_cls}")


# ---------------------------------------------------------------------------
# API endpoints (JSON)
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    from storage.database import get_db_stats, get_alert_count_by_severity
    stats = get_db_stats()
    stats["severity_counts"] = get_alert_count_by_severity()
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    from storage.database import get_alerts
    alerts = get_alerts(limit=200)
    return jsonify(alerts)


@app.route("/api/events")
def api_events():
    from storage.database import get_events
    events = get_events(limit=200)
    return jsonify(events)


# ---------------------------------------------------------------------------
# Flash message passthrough (via query param — simple, no session required)
# ---------------------------------------------------------------------------

@app.before_request
def _attach_flash():
    pass


def _render(content: str, flash_msg: str = "", flash_cls: str = "") -> str:
    # Check for flash in query params
    if not flash_msg:
        flash_msg = request.args.get("flash", "")
        flash_cls = request.args.get("cls", "")
    return render_template_string(
        _BASE_HTML,
        content=content,
        flash_msg=flash_msg,
        flash_cls=flash_cls,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
    )

    # Initialize DB on startup
    try:
        from storage.database import init_database
        init_database()
    except Exception as exc:
        logger.error("DB init failed: %s", exc)

    print("=" * 60)
    print("  Mini-SIEM Dashboard")
    print("  URL: http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    app.run(host="127.0.0.1", port=5000, debug=False)
