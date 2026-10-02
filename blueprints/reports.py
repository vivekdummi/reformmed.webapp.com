"""
Reports blueprint — two things:

* /reports/document — a full "Infrastructure Report" document for any set of
  servers and any date/time window: executive summary, per-server charts and
  min/avg/p95/max stats, data coverage + gaps, disks, GPUs, and the alerts in
  that window. Rendered on the page and printable / savable as PDF.
* /reports/generate + /reports/download — the raw data table (column picker)
  and its CSV export.
"""
import csv
import io
import json
import math
import re
from datetime import datetime, timedelta

from flask import Blueprint, Response, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from psycopg2 import sql

from blueprints.servers import _safe_gpu_list
from db import get_db

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.before_request
def _require_servers_feature():
    # Reports expose server metrics, so they follow the Servers permission.
    if current_user.is_authenticated and not (current_user.is_admin or current_user.can_view_servers):
        abort(403)


# ── Metric catalog ───────────────────────────────────────────────────────────
# (id, label) pairs shown as checkboxes in the UI, in display order.
METRICS = [
    ("status",    "Status (Online/Offline)"),
    ("last_seen", "Last Seen"),
    ("hostname",  "Hostname"),
    ("public_ip", "Public IP"),
    ("location",  "Location"),
    ("os",        "OS"),
    ("cpu",       "CPU %"),
    ("cpu_temp",  "CPU Temp (°C)"),
    ("cpu_freq",  "CPU Freq (MHz)"),
    ("ram",       "RAM %"),
    ("ram_used",  "RAM Used / Total (GB)"),
    ("swap",      "Swap %"),
    ("gpu",       "GPU Load / Temp"),
    ("disk",      "Disk Usage"),
    ("network",   "Network I/O (sent / recv)"),
    ("uptime",    "Uptime"),
]
METRIC_LABELS = dict(METRICS)

# Columns pulled from each machine's own metrics table for its latest row.
# Kept as one SELECT regardless of which metrics were picked — it's a single
# row per machine, so there's no real cost to always fetching all of them.
_LATEST_ROW_SQL = """
    SELECT cpu_percent, cpu_freq_mhz, cpu_temp, ram_total_gb, ram_used_gb,
           ram_percent, swap_percent, gpu_info, disk_partitions,
           net_bytes_sent, net_bytes_recv, uptime_seconds, os_version, hostname, status
    FROM {} ORDER BY ts DESC LIMIT 1
"""

# Same columns, but every reading inside a time range instead of just the
# latest one — used when the user picks "Date & time range" in the UI.
# Capped at 1000 rows per machine so a huge range can't blow up the response;
# _build_rows reports back whether any machine hit that cap.
_RANGE_ROWS_SQL = """
    SELECT ts, cpu_percent, cpu_freq_mhz, cpu_temp, ram_total_gb, ram_used_gb,
           ram_percent, swap_percent, gpu_info, disk_partitions,
           net_bytes_sent, net_bytes_recv, uptime_seconds, os_version, hostname, status
    FROM {} WHERE ts BETWEEN %s AND %s ORDER BY ts ASC LIMIT 1000
"""
_RANGE_ROW_CAP = 1000


def _fmt_status(reg, latest):
    # A per-reading status column exists on historical rows too — prefer it
    # in range mode so each row reflects what it actually was at that time,
    # falling back to the registry's current status for latest-only mode.
    if latest and latest.get("status"):
        return str(latest["status"]).upper()
    return (reg.get("status") or "unknown").upper()


def _fmt_last_seen(reg, latest):
    return str(reg["last_seen"]) if reg.get("last_seen") else "—"


def _fmt_hostname(reg, latest):
    return reg.get("hostname") or (latest or {}).get("hostname") or "—"


def _fmt_public_ip(reg, latest):
    return reg.get("public_ip") or "—"


def _fmt_location(reg, latest):
    return reg.get("location") or "—"


def _fmt_os(reg, latest):
    return reg.get("os_type") or (latest or {}).get("os_version") or "—"


def _fmt_cpu(reg, latest):
    v = latest.get("cpu_percent") if latest else None
    return f"{v:.1f}%" if v is not None else "—"


def _fmt_cpu_temp(reg, latest):
    v = latest.get("cpu_temp") if latest else None
    return f"{v:.1f}°C" if v is not None else "—"


def _fmt_cpu_freq(reg, latest):
    v = latest.get("cpu_freq_mhz") if latest else None
    return f"{v:.0f} MHz" if v is not None else "—"


def _fmt_ram(reg, latest):
    v = latest.get("ram_percent") if latest else None
    return f"{v:.1f}%" if v is not None else "—"


def _fmt_ram_used(reg, latest):
    if latest and latest.get("ram_used_gb") is not None and latest.get("ram_total_gb") is not None:
        return f"{latest['ram_used_gb']:.1f} / {latest['ram_total_gb']:.1f} GB"
    return "—"


def _fmt_swap(reg, latest):
    v = latest.get("swap_percent") if latest else None
    return f"{v:.1f}%" if v is not None else "—"


def _fmt_gpu(reg, latest):
    gpus = _safe_gpu_list(latest.get("gpu_info")) if latest else []
    if not gpus:
        return "—"
    parts = []
    for g in gpus:
        bit = g.get("name", "GPU")
        load = g.get("gpu_percent", g.get("load_percent"))
        temp = g.get("temperature")
        if load is not None:
            bit += f" {load}%"
        if temp is not None:
            bit += f" {temp}°C"
        parts.append(bit)
    return "; ".join(parts)


def _fmt_disk(reg, latest):
    if not latest:
        return "—"
    raw = latest.get("disk_partitions")
    try:
        arr = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except Exception:
        arr = []
    parts = [f"{d.get('mountpoint', '?')}:{d.get('percent', '?')}%" for d in arr if isinstance(d, dict)]
    return ", ".join(parts) if parts else "—"


def _fmt_network(reg, latest):
    if not latest:
        return "—"
    sent, recv = latest.get("net_bytes_sent"), latest.get("net_bytes_recv")
    if sent is None and recv is None:
        return "—"

    def mb(x):
        return f"{(x or 0) / 1e6:.1f} MB"

    return f"↑{mb(sent)} / ↓{mb(recv)}"


def _fmt_uptime(reg, latest):
    secs = latest.get("uptime_seconds") if latest else None
    if not secs:
        return "—"
    days, hours = int(secs // 86400), int((secs % 86400) // 3600)
    return f"{days}d {hours}h"


METRIC_FORMATTERS = {
    "status":    _fmt_status,
    "last_seen": _fmt_last_seen,
    "hostname":  _fmt_hostname,
    "public_ip": _fmt_public_ip,
    "location":  _fmt_location,
    "os":        _fmt_os,
    "cpu":       _fmt_cpu,
    "cpu_temp":  _fmt_cpu_temp,
    "cpu_freq":  _fmt_cpu_freq,
    "ram":       _fmt_ram,
    "ram_used":  _fmt_ram_used,
    "swap":      _fmt_swap,
    "gpu":       _fmt_gpu,
    "disk":      _fmt_disk,
    "network":   _fmt_network,
    "uptime":    _fmt_uptime,
}


def _friendly_event_label(alert_type: str) -> str:
    labels = {
        "offline": "Went Offline",
        "online":  "Back Online",
        "cpu":     "High CPU",
        "ram":     "High RAM",
        "temp":    "High Temperature",
    }
    if alert_type in labels:
        return labels[alert_type]
    if alert_type.startswith("disk:"):
        return f"High Disk ({alert_type.split(':', 1)[1]})"
    return alert_type.replace("_", " ").title()


_EVENT_ROW_CAP = 2000


def _build_event_rows(table_names, start, end):
    """
    Offline/online transitions and CPU/RAM/disk threshold alerts for the
    selected machines, in the given time range — sourced from alert_log,
    which offline_checker.py already writes to every time one of these
    happens. Returns (rows, truncated).
    """
    if not table_names:
        return [], False
    with get_db() as conn:
        cur = conn.cursor()
        placeholders = ",".join(["%s"] * len(table_names))
        cur.execute(f"""
            SELECT system_name, location
            FROM machine_registry WHERE table_name IN ({placeholders})
        """, table_names)
        regs = cur.fetchall()

        # alert_log.machine_key is written as "system_name@location" —
        # build that same key for each selected machine so we can match rows.
        key_to_label = {}
        for r in regs:
            key = f"{r['system_name']}@{r['location']}"
            key_to_label[key] = f"{r['system_name']} ({r['location']})"

        if not key_to_label:
            return [], False

        key_placeholders = ",".join(["%s"] * len(key_to_label))
        cur.execute(f"""
            SELECT sent_at, alert_type, machine_key, subject, body
            FROM alert_log
            WHERE machine_key IN ({key_placeholders}) AND sent_at BETWEEN %s AND %s
            ORDER BY sent_at ASC
            LIMIT {_EVENT_ROW_CAP}
        """, list(key_to_label.keys()) + [start, end])
        events = cur.fetchall()

    rows = []
    for e in events:
        detail = (e.get("body") or "").replace("\n", "; ").strip()
        rows.append({
            "Machine":   key_to_label.get(e["machine_key"], e["machine_key"]),
            "Timestamp": str(e["sent_at"]),
            "Event":     _friendly_event_label(e["alert_type"]),
            "Details":   detail or "—",
        })
    return rows, len(events) >= _EVENT_ROW_CAP


def _require_access():
    if not (current_user.is_admin or current_user.can_view_servers):
        abort(403)


def _allowed_table_names(requested):
    """Filter the requested table_names down to ones this user can see."""
    allowed = current_user.allowed_servers()
    if allowed is None:
        return list(requested)
    return [t for t in requested if t in allowed]


def _build_rows(table_names, metric_ids, mode="latest", start=None, end=None):
    """
    One row per machine in "latest" mode (current snapshot), or one row per
    reading per machine in "range" mode (historical). Returns (rows, truncated)
    — truncated is True if any machine's history hit the _RANGE_ROW_CAP.
    """
    if not table_names:
        return [], False
    truncated = False
    with get_db() as conn:
        cur = conn.cursor()
        placeholders = ",".join(["%s"] * len(table_names))
        cur.execute(f"""
            SELECT table_name, system_name, location, os_type, hostname,
                   public_ip, status, last_seen
            FROM machine_registry WHERE table_name IN ({placeholders})
            ORDER BY system_name, location
        """, table_names)
        regs = {r["table_name"]: r for r in cur.fetchall()}

        rows = []
        for tbl in table_names:
            reg = regs.get(tbl)
            if not reg:
                continue
            machine_label = f"{reg['system_name']} ({reg['location']})"

            if mode == "range":
                try:
                    cur.execute(sql.SQL(_RANGE_ROWS_SQL).format(sql.Identifier(tbl)), (start, end))
                    readings = cur.fetchall()
                except Exception:
                    conn.rollback()
                    readings = []
                if len(readings) >= _RANGE_ROW_CAP:
                    truncated = True
                for reading in readings:
                    row = {"Machine": machine_label, "Timestamp": str(reading["ts"])}
                    for mid in metric_ids:
                        fn = METRIC_FORMATTERS.get(mid)
                        if fn:
                            row[METRIC_LABELS[mid]] = fn(reg, reading)
                    rows.append(row)
            else:
                latest = None
                try:
                    cur.execute(sql.SQL(_LATEST_ROW_SQL).format(sql.Identifier(tbl)))
                    latest = cur.fetchone()
                except Exception:
                    conn.rollback()
                    latest = None
                row = {"Machine": machine_label}
                for mid in metric_ids:
                    fn = METRIC_FORMATTERS.get(mid)
                    if fn:
                        row[METRIC_LABELS[mid]] = fn(reg, latest)
                rows.append(row)
    return rows, truncated


def _parse_report_request(body):
    """
    Shared validation for /generate and /download. Returns
    (table_names, metric_ids, mode, start, end, error_response_or_None).
    """
    table_names = _allowed_table_names(body.get("table_names") or [])
    mode        = body.get("mode") or "latest"
    if mode not in ("latest", "range", "events"):
        mode = "latest"
    metric_ids  = [m for m in (body.get("metrics") or []) if m in METRIC_FORMATTERS]
    start, end  = body.get("start"), body.get("end")

    if not table_names:
        return None, None, None, None, None, (jsonify({
            "error": "No machines selected (or you don't have access to the selected machines)."
        }), 400)
    if mode != "events" and not metric_ids:
        return None, None, None, None, None, (jsonify({"error": "No metrics selected."}), 400)
    if mode in ("range", "events"):
        if not start or not end:
            return None, None, None, None, None, (jsonify({
                "error": "Pick both a start and end date/time."
            }), 400)
        if str(start) >= str(end):
            return None, None, None, None, None, (jsonify({
                "error": "Start must be before end."
            }), 400)

    return table_names, metric_ids, mode, start, end, None


@reports_bp.route("/")
@login_required
def index():
    _require_access()
    allowed = current_user.allowed_servers()
    with get_db() as conn:
        cur = conn.cursor()
        if allowed is None:
            cur.execute("""
                SELECT table_name, system_name, location, status
                FROM machine_registry ORDER BY system_name, location
            """)
            machines = cur.fetchall()
        elif not allowed:
            machines = []
        else:
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT table_name, system_name, location, status
                FROM machine_registry WHERE table_name IN ({placeholders})
                ORDER BY system_name, location
            """, list(allowed))
            machines = cur.fetchall()
    return render_template("reports.html", machines=machines, metrics=METRICS,
                           sections=DOC_SECTIONS, intervals=INTERVAL_CHOICES,
                           max_range_days=MAX_RANGE_DAYS)


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    _require_access()
    body = request.get_json(silent=True) or {}
    table_names, metric_ids, mode, start, end, err = _parse_report_request(body)
    if err:
        return err

    if mode == "events":
        rows, truncated = _build_event_rows(table_names, start, end)
        columns = ["Machine", "Timestamp", "Event", "Details"]
    else:
        rows, truncated = _build_rows(table_names, metric_ids, mode, start, end)
        columns = ["Machine"] + (["Timestamp"] if mode == "range" else []) + [METRIC_LABELS[m] for m in metric_ids]

    return jsonify({
        "columns": columns,
        "rows": [[r.get(c, "—") for c in columns] for r in rows],
        "truncated": truncated,
    })


@reports_bp.route("/download", methods=["POST"])
@login_required
def download():
    _require_access()
    body = request.get_json(silent=True) or {}
    table_names, metric_ids, mode, start, end, err = _parse_report_request(body)
    if err:
        return err

    if mode == "events":
        rows, _truncated = _build_event_rows(table_names, start, end)
        columns = ["Machine", "Timestamp", "Event", "Details"]
    else:
        rows, _truncated = _build_rows(table_names, metric_ids, mode, start, end)
        columns = ["Machine"] + (["Timestamp"] if mode == "range" else []) + [METRIC_LABELS[m] for m in metric_ids]

    buf = io.StringIO()
    writer = csv.writer(buf)

    def _cell(v):
        # Agent-supplied text (hostnames, names…) starting with = + - @ would
        # run as a formula when the CSV is opened in Excel / Sheets.
        v = "" if v is None else v
        if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", chr(9), chr(13)):
            return "'" + v
        return v

    writer.writerow([_cell(c) for c in columns])
    for r in rows:
        writer.writerow([_cell(r.get(c, "—")) for c in columns])

    filename = f"reformmed_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

# ═════════════════════════════════════════════════════════════════════════════
#  Document report
# ═════════════════════════════════════════════════════════════════════════════

DOC_SECTIONS = [
    ("summary",      "Executive summary"),
    ("availability", "Availability & data gaps"),
    ("cpu",          "CPU"),
    ("memory",       "Memory & swap"),
    ("disk",         "Disk"),
    ("network",      "Network"),
    ("temperature",  "Temperature"),
    ("gpu",          "GPU"),
    ("alerts",       "Alerts in period"),
    ("raw",          "Raw data table"),
]
DOC_SECTION_IDS = {k for k, _ in DOC_SECTIONS}

# (id, label, bucket seconds) — "auto" picks the finest bucket that keeps
# every series at or below MAX_POINTS.
INTERVAL_CHOICES = [
    ("auto", "Auto", None),
    ("1m",   "1 minute", 60),
    ("5m",   "5 minutes", 300),
    ("15m",  "15 minutes", 900),
    ("1h",   "1 hour", 3600),
    ("6h",   "6 hours", 21600),
    ("1d",   "1 day", 86400),
]
_INTERVAL_SECS = {k: v for k, _, v in INTERVAL_CHOICES}
_BUCKET_LADDER = [60, 300, 900, 3600, 21600, 86400]
MAX_POINTS = 500
MAX_RANGE_DAYS = 93
MAX_SERVERS = 50
_TABLE_RE = re.compile(r"^[a-z0-9_]{1,63}$")


class ReportError(ValueError):
    pass


def _parse_dt(value, field):
    """'2026-10-02T14:30' (datetime-local) → naive datetime. Naive values are
    compared in the DB session timezone (IST), same as the rest of the app."""
    if not value or not isinstance(value, str):
        raise ReportError(f"Pick a {field} date/time.")
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", ""))
    except ValueError:
        raise ReportError(f"Invalid {field} date/time.")
    return dt.replace(tzinfo=None, microsecond=0)


def choose_bucket_seconds(span_seconds, interval="auto"):
    """Bucket size for aggregation. A requested interval is honoured unless it
    would produce more than MAX_POINTS points, in which case the next coarser
    step is used (the response says which bucket was actually applied)."""
    if interval not in _INTERVAL_SECS:
        raise ReportError("Unknown interval.")
    wanted = _INTERVAL_SECS[interval]
    ladder = [b for b in _BUCKET_LADDER if wanted is None or b >= wanted]
    for b in ladder:
        if span_seconds / b <= MAX_POINTS:
            return b
    return ladder[-1] if ladder else _BUCKET_LADDER[-1]


def validate_document_request(body, allowed_servers, registry_tables):
    """Pure validation (unit-testable). allowed_servers: set of table names the
    user may see, or None for all. registry_tables: set of names in
    machine_registry. Returns a dict of clean inputs or raises ReportError."""
    names = body.get("table_names") or []
    if not isinstance(names, list):
        raise ReportError("table_names must be a list.")
    clean = []
    for t in names:
        if not isinstance(t, str) or not _TABLE_RE.match(t):
            raise ReportError("Invalid server id.")
        if t not in registry_tables:
            continue  # unknown / deleted machine
        if allowed_servers is not None and t not in allowed_servers:
            continue  # not this user's server
        if t not in clean:
            clean.append(t)
    if not clean:
        raise ReportError("Select at least one server you have access to.")
    if len(clean) > MAX_SERVERS:
        raise ReportError(f"Select at most {MAX_SERVERS} servers per report.")

    start = _parse_dt(body.get("start"), "start")
    end = _parse_dt(body.get("end"), "end")
    if start >= end:
        raise ReportError("Start must be before end.")
    if end - start > timedelta(days=MAX_RANGE_DAYS):
        raise ReportError(f"The period can be at most {MAX_RANGE_DAYS} days.")

    sections = [x for x in (body.get("sections") or []) if x in DOC_SECTION_IDS]
    if not sections:
        raise ReportError("Pick at least one section to include.")
    interval = body.get("interval") or "auto"
    bucket = choose_bucket_seconds((end - start).total_seconds(), interval)
    return {"table_names": clean, "start": start, "end": end,
            "sections": sections, "interval": interval, "bucket": bucket}


def _num(v, nd=1):
    if v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return round(f, nd)


def net_rates(buckets, bucket_seconds):
    """Cumulative byte counters (max per bucket) → KB/s per bucket. The first
    bucket, counter resets (agent restart) and gaps produce None, never a
    negative or wildly inflated rate."""
    up, down = [], []
    prev = None
    for b in buckets:
        cur_t, s_, r_ = b["t"], b.get("ns"), b.get("nr")
        if prev is None or s_ is None or r_ is None or prev["ns"] is None or prev["nr"] is None:
            up.append(None); down.append(None)
        else:
            dt = (cur_t - prev["t"]).total_seconds() or bucket_seconds
            ds, dr = s_ - prev["ns"], r_ - prev["nr"]
            gap = dt > bucket_seconds * 1.5
            up.append(None if ds < 0 or gap else round(ds / dt / 1024, 1))
            down.append(None if dr < 0 or gap else round(dr / dt / 1024, 1))
        prev = {"t": cur_t, "ns": s_, "nr": r_}
    return up, down


def find_gaps(bucket_times, start, end, bucket_seconds, now=None, min_gap_seconds=180):
    """Periods with no data at all, from the list of bucket start times that
    have readings. Returns (coverage_pct, gaps) where gaps are the longest
    10 silent periods [{start, end, seconds}]. The window is clipped to 'now'
    so a report reaching into the future isn't counted as downtime."""
    now = now or datetime.now()
    end_eff = min(end, now)
    if end_eff <= start:
        return None, []
    total = max(1, math.ceil((end_eff - start).total_seconds() / bucket_seconds))
    covered = len({t for t in bucket_times if start <= t < end_eff + timedelta(seconds=bucket_seconds)})
    coverage = round(min(100.0, covered / total * 100), 1)
    threshold = max(min_gap_seconds, bucket_seconds * 2)
    gaps = []
    edges = [start - timedelta(seconds=bucket_seconds)] + sorted(bucket_times) + [end_eff]
    for a, b in zip(edges, edges[1:]):
        silent = (b - a).total_seconds() - bucket_seconds
        if silent >= threshold:
            g_start = a + timedelta(seconds=bucket_seconds)
            gaps.append({"start": g_start.isoformat(), "end": b.isoformat(), "seconds": int(silent)})
    gaps.sort(key=lambda g: -g["seconds"])
    return coverage, gaps[:10]


_BUCKET_SQL = """
    SELECT to_timestamp(floor(extract(epoch FROM ts) / %(b)s) * %(b)s) AS t,
           avg(cpu_percent)  AS cpu_avg,  max(cpu_percent)  AS cpu_max,
           avg(ram_percent)  AS ram_avg,  max(ram_percent)  AS ram_max,
           avg(swap_percent) AS swap_avg,
           avg(cpu_temp)     AS temp_avg, max(cpu_temp)     AS temp_max,
           max(net_bytes_sent) AS ns, max(net_bytes_recv) AS nr,
           count(*) AS n
    FROM {tbl} WHERE ts >= %(s)s AND ts < %(e)s
    GROUP BY 1 ORDER BY 1
"""

_STATS_SQL = """
    SELECT count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts,
           min(cpu_percent) AS cpu_min, avg(cpu_percent) AS cpu_avg, max(cpu_percent) AS cpu_max,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY cpu_percent) AS cpu_p95,
           min(ram_percent) AS ram_min, avg(ram_percent) AS ram_avg, max(ram_percent) AS ram_max,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY ram_percent) AS ram_p95,
           min(swap_percent) AS swap_min, avg(swap_percent) AS swap_avg, max(swap_percent) AS swap_max,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY swap_percent) AS swap_p95,
           min(cpu_temp) AS temp_min, avg(cpu_temp) AS temp_avg, max(cpu_temp) AS temp_max,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY cpu_temp) AS temp_p95,
           avg(ram_total_gb) AS ram_total_gb
    FROM {tbl} WHERE ts >= %(s)s AND ts < %(e)s
"""

_LAST_IN_RANGE_SQL = """
    SELECT ts, disk_partitions, gpu_info, uptime_seconds, os_version
    FROM {tbl} WHERE ts >= %(s)s AND ts < %(e)s ORDER BY ts DESC LIMIT 1
"""

_SKIP_MOUNTS = ("/snap/", "/proc", "/sys", "/dev", "/run")


def _stat_block(row, key):
    return {k: _num(row.get(f"{key}_{k}")) for k in ("min", "avg", "p95", "max")}


def _disks(raw):
    try:
        arr = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except Exception:
        return []
    out = []
    for d in arr if isinstance(arr, list) else []:
        if not isinstance(d, dict):
            continue
        mount = str(d.get("mountpoint") or "?")
        if d.get("fstype") == "squashfs" or mount.startswith(_SKIP_MOUNTS):
            continue
        out.append({"mount": mount, "percent": _num(d.get("percent")),
                    "used_gb": _num(d.get("used_gb")), "total_gb": _num(d.get("total_gb")),
                    "fstype": d.get("fstype")})
    return out


def _gpus(raw):
    out = []
    for g in _safe_gpu_list(raw):
        used = g.get("memory_used_mb", g.get("mem_used_mb"))
        total = g.get("memory_total_mb", g.get("mem_total_mb"))
        out.append({"name": str(g.get("name") or "GPU").split("\n")[0],
                    "type": g.get("type"),
                    "load": _num(g.get("load_percent", g.get("gpu_percent"))),
                    "temp": _num(g.get("temperature", g.get("temp_c"))),
                    "vram_used_mb": _num(used, 0), "vram_total_mb": _num(total, 0)})
    return out


def _server_section(cur, reg, p):
    tbl = sql.Identifier(reg["table_name"])
    args = {"s": p["start"], "e": p["end"], "b": p["bucket"]}
    cur.execute(sql.SQL(_STATS_SQL).format(tbl=tbl), args)
    st = cur.fetchone() or {}
    cur.execute(sql.SQL(_BUCKET_SQL).format(tbl=tbl), args)
    buckets = []
    for r in cur.fetchall():
        t = r["t"].replace(tzinfo=None) if r["t"] is not None and r["t"].tzinfo else r["t"]
        buckets.append(dict(r, t=t))
    cur.execute(sql.SQL(_LAST_IN_RANGE_SQL).format(tbl=tbl), args)
    last = cur.fetchone() or {}

    up, down = net_rates(buckets, p["bucket"])
    coverage, gaps = find_gaps([b["t"] for b in buckets], p["start"], p["end"], p["bucket"])
    vals_up = [v for v in up if v is not None]
    vals_down = [v for v in down if v is not None]

    def first_ts(v):
        if v is None:
            return None
        return (v.replace(tzinfo=None) if v.tzinfo else v).isoformat()

    return {
        "table_name": reg["table_name"],
        "name": reg["system_name"], "location": reg["location"],
        "os": reg.get("os_type") or last.get("os_version"), "hostname": reg.get("hostname"),
        "public_ip": reg.get("public_ip"), "status": reg.get("status"),
        "samples": int(st.get("n") or 0),
        "first_ts": first_ts(st.get("first_ts")), "last_ts": first_ts(st.get("last_ts")),
        "coverage_pct": coverage if st.get("n") else 0.0,
        "gaps": gaps,
        "ram_total_gb": _num(st.get("ram_total_gb")),
        "uptime_seconds": _num(last.get("uptime_seconds"), 0),
        "stats": {k: _stat_block(st, k) for k in ("cpu", "ram", "swap", "temp")} | {
            "net_up": {"avg": _num(sum(vals_up) / len(vals_up)) if vals_up else None, "max": _num(max(vals_up)) if vals_up else None},
            "net_down": {"avg": _num(sum(vals_down) / len(vals_down)) if vals_down else None, "max": _num(max(vals_down)) if vals_down else None},
        },
        "series": {
            "t": [b["t"].isoformat() for b in buckets],
            "cpu_avg": [_num(b["cpu_avg"]) for b in buckets], "cpu_max": [_num(b["cpu_max"]) for b in buckets],
            "ram_avg": [_num(b["ram_avg"]) for b in buckets], "ram_max": [_num(b["ram_max"]) for b in buckets],
            "swap_avg": [_num(b["swap_avg"]) for b in buckets],
            "temp_avg": [_num(b["temp_avg"]) for b in buckets], "temp_max": [_num(b["temp_max"]) for b in buckets],
            "net_up": up, "net_down": down,
        },
        "disks": _disks(last.get("disk_partitions")),
        "gpus": _gpus(last.get("gpu_info")),
        "alert_count": 0,
    }


@reports_bp.route("/document", methods=["POST"])
@login_required
def document():
    _require_access()
    body = request.get_json(silent=True) or {}
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name, system_name, location, os_type, hostname, public_ip, status
            FROM machine_registry
        """)
        registry = {r["table_name"]: r for r in cur.fetchall()}
        try:
            p = validate_document_request(body, current_user.allowed_servers(), set(registry))
        except ReportError as e:
            return jsonify({"error": str(e)}), 400

        servers = []
        for t in p["table_names"]:
            try:
                servers.append(_server_section(cur, registry[t], p))
            except Exception:
                conn.rollback()
                reg = registry[t]
                servers.append({"table_name": t, "name": reg["system_name"], "location": reg["location"],
                                "error": "No metrics table for this server yet.", "samples": 0})

        alerts = []
        keys = {f"{registry[t]['system_name']}@{registry[t]['location']}": t for t in p["table_names"]}
        cur.execute("""
            SELECT sent_at, alert_type, machine_key, subject, success, COALESCE(source,'system') AS source
            FROM alert_log
            WHERE machine_key = ANY(%s) AND sent_at >= %s AND sent_at < %s
              AND COALESCE(source,'system') <> 'dvr'
            ORDER BY sent_at DESC LIMIT 500
        """, (list(keys), p["start"], p["end"]))
        per_table = {}
        for a in cur.fetchall():
            t = keys.get(a["machine_key"])
            per_table[t] = per_table.get(t, 0) + 1
            sent = a["sent_at"]
            alerts.append({
                "time": (sent.replace(tzinfo=None) if sent.tzinfo else sent).isoformat(),
                "server": registry[t]["system_name"] if t else a["machine_key"],
                "type": a["alert_type"], "label": _friendly_event_label(a["alert_type"]),
                "subject": a["subject"], "success": bool(a["success"]),
            })
        for srv in servers:
            srv["alert_count"] = per_table.get(srv["table_name"], 0)

    ok = [s_ for s_ in servers if s_.get("samples")]

    def mean(key, sub):
        vals = [s_["stats"][key][sub] for s_ in ok if s_["stats"][key][sub] is not None]
        return _num(sum(vals) / len(vals)) if vals else None

    def peak(key):
        vals = [s_["stats"][key]["max"] for s_ in ok if s_["stats"][key]["max"] is not None]
        return _num(max(vals)) if vals else None

    return jsonify({
        "title": "Infrastructure Report",
        "period": {"start": p["start"].isoformat(), "end": p["end"].isoformat(),
                   "bucket_seconds": p["bucket"], "interval": p["interval"]},
        "generated_at": datetime.now().replace(microsecond=0).isoformat(),
        "generated_by": current_user.username,
        "sections": p["sections"],
        "totals": {
            "servers": len(servers), "with_data": len(ok),
            "samples": sum(s_.get("samples", 0) for s_ in servers),
            "alerts": len(alerts), "alerts_failed": sum(1 for a in alerts if not a["success"]),
            "cpu_avg": mean("cpu", "avg"), "cpu_peak": peak("cpu"),
            "ram_avg": mean("ram", "avg"), "ram_peak": peak("ram"),
            "coverage_avg": _num(sum(s_["coverage_pct"] for s_ in ok) / len(ok)) if ok else None,
        },
        "servers": servers,
        "alerts": alerts,
        "alerts_truncated": len(alerts) >= 500,
    })
