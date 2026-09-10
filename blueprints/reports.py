"""
Reports blueprint — pick any set of machines and any set of metrics
(status, CPU, RAM, GPU, disk, network, uptime, ...), preview the result
as a table in the UI, then download it as a CSV file. Replaces the old
raw-SQL Terminal page.
"""
import csv
import io
import json
from datetime import datetime

from flask import Blueprint, Response, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from blueprints.servers import _safe_gpu_list
from db import get_db

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


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
    FROM {table} ORDER BY ts DESC LIMIT 1
"""

# Same columns, but every reading inside a time range instead of just the
# latest one — used when the user picks "Date & time range" in the UI.
# Capped at 1000 rows per machine so a huge range can't blow up the response;
# _build_rows reports back whether any machine hit that cap.
_RANGE_ROWS_SQL = """
    SELECT ts, cpu_percent, cpu_freq_mhz, cpu_temp, ram_total_gb, ram_used_gb,
           ram_percent, swap_percent, gpu_info, disk_partitions,
           net_bytes_sent, net_bytes_recv, uptime_seconds, os_version, hostname, status
    FROM {table} WHERE ts BETWEEN %s AND %s ORDER BY ts ASC LIMIT 1000
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
                    cur.execute(_RANGE_ROWS_SQL.format(table=tbl), (start, end))
                    readings = cur.fetchall()
                except Exception:
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
                    cur.execute(_LATEST_ROW_SQL.format(table=tbl))
                    latest = cur.fetchone()
                except Exception:
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
    return render_template("reports.html", machines=machines, metrics=METRICS)


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
    writer.writerow(columns)
    for r in rows:
        writer.writerow([r.get(c, "—") for c in columns])

    filename = f"reformmed_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )