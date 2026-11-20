import csv
import io
import json
import os
import re
from datetime import datetime, timezone
from flask import Blueprint, Response, render_template, abort, jsonify, request
from flask_login import login_required, current_user
from psycopg2 import sql
from db import get_db

servers_bp = Blueprint("servers", __name__, url_prefix="/servers")


@servers_bp.before_request
def _require_servers_feature():
    """can_view_servers used to only hide the nav link — enforce it on the routes too."""
    if current_user.is_authenticated and not (current_user.is_admin or current_user.can_view_servers):
        abort(403)


# Same shape the ingest API (server/main.py) creates. Several queries below
# interpolate the table name, so refuse anything else outright.
_TABLE_RE = re.compile(r"^machine_[a-z0-9_]{1,60}$")
HISTORY_MAX_DAYS = 93


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_pm2(raw):
    """
    Normalise the agent's pm2_processes cell into a list of
    {name, id, status, cpu, memory_mb, restarts, uptime_secs, mode, instances}.

    Accepts raw `pm2 jlist` entries (monit / pm2_env nested) as well as a
    flat shape ({name, status, cpu, memory, restarts, uptime}), and a dict
    wrapper like {"processes": [...]}. Anything unparseable is dropped.
    """
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return []
    if isinstance(raw, dict):
        raw = raw.get("processes") or raw.get("apps") or raw.get("list") or []
    if not isinstance(raw, list):
        return []

    now = datetime.now().timestamp()
    out = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        env = p.get("pm2_env") if isinstance(p.get("pm2_env"), dict) else {}
        monit = p.get("monit") if isinstance(p.get("monit"), dict) else {}

        status = str(p.get("status") or env.get("status") or "unknown").lower()
        cpu = _num(p.get("cpu", p.get("cpu_percent", monit.get("cpu"))))

        mem_mb = _num(p.get("memory_mb", p.get("mem_mb")))
        if mem_mb is None:
            mem = _num(p.get("memory", monit.get("memory")))
            if mem is not None:
                # pm2 reports bytes; small values were already sent in MB.
                mem_mb = mem / (1024 * 1024) if mem > 100_000 else mem

        # Uptime: an explicit duration, or a start timestamp (pm_uptime, in ms
        # from pm2 jlist). A bare "uptime" over 1e9 can only be a timestamp —
        # as a duration that would be 31+ years.
        uptime = _num(p.get("uptime_secs", p.get("uptime_seconds")))
        if uptime is None:
            started = _num(p.get("pm_uptime", env.get("pm_uptime")))
            bare = _num(p.get("uptime"))
            if started is None and bare is not None:
                if bare > 1e9:
                    started = bare
                else:
                    uptime = bare
            if started is not None:
                started = started / 1000 if started > 1e11 else started  # ms → s
                uptime = max(0.0, now - started)
        if status != "online":
            uptime = None

        out.append({
            "name": str(p.get("name") or env.get("name") or "?")[:120],
            "id": p.get("pm_id", p.get("id")),
            # Which PM2 daemon it belongs to — a box can run one per user
            # (e.g. root's /root/.pm2 and adminqa's ~/.pm2), with clashing ids.
            "user": str(p.get("pm2_user") or p.get("user") or env.get("username") or "")[:64] or None,
            "status": status,
            "cpu": round(cpu, 1) if cpu is not None else None,
            "memory_mb": round(mem_mb, 1) if mem_mb is not None else None,
            "restarts": int(_num(p.get("restarts", p.get("restart_time", env.get("restart_time")))) or 0),
            "uptime_secs": round(uptime) if uptime is not None else None,
            "mode": str(p.get("exec_mode") or env.get("exec_mode") or p.get("mode") or "").replace("_mode", ""),
            "instances": p.get("instances", env.get("instances")),
        })
    out.sort(key=lambda x: (x["status"] == "online", (x["user"] or ""), x["name"].lower()))
    return out


def pm2_summary(procs):
    """{'online': n, 'total': n} or None when the agent sent no PM2 data."""
    if not procs:
        return None
    return {"online": sum(1 for p in procs if p["status"] == "online"), "total": len(procs)}


def _check_access(table_name):
    if not _TABLE_RE.match(table_name):
        abort(404)
    allowed = current_user.allowed_servers()
    if allowed is not None and table_name not in allowed:
        abort(403)


@servers_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()

        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, os_type, hostname,
                       public_ip, registered_at, last_seen, status, alerts_enabled
                FROM machine_registry ORDER BY system_name, location
            """)
        else:
            if not allowed:
                return render_template("servers.html", machines=[], thresholds={})
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, os_type, hostname,
                       public_ip, registered_at, last_seen, status, alerts_enabled
                FROM machine_registry WHERE table_name IN ({placeholders})
                ORDER BY system_name, location
            """, list(allowed))

        machines = [dict(m) for m in cur.fetchall()]

        # Alert thresholds — used to flag servers over the fleet-wide limits
        cur.execute("SELECT alert_type, threshold FROM alert_config")
        th = {r["alert_type"]: r["threshold"] for r in cur.fetchall()}
        thresholds = {"cpu": th.get("cpu") or 90, "ram": th.get("ram") or 90,
                      "disk": th.get("disk") or 85}

        # Latest reading per machine for the CPU / RAM / disk meters. One
        # LIMIT 1 query per machine table; a broken table just shows "—".
        for m in machines:
            m["cpu"] = m["ram"] = m["disk"] = m["pm2"] = None
            try:
                # to_jsonb(t)->'pm2_processes' is NULL (not an error) on older
                # tables that don't have the column yet.
                cur.execute(sql.SQL(
                    "SELECT cpu_percent, ram_percent, disk_partitions, "
                    "to_jsonb(t)->'pm2_processes' AS pm2 FROM {} t ORDER BY ts DESC LIMIT 1"
                ).format(sql.Identifier(m["table_name"])))
                row = cur.fetchone()
            except Exception:
                conn.rollback()
                continue
            if not row:
                continue
            m["cpu"] = round(float(row["cpu_percent"] or 0), 1)
            m["pm2"] = pm2_summary(parse_pm2(row.get("pm2")))
            m["ram"] = round(float(row["ram_percent"] or 0), 1)
            disks = row.get("disk_partitions")
            try:
                disks = json.loads(disks) if isinstance(disks, str) else (disks or [])
                pcts = [float(d.get("percent") or 0) for d in disks
                        if isinstance(d, dict) and d.get("fstype") != "squashfs"
                        and not str(d.get("mountpoint") or "").startswith(("/snap/", "/proc", "/sys", "/dev", "/run"))]
                m["disk"] = round(max(pcts), 1) if pcts else None
            except Exception:
                m["disk"] = None
            m["hot"] = ((m["cpu"] or 0) >= thresholds["cpu"] or (m["ram"] or 0) >= thresholds["ram"]
                        or (m["disk"] or 0) >= thresholds["disk"])

    return render_template("servers.html", machines=machines, thresholds=thresholds)


def _safe_gpu_list(raw):
    """
    Parse a gpu_info cell into a list of GPU dicts, tolerating shapes that
    don't match what the current agent writes (a legacy single dict instead
    of a list, a malformed JSON string, non-dict entries, etc.) — one bad
    historical row shouldn't take down the whole page.
    """
    try:
        arr = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except Exception:
        return []
    if isinstance(arr, dict):
        arr = [arr]
    if not isinstance(arr, list):
        return []
    return [g for g in arr if isinstance(g, dict)]


def _net_kbs(cur, prev, field):
    """KB/s between two metric rows — byte delta divided by the time between them."""
    secs = (cur["ts"] - prev["ts"]).total_seconds() if cur.get("ts") and prev.get("ts") else 0
    delta = max(0, (cur[field] or 0) - (prev[field] or 0))
    return round(delta / 1024 / secs, 1) if secs > 0 else 0


def _safe_float(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _gpu_history_stats(table_name, minutes=60):
    """
    Downsampled per-GPU history (~200 points) + summary stats (avg/min/max
    load, time spent above 50%/80%) over the last N minutes. Uses the same
    window-function downsampling as the main /history endpoint, since a
    machine polling every few seconds could have thousands of raw rows in a
    60-minute window.
    """
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT ts, gpu_info
            FROM (
                SELECT ts, gpu_info,
                       ROW_NUMBER() OVER (ORDER BY ts) AS rn,
                       COUNT(*) OVER () AS total
                FROM {table_name}
                WHERE ts > NOW() - INTERVAL '{int(minutes)} minutes' AND gpu_info IS NOT NULL
            ) t
            WHERE rn % GREATEST(total / 200, 1) = 0
            ORDER BY ts ASC
        """)
        rows = cur.fetchall()

    if not rows:
        return {"labels": [], "gpus": []}

    labels = [str(r["ts"]) for r in rows]

    # Some rows may have fewer GPUs than others (e.g. captured before a
    # second GPU came online) — use the max seen so nothing gets dropped.
    max_gpus = 0
    for r in rows:
        max_gpus = max(max_gpus, len(_safe_gpu_list(r["gpu_info"])))

    window_secs = max((rows[-1]["ts"] - rows[0]["ts"]).total_seconds(), 1)

    def _fmt_secs(s):
        s = int(s)
        m, sec = divmod(s, 60)
        h, m = divmod(m, 60)
        return f"{h}h {m}m {sec}s" if h else f"{m}m {sec}s"

    gpus_out = []
    for gi in range(max_gpus):
        loads, vrams = [], []
        name, gtype = None, "unknown"
        for r in rows:
            arr = _safe_gpu_list(r["gpu_info"])
            if gi < len(arr):
                g = arr[gi]
                gtype = (g.get("type") or "unknown").lower()
                name = g.get("name") or name
                if gtype == "intel":
                    loads.append(_safe_float(g.get("gpu_percent")))
                    vrams.append(None)
                else:
                    loads.append(_safe_float(g.get("load_percent") or g.get("gpu_percent")))
                    vt = _safe_float(g.get("memory_total_mb") or g.get("mem_total_mb"))
                    vu = _safe_float(g.get("memory_used_mb")  or g.get("mem_used_mb"))
                    vrams.append(round(vu / vt * 100, 1) if vt > 0 else None)
            else:
                loads.append(None)
                vrams.append(None)

        clean = [v for v in loads if v is not None]
        if clean:
            avg_load = sum(clean) / len(clean)
            min_load = min(clean)
            max_load = max(clean)
            above_50 = sum(1 for v in clean if v >= 50) / len(clean) * window_secs
            above_80 = sum(1 for v in clean if v >= 80) / len(clean) * window_secs
        else:
            avg_load = min_load = max_load = above_50 = above_80 = 0

        has_vram = any(v is not None for v in vrams)
        gpus_out.append({
            "index": gi,
            "name": name or f"GPU {gi + 1}",
            "type": gtype,
            "load": loads,
            "vram_pct": vrams if has_vram else None,
            "stats": {
                "avg": round(avg_load, 1),
                "min": round(min_load, 1),
                "max": round(max_load, 1),
                "time_above_50": _fmt_secs(above_50),
                "time_above_80": _fmt_secs(above_80),
            }
        })

    return {"labels": labels, "gpus": gpus_out}


@servers_bp.route("/<table_name>/gpu-history")
@login_required
def gpu_history(table_name):
    _check_access(table_name)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM machine_registry WHERE table_name=%s", (table_name,))
        if not cur.fetchone():
            return jsonify({"error": "not found"}), 404
    try:
        minutes = max(5, min(int(request.args.get("minutes", "60")), 10080))
    except ValueError:
        minutes = 60
    try:
        return jsonify(_gpu_history_stats(table_name, minutes))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@servers_bp.route("/<table_name>/alert-history")
@login_required
def alert_history_page(table_name):
    """Paginated alert history for this machine — 10 per page by default."""
    _check_access(table_name)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT system_name, location FROM machine_registry WHERE table_name=%s", (table_name,))
        m = cur.fetchone()
        if not m:
            return jsonify({"error": "not found"}), 404
        machine_key = f"{m['system_name']}@{m['location']}"

        try:
            offset = max(0, int(request.args.get("offset", "0")))
            limit  = max(1, min(int(request.args.get("limit", "10")), 100))
        except ValueError:
            offset, limit = 0, 10

        cur.execute("SELECT COUNT(*) AS cnt FROM alert_log WHERE machine_key=%s", (machine_key,))
        total = cur.fetchone()["cnt"]

        cur.execute("""
            SELECT alert_type, subject, sent_at, success
            FROM alert_log WHERE machine_key=%s
            ORDER BY sent_at DESC
            LIMIT %s OFFSET %s
        """, (machine_key, limit, offset))
        rows = cur.fetchall()

    return jsonify({
        "total": total,
        "offset": offset,
        "limit": limit,
        "alerts": [{
            "alert_type": r["alert_type"],
            "subject": r["subject"],
            "sent_at": r["sent_at"].strftime("%m-%d %H:%M") if r["sent_at"] else "—",
            "success": r["success"],
        } for r in rows],
    })


@servers_bp.route("/<table_name>")
@login_required
def detail(table_name):
    _check_access(table_name)

    with get_db() as conn:
        cur = conn.cursor()

        cur.execute("SELECT * FROM machine_registry WHERE table_name=%s", (table_name,))
        machine = cur.fetchone()
        if not machine:
            abort(404)

        # Latest snapshot
        cur.execute(f"""
            SELECT * FROM {table_name} ORDER BY ts DESC LIMIT 1
        """)
        latest = cur.fetchone()

        # Last 60 data points for charts
        cur.execute(f"""
            SELECT ts, cpu_percent, ram_percent, swap_percent,
                   net_bytes_sent, net_bytes_recv, cpu_temp, cpu_per_core
            FROM {table_name} ORDER BY ts DESC LIMIT 60
        """)
        history_rows = list(reversed(cur.fetchall()))

        # Alert log for this machine — first page only (10); rest loads via
        # /alert-history as the person clicks Next.
        machine_key = f"{machine['system_name']}@{machine['location']}"
        cur.execute("SELECT COUNT(*) AS cnt FROM alert_log WHERE machine_key=%s", (machine_key,))
        alert_total = cur.fetchone()["cnt"]
        cur.execute("""
            SELECT alert_type, subject, sent_at, success
            FROM alert_log WHERE machine_key=%s ORDER BY sent_at DESC LIMIT 10
        """, (machine_key,))
        alert_history = cur.fetchall()

    # Parse JSON fields
    disks = []
    gpus  = []
    procs = []
    pm2 = []
    if latest:
        pm2 = parse_pm2(latest.get("pm2_processes"))
        raw_disks = latest.get("disk_partitions")
        if raw_disks:
            disks = json.loads(raw_disks) if isinstance(raw_disks, str) else raw_disks

        raw_gpus = latest.get("gpu_info")
        if raw_gpus:
            gpus = json.loads(raw_gpus) if isinstance(raw_gpus, str) else raw_gpus

        raw_procs = latest.get("top_processes")
        if raw_procs:
            procs = json.loads(raw_procs) if isinstance(raw_procs, str) else raw_procs

    # Build chart series (JSON-serialisable)
    chart_labels = [str(r["ts"]) for r in history_rows]
    chart_cpu    = [r["cpu_percent"]  or 0 for r in history_rows]
    chart_ram    = [r["ram_percent"]  or 0 for r in history_rows]
    chart_swap   = [r["swap_percent"] or 0 for r in history_rows]
    chart_temp   = [r["cpu_temp"]     or 0 for r in history_rows]

    # Network delta (bytes → KB/s approx)
    chart_net_sent = []
    chart_net_recv = []
    for i, r in enumerate(history_rows):
        if i == 0:
            chart_net_sent.append(0)
            chart_net_recv.append(0)
        else:
            prev = history_rows[i - 1]
            chart_net_sent.append(_net_kbs(r, prev, "net_bytes_sent"))
            chart_net_recv.append(_net_kbs(r, prev, "net_bytes_recv"))

    # ── Per-core CPU history — each row's cpu_per_core JSONB is an array of
    # core percentages at that instant; transpose into one series per core.
    core_count = 0
    chart_cores = []  # list of arrays, one per core, aligned with chart_labels
    for r in history_rows:
        raw = r.get("cpu_per_core")
        if raw:
            arr = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(arr, list):
                core_count = max(core_count, len(arr))
    if core_count:
        chart_cores = [[] for _ in range(core_count)]
        for r in history_rows:
            raw = r.get("cpu_per_core")
            arr = (json.loads(raw) if isinstance(raw, str) else raw) if raw else []
            if not isinstance(arr, list):
                arr = []
            for ci in range(core_count):
                # Agent-supplied — coerce to a number so nothing but numbers
                # can ever reach the page's <script> block.
                chart_cores[ci].append(_safe_float(arr[ci]) if ci < len(arr) else 0)

    # ── Trend deltas for the top stat cards — current value vs the average
    # over the loaded window, so "↑8.4%" means "8.4 points above the recent
    # average", not a fabricated number.
    def _trend(series, current):
        vals = [v for v in series if v is not None]
        if len(vals) < 2 or current is None:
            return 0.0
        avg = sum(vals) / len(vals)
        return round(current - avg, 1)

    cur_cpu  = latest.get("cpu_percent")  if latest else None
    cur_ram  = latest.get("ram_percent")  if latest else None
    trend_cpu = _trend(chart_cpu, cur_cpu)
    trend_ram = _trend(chart_ram, cur_ram)

    # ── Primary GPU (first one reported) for the two GPU stat cards ──
    gpu_primary = gpus[0] if gpus else None
    gpu_load_pct = None
    gpu_vram_pct = None
    gpu_vram_used_mb = gpu_vram_total_mb = 0
    if gpu_primary:
        gtype = (gpu_primary.get("type") or "").lower()
        if gtype == "intel":
            gpu_load_pct = float(gpu_primary.get("gpu_percent") or 0)
        else:
            gpu_load_pct = float(gpu_primary.get("load_percent") or gpu_primary.get("gpu_percent") or 0)
            gpu_vram_used_mb  = float(gpu_primary.get("memory_used_mb")  or gpu_primary.get("mem_used_mb")  or 0)
            gpu_vram_total_mb = float(gpu_primary.get("memory_total_mb") or gpu_primary.get("mem_total_mb") or 0)
            if gpu_vram_total_mb > 0:
                gpu_vram_pct = round(gpu_vram_used_mb / gpu_vram_total_mb * 100, 1)

    # ── Primary disk for the Disk Usage donut — root filesystem if present,
    # else the first non-squashfs partition.
    real_disks = [d for d in disks if d.get("fstype") != "squashfs"]
    disk_primary = next((d for d in real_disks if d.get("mountpoint") == "/"), None) \
                   or (real_disks[0] if real_disks else None)

    # ── Per-GPU history + stats (last 60 minutes by default) for the
    # redesigned GPU Load Overview section — wrapped so a bug in this
    # brand-new code can't 500 the whole page; CPU/RAM/etc. still load.
    if gpus:
        try:
            gpu_history = _gpu_history_stats(table_name, 60)
        except Exception as e:
            print(f"[servers] gpu_history_stats failed for {table_name}: {e}")
            gpu_history = {"labels": [], "gpus": []}
    else:
        gpu_history = {"labels": [], "gpus": []}

    # ── Process status tally — counts within the sampled top_processes list
    # only (your agent reports a "top N by usage" sample, not every process
    # on the machine), so this is NOT a full system census.
    proc_status_counts = {}
    for p in procs:
        st = (p.get("status") or "unknown").lower()
        proc_status_counts[st] = proc_status_counts.get(st, 0) + 1

    return render_template("server_detail.html",
        analytics_thresholds=ANALYTICS_THRESHOLDS,
        real_disks=real_disks,
        machine=machine,
        latest=latest,
        disks=disks,
        gpus=gpus,
        procs=procs,
        alert_history=alert_history,
        alert_total=alert_total,
        chart_labels=chart_labels,
        chart_cpu=chart_cpu,
        chart_ram=chart_ram,
        chart_swap=chart_swap,
        chart_temp=chart_temp,
        chart_net_sent=chart_net_sent,
        chart_net_recv=chart_net_recv,
        chart_cores=chart_cores,
        last_net_sent=(chart_net_sent[-1] if chart_net_sent else 0),
        last_net_recv=(chart_net_recv[-1] if chart_net_recv else 0),
        trend_cpu=trend_cpu,
        trend_ram=trend_ram,
        gpu_primary=gpu_primary,
        gpu_load_pct=gpu_load_pct,
        gpu_vram_pct=gpu_vram_pct,
        gpu_vram_used_mb=gpu_vram_used_mb,
        gpu_vram_total_mb=gpu_vram_total_mb,
        disk_primary=disk_primary,
        gpu_history=gpu_history,
        proc_status_counts=proc_status_counts,
        pm2=pm2,
        pm2_sum=pm2_summary(pm2),
    )


@servers_bp.route("/<table_name>/toggle-alerts", methods=["POST"])
@login_required
def toggle_alerts(table_name):
    """Mute/unmute alert emails for one machine — status tracking is unaffected."""
    _check_access(table_name)
    if current_user.role != "admin":
        abort(403)

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE machine_registry
            SET alerts_enabled = NOT alerts_enabled
            WHERE table_name = %s
            RETURNING alerts_enabled
        """, (table_name,))
        row = cur.fetchone()
        conn.commit()

    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({"alerts_enabled": row["alerts_enabled"]})


@servers_bp.route("/<table_name>/history")
@login_required
def history(table_name):
    """
    Historical metrics for an arbitrary date range, for the chart date-filter.
    Evenly downsampled to ~300 points via a window function so a multi-day
    range doesn't ship (and chart) tens of thousands of raw rows.
    """
    _check_access(table_name)
    start = request.args.get("start", "").strip()
    end   = request.args.get("end", "").strip()
    if not start or not end:
        return jsonify({"error": "Pick both a start and end date/time."}), 400
    try:
        start_dt, end_dt = datetime.fromisoformat(start), datetime.fromisoformat(end)
        span = end_dt - start_dt
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid date range."}), 400
    if span.total_seconds() <= 0 or span.days > HISTORY_MAX_DAYS:
        # Bounded so a huge range can't force full-table window scans.
        return jsonify({"error": f"Range must be between 1 minute and {HISTORY_MAX_DAYS} days."}), 400

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM machine_registry WHERE table_name=%s", (table_name,))
        if not cur.fetchone():
            return jsonify({"error": "not found"}), 404

        try:
            cur.execute(f"""
                SELECT ts, cpu_percent, ram_percent, swap_percent, cpu_temp,
                       net_bytes_sent, net_bytes_recv
                FROM (
                    SELECT ts, cpu_percent, ram_percent, swap_percent, cpu_temp,
                           net_bytes_sent, net_bytes_recv,
                           ROW_NUMBER() OVER (ORDER BY ts) AS rn,
                           COUNT(*) OVER () AS total
                    FROM {table_name}
                    WHERE ts BETWEEN %s AND %s
                ) t
                WHERE rn %% GREATEST(total / 300, 1) = 0
                ORDER BY ts ASC
            """, (start, end))
            rows = cur.fetchall()
        except Exception:
            return jsonify({"error": "Invalid date range."}), 400

    if not rows:
        return jsonify({
            "labels": [], "cpu": [], "ram": [], "swap": [], "temp": [],
            "net_sent": [], "net_recv": [], "count": 0,
        })

    labels = [str(r["ts"]) for r in rows]
    cpu  = [r["cpu_percent"]  or 0 for r in rows]
    ram  = [r["ram_percent"]  or 0 for r in rows]
    swap = [r["swap_percent"] or 0 for r in rows]
    temp = [r["cpu_temp"]     or 0 for r in rows]

    net_sent, net_recv = [], []
    for i, r in enumerate(rows):
        if i == 0:
            net_sent.append(0)
            net_recv.append(0)
        else:
            prev = rows[i - 1]
            net_sent.append(_net_kbs(r, prev, "net_bytes_sent"))
            net_recv.append(_net_kbs(r, prev, "net_bytes_recv"))

    return jsonify({
        "labels": labels, "cpu": cpu, "ram": ram, "swap": swap, "temp": temp,
        "net_sent": net_sent, "net_recv": net_recv, "count": len(rows),
    })


# A gap between two consecutive reports longer than this counts as offline —
# the same rule (and env var) the checker uses to flip machine_registry.status.
OFFLINE_AFTER_SECS = int(os.getenv("OFFLINE_AFTER_SECS", "60"))
UPTIME_MAX_HOURS = 24 * 31
UPTIME_MAX_OUTAGES = 2000  # a flapping agent shouldn't ship megabytes of segments


def _uptime_timeline(table_name, hours):
    """
    Online/offline timeline for the last `hours`, derived from gaps in the
    machine's own metric rows (so it covers all retained history, not just
    events since a log table existed).

    Returns {window_start, window_end (epoch secs), segments: [{state, start, end}],
    online_secs, offline_secs, nodata_secs, uptime_pct, outages, longest_outage_secs}.
    state is "online", "offline" or "nodata" (before the oldest retained row).
    """
    t = sql.Identifier(table_name)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT EXTRACT(EPOCH FROM NOW()) AS now")
        now = float(cur.fetchone()["now"])
        start = now - hours * 3600

        cur.execute(sql.SQL("""
            SELECT EXTRACT(EPOCH FROM MIN(ts)) AS first, EXTRACT(EPOCH FROM MAX(ts)) AS last
            FROM {t} WHERE ts > to_timestamp(%s)
        """).format(t=t), (start,))
        bounds = cur.fetchone()
        cur.execute(sql.SQL("""
            SELECT EXTRACT(EPOCH FROM ts) AS ts FROM {t}
            WHERE ts <= to_timestamp(%s) ORDER BY ts DESC LIMIT 1
        """).format(t=t), (start,))
        before = cur.fetchone()
        cur.execute(sql.SQL("""
            SELECT EXTRACT(EPOCH FROM prev_ts) AS s, EXTRACT(EPOCH FROM ts) AS e
            FROM (
                SELECT ts, LAG(ts) OVER (ORDER BY ts) AS prev_ts
                FROM {t} WHERE ts > to_timestamp(%s)
            ) x
            WHERE ts - prev_ts > make_interval(secs => %s)
            ORDER BY ts
            LIMIT %s
        """).format(t=t), (start, OFFLINE_AFTER_SECS, UPTIME_MAX_OUTAGES))
        gaps = [(float(r["s"]), float(r["e"])) for r in cur.fetchall()]

    first = float(bounds["first"]) if bounds and bounds["first"] is not None else None
    last = float(bounds["last"]) if bounds and bounds["last"] is not None else None
    prev = float(before["ts"]) if before else None

    segments = []

    def add(state, s, e):
        s, e = max(s, start), min(e, now)
        if e <= s:
            return
        if segments and segments[-1]["state"] == state and abs(segments[-1]["end"] - s) < 1e-6:
            segments[-1]["end"] = e
        else:
            segments.append({"state": state, "start": s, "end": e})

    if first is None:
        # No reports at all inside the window.
        if prev is None:
            add("nodata", start, now)
        else:
            add("offline", start, now)
    else:
        # Leading edge: was it already running when the window opened?
        if prev is None:
            add("nodata", start, first)
        elif first - prev > OFFLINE_AFTER_SECS:
            add("offline", start, first)
        else:
            add("online", start, first)
        cursor = first
        for s, e in gaps:
            add("online", cursor, s)
            add("offline", s, e)
            cursor = e
        add("online", cursor, last)
        # Trailing edge: silent since the last report?
        if now - last > OFFLINE_AFTER_SECS:
            add("offline", last, now)
        else:
            add("online", last, now)

    totals = {"online": 0.0, "offline": 0.0, "nodata": 0.0}
    for seg in segments:
        totals[seg["state"]] += seg["end"] - seg["start"]
    offline_segs = [s for s in segments if s["state"] == "offline"]
    observed = totals["online"] + totals["offline"]
    return {
        "window_start": start,
        "window_end": now,
        "threshold_secs": OFFLINE_AFTER_SECS,
        "segments": segments,
        "online_secs": round(totals["online"]),
        "offline_secs": round(totals["offline"]),
        "nodata_secs": round(totals["nodata"]),
        "uptime_pct": round(totals["online"] / observed * 100, 2) if observed else None,
        "outages": len(offline_segs),
        "longest_outage_secs": round(max((s["end"] - s["start"] for s in offline_segs), default=0)),
        "truncated": len(gaps) >= UPTIME_MAX_OUTAGES,
    }


@servers_bp.route("/<table_name>/uptime")
@login_required
def uptime(table_name):
    """Online/offline timeline JSON for the detail page's uptime chart."""
    _check_access(table_name)
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24
    hours = max(1, min(hours, UPTIME_MAX_HOURS))

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM machine_registry WHERE table_name=%s", (table_name,))
        if not cur.fetchone():
            return jsonify({"error": "not found"}), 404
    try:
        return jsonify(_uptime_timeline(table_name, hours))
    except Exception as e:
        print(f"[servers] uptime timeline failed for {table_name}: {e}")
        return jsonify({"error": "Could not load uptime history."}), 500


# ── Analytics cards (CPU / RAM / Swap / Disk / Temp / Net / Disk I/O / Cores) ──
# Status zones per metric: [warning, critical(, very high)] — the page colours
# gauges, trend lines and status pills from these. One place to change them.
ANALYTICS_THRESHOLDS = {
    "cpu":  [60, 85],
    "ram":  [60, 80, 95],
    "swap": [40, 70, 90],
    "disk": [70, 85, 95],
    "temp": [65, 80],
    "core": [60, 80, 95],
}
TREND_POINTS = 120    # buckets per window — a smooth line at any range, small payload
RATE_MAX_GAP = 600    # counter deltas across a longer gap (outage / reboot) are skipped

_DISK_PCT = (
    "(SELECT NULLIF(p->>'percent', '')::float FROM jsonb_array_elements("
    "CASE WHEN jsonb_typeof(disk_partitions) = 'array' THEN disk_partitions ELSE '[]'::jsonb END) p "
    "WHERE p->>'mountpoint' = %s LIMIT 1)"
)
_CORE_PCT = "(CASE WHEN jsonb_typeof(cpu_per_core) = 'array' THEN NULLIF(cpu_per_core->>%s, '')::float END)"

# Level metrics: one value per row, bucketed to avg/min/max.
GAUGE_METRICS = {
    "cpu":  "cpu_percent",
    "ram":  "ram_percent",
    "swap": "swap_percent",
    "temp": "NULLIF(cpu_temp, 0)",   # 0 = no sensor
    "disk": _DISK_PCT,               # needs mount
    "core": _CORE_PCT,               # needs core index
}
# Counter metrics: per-second rate from deltas of two cumulative counters (a, b).
RATE_METRICS = {
    "net":    {"a": "net_bytes_recv", "b": "net_bytes_sent", "scale": 1 / 1024,
               "cols": ("download_kbs", "upload_kbs")},
    "diskio": {"a": "NULLIF(disk_io->>'read_mb', '')::float",
               "b": "NULLIF(disk_io->>'write_mb', '')::float", "scale": 1,
               "cols": ("read_mbs", "write_mbs")},
}


def _metric_history(table_name, metric, start=None, end=None, hours=1, mount=None, core=None):
    """
    Trend for one analytics card, averaged into ~TREND_POINTS evenly spaced
    buckets between start and end (epoch secs; default: the last `hours`).
    Empty buckets are null so a line breaks over an outage instead of
    bridging it.

    Level metrics return points [{t, avg, min, max}] and min/max/avg/first/last.
    Rate metrics return points [{t, a, a_max, b, b_max}] (per-second rates;
    net in KB/s, disk I/O in MB/s) and peaks, averages and totals transferred.
    """
    t = sql.Identifier(table_name)
    with get_db() as conn:
        cur = conn.cursor()
        if start is None:
            cur.execute("SELECT EXTRACT(EPOCH FROM NOW()) AS now")
            end = float(cur.fetchone()["now"])
            start = end - hours * 3600
        bucket = max(15, int((end - start) // TREND_POINTS))

        if metric in GAUGE_METRICS:
            extra = [mount or "/"] if metric == "disk" else [int(core or 0)] if metric == "core" else []
            cur.execute(sql.SQL("""
                SELECT FLOOR(EXTRACT(EPOCH FROM ts) / %s) AS b,
                       AVG(v) AS a, MIN(v) AS lo, MAX(v) AS hi, COUNT(v) AS n
                FROM (SELECT ts, {expr} AS v FROM {t}
                      WHERE ts > to_timestamp(%s) AND ts <= to_timestamp(%s)) x
                WHERE v IS NOT NULL
                GROUP BY 1 ORDER BY 1
            """).format(expr=sql.SQL(GAUGE_METRICS[metric]), t=t), [bucket, *extra, start, end])
        else:
            m = RATE_METRICS[metric]
            cur.execute(sql.SQL("""
                SELECT FLOOR(EXTRACT(EPOCH FROM ts) / %s) AS b,
                       AVG(da / dt) AS aa, MAX(da / dt) AS am, AVG(db / dt) AS ba, MAX(db / dt) AS bm,
                       SUM(da) AS ta, SUM(db) AS tb, COUNT(*) AS n
                FROM (
                    SELECT ts, a - LAG(a) OVER w AS da, b - LAG(b) OVER w AS db,
                           EXTRACT(EPOCH FROM ts - LAG(ts) OVER w) AS dt
                    FROM (SELECT ts, {a} AS a, {b} AS b FROM {t}
                          WHERE ts > to_timestamp(%s) - INTERVAL '10 minutes'
                            AND ts <= to_timestamp(%s)) r
                    WINDOW w AS (ORDER BY ts)
                ) x
                WHERE ts > to_timestamp(%s) AND dt > 0 AND dt <= %s AND da >= 0 AND db >= 0
                GROUP BY 1 ORDER BY 1
            """).format(a=sql.SQL(m["a"]), b=sql.SQL(m["b"]), t=t),
                [bucket, start, end, start, RATE_MAX_GAP])
        rows = cur.fetchall()

    by_bucket = {int(r["b"]): r for r in rows}
    buckets = range(int(start // bucket), int(end // bucket) + 1)
    out = {"metric": metric, "window_start": start, "window_end": end, "bucket_secs": bucket}

    if metric in GAUGE_METRICS:
        points, lo, hi, total, count = [], None, None, 0.0, 0
        for b in buckets:
            r, ts = by_bucket.get(b), b * bucket
            if not r:
                points.append({"t": ts, "avg": None, "min": None, "max": None})
                continue
            a, mn, mx, n = float(r["a"]), float(r["lo"]), float(r["hi"]), int(r["n"])
            points.append({"t": ts, "avg": round(a, 1), "min": round(mn, 1), "max": round(mx, 1)})
            if lo is None or mn < lo["value"]:
                lo = {"value": round(mn, 1), "t": ts}
            if hi is None or mx > hi["value"]:
                hi = {"value": round(mx, 1), "t": ts}
            total += a * n
            count += n
        filled = [p["avg"] for p in points if p["avg"] is not None]
        out.update({
            "points": points, "min": lo, "max": hi,
            "avg": round(total / count, 1) if count else None,
            "first": filled[0] if filled else None, "last": filled[-1] if filled else None,
            "samples": count,
        })
        return out

    scale = RATE_METRICS[metric]["scale"]
    points, peaks = [], {"a": None, "b": None}
    sums = {"a": 0.0, "b": 0.0}
    totals = {"a": 0.0, "b": 0.0}
    count = 0
    for b in buckets:
        r, ts = by_bucket.get(b), b * bucket
        if not r:
            points.append({"t": ts, "a": None, "a_max": None, "b": None, "b_max": None})
            continue
        n = int(r["n"])
        p = {"t": ts}
        for k in ("a", "b"):
            avg, mx = float(r[k + "a"]) * scale, float(r[k + "m"]) * scale
            p[k], p[k + "_max"] = round(avg, 2), round(mx, 2)
            if peaks[k] is None or mx > peaks[k]["value"]:
                peaks[k] = {"value": round(mx, 2), "t": ts}
            sums[k] += avg * n
            totals[k] += float(r["t" + k])
        points.append(p)
        count += n
    out.update({
        "points": points,
        "a_peak": peaks["a"], "b_peak": peaks["b"],
        "a_avg": round(sums["a"] / count, 2) if count else None,
        "b_avg": round(sums["b"] / count, 2) if count else None,
        # raw counter units: bytes for net, MB for disk I/O
        "a_total": round(totals["a"], 2), "b_total": round(totals["b"], 2),
        "samples": count,
    })
    return out


def _metric_csv(d, table_name):
    """CSV download of a _metric_history result (one row per bucket, UTC times)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    metric = d["metric"]
    if metric in RATE_METRICS:
        a, b = RATE_METRICS[metric]["cols"]
        w.writerow(["time_utc", a + "_avg", a + "_max", b + "_avg", b + "_max"])
        keys = ("a", "a_max", "b", "b_max")
    else:
        w.writerow(["time_utc", metric + "_avg", metric + "_min", metric + "_max"])
        keys = ("avg", "min", "max")
    for p in d["points"]:
        if all(p[k] is None for k in keys):
            continue
        w.writerow([datetime.fromtimestamp(p["t"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S")]
                   + [p[k] for k in keys])
    name = f"{table_name.removeprefix('machine_')}_{metric}_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _parse_instant(v):
    """ISO date/time from the page (toISOString) → epoch secs, or None."""
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@servers_bp.route("/<table_name>/metric-history")
@login_required
def metric_history(table_name):
    """
    Trend JSON (or CSV with format=csv) for one analytics card.
    ?metric=cpu|ram|swap|temp|disk|core|net|diskio
    &hours=N  — or —  &start=ISO&end=ISO   (custom range, max HISTORY_MAX_DAYS)
    &mount=/  (disk)   &core=N (core)
    """
    _check_access(table_name)
    metric = request.args.get("metric", "")
    if metric not in GAUGE_METRICS and metric not in RATE_METRICS:
        return jsonify({"error": "Unknown metric."}), 400

    start = end = None
    hours = 1
    if request.args.get("start") or request.args.get("end"):
        start = _parse_instant(request.args.get("start", ""))
        end = _parse_instant(request.args.get("end", ""))
        if start is None or end is None:
            return jsonify({"error": "Invalid date range."}), 400
        if end - start < 60 or end - start > HISTORY_MAX_DAYS * 86400:
            return jsonify({"error": f"Range must be between 1 minute and {HISTORY_MAX_DAYS} days."}), 400
    else:
        try:
            hours = int(request.args.get("hours", "1"))
        except ValueError:
            hours = 1
        hours = max(1, min(hours, UPTIME_MAX_HOURS))

    mount = request.args.get("mount", "/")[:255]
    try:
        core = max(0, min(int(request.args.get("core", "0")), 4095))
    except ValueError:
        core = 0

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM machine_registry WHERE table_name=%s", (table_name,))
        if not cur.fetchone():
            return jsonify({"error": "not found"}), 404
    try:
        d = _metric_history(table_name, metric, start, end, hours, mount, core)
    except Exception as e:
        print(f"[servers] {metric} history failed for {table_name}: {e}")
        return jsonify({"error": "Could not load history."}), 500
    if request.args.get("format") == "csv":
        return _metric_csv(d, table_name)
    return jsonify(d)


@servers_bp.route("/<table_name>/live")
@login_required
def live(table_name):
    """JSON endpoint polled every 2s by the detail page."""
    _check_access(table_name)

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT status, last_seen FROM machine_registry WHERE table_name=%s", (table_name,))
        reg = cur.fetchone()
        if not reg:
            return jsonify({"error": "not found"}), 404

        cur.execute(f"""
            SELECT ts, cpu_percent, ram_percent, swap_percent,
                   swap_used_gb, swap_total_gb,
                   net_bytes_sent, net_bytes_recv, cpu_temp, cpu_freq_mhz,
                   ram_used_gb, ram_total_gb, uptime_seconds,
                   net_packets_sent, net_packets_recv,
                   disk_partitions, gpu_info, top_processes, cpu_per_core, disk_io,
                   to_jsonb(t)->'pm2_processes' AS pm2_processes
            FROM {table_name} t ORDER BY ts DESC LIMIT 2
        """)
        rows = cur.fetchall()

    latest = dict(rows[0]) if rows else {}

    # Disk partitions
    raw_dp = latest.pop("disk_partitions", None)
    if raw_dp:
        latest["disk_partitions"] = json.loads(raw_dp) if isinstance(raw_dp, str) else raw_dp

    # GPU info — the frontend's pollLive() reads d.gpus (matches the "gpus"
    # key the initial page render also uses), not the raw column name.
    raw_gpus = latest.pop("gpu_info", None)
    if raw_gpus:
        latest["gpus"] = json.loads(raw_gpus) if isinstance(raw_gpus, str) else raw_gpus

    # Top processes
    raw_procs = latest.pop("top_processes", None)
    if raw_procs:
        latest["top_processes"] = json.loads(raw_procs) if isinstance(raw_procs, str) else raw_procs

    # PM2 apps (None when the agent doesn't report PM2 at all)
    latest["pm2"] = parse_pm2(latest.pop("pm2_processes", None))

    # Per-core CPU
    raw_cores = latest.pop("cpu_per_core", None)
    if raw_cores:
        latest["cpu_per_core"] = json.loads(raw_cores) if isinstance(raw_cores, str) else raw_cores

    # Network KB/s
    if len(rows) >= 2:
        latest["net_sent_kbs"] = _net_kbs(rows[0], rows[1], "net_bytes_sent")
        latest["net_recv_kbs"] = _net_kbs(rows[0], rows[1], "net_bytes_recv")
    else:
        latest["net_sent_kbs"] = 0
        latest["net_recv_kbs"] = 0

    # Packets/s and disk read/write MB/s from the two newest rows' counters
    latest.pop("disk_io", None)
    latest["disk_read_mbs"] = latest["disk_write_mbs"] = None
    latest["net_recv_pps"] = latest["net_sent_pps"] = None
    if len(rows) >= 2:
        secs = (rows[0]["ts"] - rows[1]["ts"]).total_seconds() if rows[0].get("ts") and rows[1].get("ts") else 0
        if secs > 0:
            for field, out_key in (("net_packets_recv", "net_recv_pps"), ("net_packets_sent", "net_sent_pps")):
                if rows[0].get(field) is not None and rows[1].get(field) is not None:
                    latest[out_key] = round(max(0, rows[0][field] - rows[1][field]) / secs, 1)
        def _io(r):
            v = r.get("disk_io")
            v = json.loads(v) if isinstance(v, str) else v
            return v if isinstance(v, dict) else {}
        cur_io, prev_io = _io(rows[0]), _io(rows[1])
        secs = (rows[0]["ts"] - rows[1]["ts"]).total_seconds() if rows[0].get("ts") and rows[1].get("ts") else 0
        if secs > 0 and cur_io and prev_io:
            for key, out_key in (("read_mb", "disk_read_mbs"), ("write_mb", "disk_write_mbs")):
                delta = _safe_float(cur_io.get(key)) - _safe_float(prev_io.get(key))
                latest[out_key] = round(max(0.0, delta) / secs, 2)

    latest["status"]    = reg["status"]
    latest["last_seen"] = str(reg["last_seen"])
    # Convert ts to string
    if "ts" in latest and latest["ts"]:
        latest["ts"] = str(latest["ts"])

    return jsonify(latest)