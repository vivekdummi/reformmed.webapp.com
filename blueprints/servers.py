import json
from flask import Blueprint, render_template, abort, jsonify, request
from flask_login import login_required, current_user
from db import get_db

servers_bp = Blueprint("servers", __name__, url_prefix="/servers")


def _check_access(table_name):
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
                return render_template("servers.html", machines=[])
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, os_type, hostname,
                       public_ip, registered_at, last_seen, status, alerts_enabled
                FROM machine_registry WHERE table_name IN ({placeholders})
                ORDER BY system_name, location
            """, list(allowed))

        machines = cur.fetchall()

    return render_template("servers.html", machines=machines)


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

        # Alert log for this machine
        machine_key = f"{machine['system_name']}@{machine['location']}"
        cur.execute("""
            SELECT alert_type, subject, sent_at, success
            FROM alert_log WHERE machine_key=%s ORDER BY sent_at DESC LIMIT 20
        """, (machine_key,))
        alert_history = cur.fetchall()

    # Parse JSON fields
    disks = []
    gpus  = []
    procs = []
    if latest:
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
            chart_net_sent.append(max(0, (r["net_bytes_sent"] or 0) - (prev["net_bytes_sent"] or 0)) // 1024)
            chart_net_recv.append(max(0, (r["net_bytes_recv"] or 0) - (prev["net_bytes_recv"] or 0)) // 1024)

    # ── Per-core CPU history — each row's cpu_per_core JSONB is an array of
    # core percentages at that instant; transpose into one series per core.
    core_count = 0
    chart_cores = []  # list of arrays, one per core, aligned with chart_labels
    for r in history_rows:
        raw = r.get("cpu_per_core")
        if raw:
            arr = json.loads(raw) if isinstance(raw, str) else raw
            core_count = max(core_count, len(arr))
    if core_count:
        chart_cores = [[] for _ in range(core_count)]
        for r in history_rows:
            raw = r.get("cpu_per_core")
            arr = (json.loads(raw) if isinstance(raw, str) else raw) if raw else []
            for ci in range(core_count):
                chart_cores[ci].append(arr[ci] if ci < len(arr) else 0)

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
    # else the first non-squashfs partition. The full per-partition
    # breakdown remains in the Disk Partitions section further down.
    real_disks = [d for d in disks if d.get("fstype") != "squashfs"]
    disk_primary = next((d for d in real_disks if d.get("mountpoint") == "/"), None) \
                   or (real_disks[0] if real_disks else None)

    # ── Process status tally — counts within the sampled top_processes list
    # only (your agent reports a "top N by usage" sample, not every process
    # on the machine), so this is NOT a full system census.
    proc_status_counts = {}
    for p in procs:
        st = (p.get("status") or "unknown").lower()
        proc_status_counts[st] = proc_status_counts.get(st, 0) + 1

    return render_template("server_detail.html",
        machine=machine,
        latest=latest,
        disks=disks,
        gpus=gpus,
        procs=procs,
        alert_history=alert_history,
        chart_labels=json.dumps(chart_labels),
        chart_cpu=json.dumps(chart_cpu),
        chart_ram=json.dumps(chart_ram),
        chart_swap=json.dumps(chart_swap),
        chart_temp=json.dumps(chart_temp),
        chart_net_sent=json.dumps(chart_net_sent),
        chart_net_recv=json.dumps(chart_net_recv),
        chart_cores=json.dumps(chart_cores),
        trend_cpu=trend_cpu,
        trend_ram=trend_ram,
        gpu_primary=gpu_primary,
        gpu_load_pct=gpu_load_pct,
        gpu_vram_pct=gpu_vram_pct,
        gpu_vram_used_mb=gpu_vram_used_mb,
        gpu_vram_total_mb=gpu_vram_total_mb,
        disk_primary=disk_primary,
        proc_status_counts=proc_status_counts,
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
        except Exception as e:
            return jsonify({"error": f"Invalid date range: {e}"}), 400

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
            net_sent.append(max(0, (r["net_bytes_sent"] or 0) - (prev["net_bytes_sent"] or 0)) // 1024)
            net_recv.append(max(0, (r["net_bytes_recv"] or 0) - (prev["net_bytes_recv"] or 0)) // 1024)

    return jsonify({
        "labels": labels, "cpu": cpu, "ram": ram, "swap": swap, "temp": temp,
        "net_sent": net_sent, "net_recv": net_recv, "count": len(rows),
    })
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
                   disk_partitions, gpu_info, top_processes, cpu_per_core
            FROM {table_name} ORDER BY ts DESC LIMIT 2
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

    # Per-core CPU
    raw_cores = latest.pop("cpu_per_core", None)
    if raw_cores:
        latest["cpu_per_core"] = json.loads(raw_cores) if isinstance(raw_cores, str) else raw_cores

    # Network KB/s
    if len(rows) >= 2:
        latest["net_sent_kbs"] = max(0, (rows[0]["net_bytes_sent"] or 0) - (rows[1]["net_bytes_sent"] or 0)) // 1024
        latest["net_recv_kbs"] = max(0, (rows[0]["net_bytes_recv"] or 0) - (rows[1]["net_bytes_recv"] or 0)) // 1024
    else:
        latest["net_sent_kbs"] = 0
        latest["net_recv_kbs"] = 0

    latest["status"]    = reg["status"]
    latest["last_seen"] = str(reg["last_seen"])
    # Convert ts to string
    if "ts" in latest and latest["ts"]:
        latest["ts"] = str(latest["ts"])

    return jsonify(latest)