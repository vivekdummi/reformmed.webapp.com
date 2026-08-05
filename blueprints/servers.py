import json
from flask import Blueprint, render_template, abort, jsonify
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
                   net_bytes_sent, net_bytes_recv, cpu_temp
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


@servers_bp.route("/<table_name>/live")
@login_required
def live(table_name):
    """JSON endpoint polled every 10 s by the detail page."""
    _check_access(table_name)

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT status, last_seen FROM machine_registry WHERE table_name=%s", (table_name,))
        reg = cur.fetchone()
        if not reg:
            return jsonify({"error": "not found"}), 404

        cur.execute(f"""
            SELECT ts, cpu_percent, ram_percent, swap_percent,
                   net_bytes_sent, net_bytes_recv, cpu_temp, cpu_freq_mhz,
                   ram_used_gb, ram_total_gb, uptime_seconds, disk_partitions
            FROM {table_name} ORDER BY ts DESC LIMIT 2
        """)
        rows = cur.fetchall()

    latest = dict(rows[0]) if rows else {}

    # Disk partitions
    raw_dp = latest.pop("disk_partitions", None)
    if raw_dp:
        latest["disk_partitions"] = json.loads(raw_dp) if isinstance(raw_dp, str) else raw_dp

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