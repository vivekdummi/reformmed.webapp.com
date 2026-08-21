from flask import Blueprint, render_template
from flask_login import login_required, current_user
from db import get_db

home_bp = Blueprint("home", __name__)


def _attention_list(machine_rows, limit=8):
    """
    Checks each accessible machine's LATEST reading against simple thresholds
    (CPU/RAM/temp/disk) and returns the ones that need a look, worst first.
    This is a real per-machine fan-out query (one per machine's own table),
    so it's computed once on full page load only — NOT on the 2s JS poll,
    to avoid hammering ~20+ tables every couple of seconds for every open tab.
    """
    out = []
    with get_db() as conn:
        cur = conn.cursor()
        for m in machine_rows:
            if m["status"] != "online":
                continue
            try:
                cur.execute(f"""
                    SELECT cpu_percent, ram_percent, cpu_temp, disk_partitions
                    FROM {m['table_name']} ORDER BY ts DESC LIMIT 1
                """)
                row = cur.fetchone()
            except Exception:
                continue
            if not row:
                continue

            reasons = []
            cpu = row.get("cpu_percent")
            ram = row.get("ram_percent")
            temp = row.get("cpu_temp")
            if cpu is not None and cpu >= 90:
                reasons.append(f"CPU {cpu:.0f}%")
            if ram is not None and ram >= 90:
                reasons.append(f"RAM {ram:.0f}%")
            if temp is not None and temp >= 80:
                reasons.append(f"Temp {temp:.0f}°C")

            disk_pct = None
            raw_disks = row.get("disk_partitions")
            if raw_disks:
                import json as _json
                try:
                    disks = _json.loads(raw_disks) if isinstance(raw_disks, str) else raw_disks
                    root = next((d for d in disks if d.get("mountpoint") == "/"), None)
                    if root and root.get("percent", 0) >= 90:
                        disk_pct = root["percent"]
                        reasons.append(f"Disk {disk_pct:.0f}%")
                except Exception:
                    pass

            if reasons:
                out.append({
                    "system_name": m["system_name"],
                    "location": m["location"],
                    "table_name": m["table_name"],
                    "reasons": reasons,
                })

    out.sort(key=lambda x: len(x["reasons"]), reverse=True)
    return out[:limit]


@home_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()  # None = all

        if allowed is None:
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry
            """)
        else:
            if not allowed:
                return render_template("home.html", total=0, online=0, offline=0,
                                       recent=[], alerts=[], dvr_summary=None,
                                       dbmon_summary=None, attention=[])
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry WHERE table_name IN ({placeholders})
            """, list(allowed))

        row = cur.fetchone()
        total   = row["total"]   or 0
        online  = row["online"]  or 0
        offline = row["offline"] or 0

        # All accessible machines (for the attention-needed scan below)
        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry ORDER BY last_seen DESC NULLS LAST
            """)
        else:
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry WHERE table_name IN ({placeholders})
                ORDER BY last_seen DESC NULLS LAST
            """, list(allowed))
        all_machines = cur.fetchall()
        recent = all_machines[:6]

        # Recent alerts — use COALESCE so missing source column doesn't crash
        try:
            cur.execute("""
                SELECT alert_type, COALESCE(source,'system') AS source,
                       machine_key, subject, sent_at, success
                FROM alert_log ORDER BY sent_at DESC LIMIT 10
            """)
        except Exception:
            cur.execute("""
                SELECT alert_type, 'system' AS source,
                       machine_key, subject, sent_at, success
                FROM alert_log ORDER BY sent_at DESC LIMIT 10
            """)
        alerts = cur.fetchall()

        # ── DVR summary — scoped to allowed hospitals if not admin ──
        dvr_allowed = current_user.allowed_hospitals()  # None = all
        if dvr_allowed is None:
            cur.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                       SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM dvr_devices
            """)
            dvr_row = cur.fetchone()
        elif not dvr_allowed:
            dvr_row = {"total": 0, "online": 0, "offline": 0}
        else:
            cur.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN d.status='online'  THEN 1 ELSE 0 END) AS online,
                       SUM(CASE WHEN d.status='offline' THEN 1 ELSE 0 END) AS offline
                FROM dvr_devices d
                JOIN dvr_locations l ON l.id = d.location_id
                WHERE l.hospital_id = ANY(%s)
            """, (list(dvr_allowed),))
            dvr_row = cur.fetchone()
        dvr_summary = {
            "total": dvr_row["total"] or 0,
            "online": dvr_row["online"] or 0,
            "offline": dvr_row["offline"] or 0,
        }

        # ── DB Monitor summary — table count only; live/dead status is
        # already computed by DB Monitor's own page, not cheap to repeat here ──
        cur.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN alerts_enabled THEN 1 ELSE 0 END) AS alerts_on
            FROM dbmon_watches
        """)
        dbmon_row = cur.fetchone()
        dbmon_summary = {
            "total": dbmon_row["total"] or 0,
            "alerts_on": dbmon_row["alerts_on"] or 0,
        }

    # Per-machine "needs attention" scan — SSR only, not part of the 2s poll.
    attention = _attention_list(all_machines)

    return render_template("home.html",
                           total=total, online=online, offline=offline,
                           recent=recent, alerts=alerts,
                           dvr_summary=dvr_summary, dbmon_summary=dbmon_summary,
                           attention=attention)