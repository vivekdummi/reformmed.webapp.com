from flask import Blueprint, render_template
from flask_login import login_required, current_user
from db import get_db

home_bp = Blueprint("home", __name__)


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
                                       recent=[], alerts=[])
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

        # Recent machines
        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry ORDER BY last_seen DESC NULLS LAST LIMIT 6
            """)
        else:
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry WHERE table_name IN ({placeholders})
                ORDER BY last_seen DESC NULLS LAST LIMIT 6
            """, list(allowed))
        recent = cur.fetchall()

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

    return render_template("home.html",
                           total=total, online=online, offline=offline,
                           recent=recent, alerts=alerts)
