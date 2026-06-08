"""
Internal JSON API — consumed by frontend JS (session-auth only).
"""
from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from db import get_db

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ── Machine summary / list ────────────────────────────────────────────────────

@api_bp.route("/machines/summary")
@login_required
def machines_summary():
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()
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
                return jsonify({"total": 0, "online": 0, "offline": 0})
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry WHERE table_name IN ({ph})
            """, list(allowed))
        row = cur.fetchone()
    return jsonify({
        "total":   row["total"]   or 0,
        "online":  row["online"]  or 0,
        "offline": row["offline"] or 0,
    })


@api_bp.route("/machines/list")
@login_required
def machines_list():
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()
        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry ORDER BY system_name
            """)
        else:
            if not allowed:
                return jsonify([])
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry WHERE table_name IN ({ph}) ORDER BY system_name
            """, list(allowed))
        rows = cur.fetchall()
    return jsonify([dict(r, last_seen=str(r["last_seen"])) for r in rows])


# ── Home dashboard data (partial refresh — no full page reload) ──────────────

@api_bp.route("/home/data")
@login_required
def home_data():
    """Returns all data needed by the home page for 2-second partial refresh."""
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()

        # ── Counts ──
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
                return jsonify({"total": 0, "online": 0, "offline": 0, "recent": [], "alerts": [], "alerts_today": 0})
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry WHERE table_name IN ({ph})
            """, list(allowed))
        row = cur.fetchone()
        total   = int(row["total"]   or 0)
        online  = int(row["online"]  or 0)
        offline = int(row["offline"] or 0)

        # ── Recent machines ──
        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry ORDER BY last_seen DESC NULLS LAST LIMIT 6
            """)
        else:
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry WHERE table_name IN ({ph})
                ORDER BY last_seen DESC NULLS LAST LIMIT 6
            """, list(allowed))
        recent = [dict(r, last_seen=str(r["last_seen"])) for r in cur.fetchall()]

        # ── Recent alerts ──
        cur.execute("""
            SELECT alert_type, source, machine_key, subject, sent_at, success
            FROM alert_log ORDER BY sent_at DESC LIMIT 10
        """)
        alerts = [dict(r, sent_at=str(r["sent_at"])) for r in cur.fetchall()]

        # ── Alerts today count ──
        cur.execute("""
            SELECT COUNT(*) AS cnt FROM alert_log
            WHERE sent_at >= CURRENT_DATE
        """)
        alerts_today = int(cur.fetchone()["cnt"] or 0)

    return jsonify({
        "total": total, "online": online, "offline": offline,
        "recent": recent, "alerts": alerts, "alerts_today": alerts_today,
    })


# ── Unified alerts feed ────────────────────────────────────────────────────────

@api_bp.route("/alerts/all")
@login_required
def alerts_all():
    """Unified alert log: system + DVR + dbmonitor, last 200."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, alert_type, source, machine_key, subject, sent_at, success
            FROM alert_log ORDER BY sent_at DESC LIMIT 200
        """)
        rows = cur.fetchall()
    return jsonify([dict(r, sent_at=str(r["sent_at"])) for r in rows])


# ── Settings read ────────────────────────────────────────────────────────────

@api_bp.route("/settings")
@login_required
def settings_all():
    if not current_user.is_admin:
        return jsonify({}), 403
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM app_settings ORDER BY key")
        rows = cur.fetchall()
    return jsonify({r["key"]: r["value"] for r in rows})
