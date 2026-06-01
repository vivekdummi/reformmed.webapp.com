"""
Internal JSON API consumed by frontend JS (no agent auth — uses session).
"""
from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from db import get_db

api_bp = Blueprint("api", __name__, url_prefix="/api")


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
