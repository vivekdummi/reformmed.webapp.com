"""
Terminal blueprint — read-only SQL terminal for machine metric tables.
Admin only. No DELETE/UPDATE/DROP/INSERT allowed.
"""
import re
from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user
from db import get_db

terminal_bp = Blueprint("terminal", __name__, url_prefix="/terminal")

# Only these table prefixes are accessible
ALLOWED_PREFIX = "machine_"

# Blocked SQL keywords
BLOCKED = re.compile(
    r'\b(DELETE|UPDATE|INSERT|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE|'
    r'COPY|VACUUM|EXECUTE|CALL|pg_read_file|pg_ls_dir)\b',
    re.IGNORECASE
)


def _is_safe(sql):
    """Return (safe, reason). Only SELECT statements on machine_ tables."""
    sql_stripped = sql.strip()
    if not sql_stripped.upper().startswith("SELECT"):
        return False, "Only SELECT statements are allowed."
    if BLOCKED.search(sql_stripped):
        return False, "Query contains blocked keywords."
    # Check that any FROM/JOIN references only machine_ tables or pg_catalog
    tables = re.findall(r'(?:FROM|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)', sql_stripped, re.IGNORECASE)
    for tbl in tables:
        if not (tbl.startswith(ALLOWED_PREFIX) or tbl.startswith("pg_") or tbl.startswith("information_")):
            return False, f"Access denied: table '{tbl}' is not a machine metric table."
    return True, ""


@terminal_bp.route("/")
@login_required
def index():
    if not current_user.is_admin:
        abort(403)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name, system_name, location, status
            FROM machine_registry ORDER BY system_name
        """)
        machines = cur.fetchall()
    return render_template("terminal.html", machines=machines)


@terminal_bp.route("/query", methods=["POST"])
@login_required
def query():
    if not current_user.is_admin:
        abort(403)

    sql = (request.get_json(silent=True) or {}).get("sql", "").strip()
    if not sql:
        return jsonify({"error": "Empty query."}), 400

    safe, reason = _is_safe(sql)
    if not safe:
        return jsonify({"error": reason}), 403

    try:
        with get_db() as conn:
            cur = conn.cursor()
            # Hard limit: add LIMIT if not present
            if "LIMIT" not in sql.upper():
                sql = sql.rstrip(";") + " LIMIT 500"
            cur.execute(sql)
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description] if cur.description else []
            return jsonify({
                "columns": columns,
                "rows": [list(r.values()) for r in rows],
                "count": len(rows),
                "sql": sql,
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@terminal_bp.route("/tables")
@login_required
def tables():
    if not current_user.is_admin:
        abort(403)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name, system_name, location, status
            FROM machine_registry ORDER BY system_name
        """)
        rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


@terminal_bp.route("/schema/<table_name>")
@login_required
def schema(table_name):
    if not current_user.is_admin:
        abort(403)
    if not table_name.startswith(ALLOWED_PREFIX):
        abort(403)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = %s
            ORDER BY ordinal_position
        """, (table_name,))
        cols = cur.fetchall()
        cur.execute(f"SELECT COUNT(*) AS cnt, MIN(ts) AS oldest, MAX(ts) AS newest FROM {table_name}")
        stats = cur.fetchone()
    return jsonify({
        "columns": [dict(c) for c in cols],
        "stats": dict(stats, oldest=str(stats["oldest"]), newest=str(stats["newest"])),
    })
