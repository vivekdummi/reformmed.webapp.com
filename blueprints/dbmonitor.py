"""
DB Monitor blueprint — watch any external PostgreSQL schema/table for incoming data.
Config stored in local webapp DB. Supports pause/resume per schema.
"""
import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from db import get_db
import psycopg2
import psycopg2.extras

dbmonitor_bp = Blueprint("dbmonitor", __name__, url_prefix="/dbmonitor")


def _admin_required():
    if not current_user.is_admin:
        abort(403)


def init_dbmonitor_tables():
    with get_db() as conn:
        cur = conn.cursor()
        # Store external DB connections
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dbmon_connections (
                id           SERIAL PRIMARY KEY,
                name         TEXT UNIQUE NOT NULL,
                host         TEXT NOT NULL,
                port         INTEGER NOT NULL DEFAULT 5432,
                dbname       TEXT NOT NULL,
                username     TEXT NOT NULL,
                password     TEXT NOT NULL,
                created_at   TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        # Store watched tables
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dbmon_watches (
                id           SERIAL PRIMARY KEY,
                conn_id      INTEGER REFERENCES dbmon_connections(id) ON DELETE CASCADE,
                schema_name  TEXT NOT NULL,
                table_name   TEXT NOT NULL,
                display_name TEXT,
                paused       BOOLEAN NOT NULL DEFAULT FALSE,
                created_at   TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(conn_id, schema_name, table_name)
            )
        """)


def _ext_conn(conn_row):
    """Open psycopg2 connection to an external DB."""
    return psycopg2.connect(
        host=conn_row["host"],
        port=conn_row["port"],
        dbname=conn_row["dbname"],
        user=conn_row["username"],
        password=conn_row["password"],
        connect_timeout=5,
        cursor_factory=psycopg2.extras.RealDictCursor
    )


@dbmonitor_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM dbmon_connections ORDER BY name")
        connections = cur.fetchall()
        cur.execute("""
            SELECT w.*, c.name as conn_name
            FROM dbmon_watches w
            JOIN dbmon_connections c ON c.id = w.conn_id
            ORDER BY c.name, w.schema_name, w.table_name
        """)
        watches = cur.fetchall()
    return render_template("dbmonitor.html", connections=connections, watches=watches)


@dbmonitor_bp.route("/connection/add", methods=["POST"])
@login_required
def add_connection():
    _admin_required()
    name     = request.form.get("name", "").strip()
    host     = request.form.get("host", "").strip()
    port     = request.form.get("port", "5432").strip()
    dbname   = request.form.get("dbname", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not all([name, host, dbname, username]):
        flash("All fields are required.", "danger")
        return redirect(url_for("dbmonitor.index"))

    try:
        with get_db() as conn:
            conn.cursor().execute("""
                INSERT INTO dbmon_connections (name, host, port, dbname, username, password)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, host, int(port), dbname, username, password))
        flash(f"Connection '{name}' added.", "success")
    except Exception as e:
        if "unique" in str(e).lower():
            flash("Connection name already exists.", "danger")
        else:
            flash(f"Error: {e}", "danger")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/connection/<int:conn_id>/delete", methods=["POST"])
@login_required
def delete_connection(conn_id):
    _admin_required()
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM dbmon_connections WHERE id=%s", (conn_id,))
    flash("Connection removed.", "success")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/connection/<int:conn_id>/test")
@login_required
def test_connection(conn_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM dbmon_connections WHERE id=%s", (conn_id,))
        row = cur.fetchone()
    if not row:
        return jsonify({"ok": False, "error": "Not found"})
    try:
        c = _ext_conn(row)
        cur2 = c.cursor()
        cur2.execute("SELECT version()")
        ver = cur2.fetchone()
        c.close()
        return jsonify({"ok": True, "version": str(ver[0] if ver else "OK")})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@dbmonitor_bp.route("/watch/add", methods=["POST"])
@login_required
def add_watch():
    _admin_required()
    conn_id      = request.form.get("conn_id")
    schema_name  = request.form.get("schema_name", "").strip()
    table_name   = request.form.get("table_name", "").strip()
    display_name = request.form.get("display_name", "").strip()

    if not all([conn_id, schema_name, table_name]):
        flash("Connection, schema and table are required.", "danger")
        return redirect(url_for("dbmonitor.index"))

    try:
        with get_db() as conn:
            conn.cursor().execute("""
                INSERT INTO dbmon_watches (conn_id, schema_name, table_name, display_name)
                VALUES (%s, %s, %s, %s)
            """, (conn_id, schema_name, table_name, display_name or f"{schema_name}.{table_name}"))
        flash(f"Now watching {schema_name}.{table_name}.", "success")
    except Exception as e:
        if "unique" in str(e).lower():
            flash("Already watching this table.", "warning")
        else:
            flash(f"Error: {e}", "danger")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/toggle", methods=["POST"])
@login_required
def toggle_watch(watch_id):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT paused FROM dbmon_watches WHERE id=%s", (watch_id,))
        row = cur.fetchone()
        if row:
            new_state = not row["paused"]
            cur.execute("UPDATE dbmon_watches SET paused=%s WHERE id=%s", (new_state, watch_id))
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/delete", methods=["POST"])
@login_required
def delete_watch(watch_id):
    _admin_required()
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM dbmon_watches WHERE id=%s", (watch_id,))
    flash("Watch removed.", "success")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/data")
@login_required
def watch_data(watch_id):
    """Return latest 20 rows from the watched table as JSON."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT w.*, c.host, c.port, c.dbname, c.username, c.password
            FROM dbmon_watches w
            JOIN dbmon_connections c ON c.id = w.conn_id
            WHERE w.id=%s
        """, (watch_id,))
        watch = cur.fetchone()

    if not watch:
        return jsonify({"error": "Not found"}), 404

    if watch["paused"]:
        return jsonify({"paused": True, "rows": [], "columns": []})

    try:
        c = _ext_conn(watch)
        cur2 = c.cursor()
        schema = watch["schema_name"]
        table  = watch["table_name"]

        # Get column names
        cur2.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema=%s AND table_name=%s
            ORDER BY ordinal_position
        """, (schema, table))
        columns = [r["column_name"] for r in cur2.fetchall()]

        if not columns:
            c.close()
            return jsonify({"error": f"Table {schema}.{table} not found or no columns"})

        # Detect time column for ordering
        time_col = None
        for candidate in ["observation_time", "Observation_Time", "created_at", "ts", "timestamp", "time"]:
            if candidate in columns or candidate.lower() in [col.lower() for col in columns]:
                time_col = next((col for col in columns if col.lower() == candidate.lower()), None)
                break

        order_clause = f'ORDER BY "{time_col}" DESC' if time_col else f'ORDER BY "{columns[0]}" DESC'
        cur2.execute(f'SELECT * FROM "{schema}"."{table}" {order_clause} LIMIT 20')
        rows = cur2.fetchall()
        c.close()

        # Count rows in last 1 minute
        count_recent = 0
        if time_col:
            c2 = _ext_conn(watch)
            cur3 = c2.cursor()
            cur3.execute(f"""
                SELECT COUNT(*) as cnt FROM "{schema}"."{table}"
                WHERE "{time_col}" > NOW() - INTERVAL '1 minute'
            """)
            count_recent = cur3.fetchone()["cnt"]
            c2.close()

        return jsonify({
            "paused": False,
            "columns": columns,
            "rows": [dict(r) for r in rows],
            "count_recent": count_recent,
            "time_col": time_col
        })
    except Exception as e:
        return jsonify({"error": str(e)})
