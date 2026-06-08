"""
DB Monitor blueprint — watches external PostgreSQL tables for live data.
Shows LIVE / DEAD status per table (dead = no new rows in 5 min).
Sends alert email when data stops, repeats every 1 hour until data resumes.
Per-table controls: monitoring on/off, alerts on/off.
"""
import smtplib
import os
from email.mime.text import MIMEText
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from db import get_db
import psycopg2
import psycopg2.extras

dbmonitor_bp = Blueprint("dbmonitor", __name__, url_prefix="/dbmonitor")

DEAD_THRESHOLD_MINUTES = 5   # no rows in this window = DEAD
ALERT_REPEAT_HOURS     = 1   # re-send alert every N hours while still dead


def _admin_required():
    if not current_user.is_admin:
        abort(403)


def init_dbmonitor_tables():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dbmon_connections (
                id         SERIAL PRIMARY KEY,
                name       TEXT UNIQUE NOT NULL,
                host       TEXT NOT NULL,
                port       INTEGER NOT NULL DEFAULT 5432,
                dbname     TEXT NOT NULL,
                username   TEXT NOT NULL,
                password   TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dbmon_watches (
                id               SERIAL PRIMARY KEY,
                conn_id          INTEGER REFERENCES dbmon_connections(id) ON DELETE CASCADE,
                schema_name      TEXT NOT NULL,
                table_name       TEXT NOT NULL,
                display_name     TEXT,
                -- monitoring toggle (pause polling entirely)
                monitoring       BOOLEAN NOT NULL DEFAULT TRUE,
                -- alert toggle (send email or not)
                alerts_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
                -- alert recipients (comma-separated emails)
                alert_emails     TEXT NOT NULL DEFAULT '',
                -- tracks when we last sent an alert (for 1-hr repeat)
                last_alert_sent  TIMESTAMPTZ,
                -- tracks if we already sent a "resumed" recovery email
                was_dead         BOOLEAN NOT NULL DEFAULT FALSE,
                created_at       TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(conn_id, schema_name, table_name)
            )
        """)
        # Add new columns to existing installs (safe if already exist)
        for col_sql in [
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS monitoring BOOLEAN NOT NULL DEFAULT TRUE",
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE",
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS alert_emails TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS last_alert_sent TIMESTAMPTZ",
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS was_dead BOOLEAN NOT NULL DEFAULT FALSE",
        ]:
            try:
                cur.execute(col_sql)
            except Exception:
                pass


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ext_conn(row):
    return psycopg2.connect(
        host=row["host"], port=row["port"], dbname=row["dbname"],
        user=row["username"], password=row["password"],
        connect_timeout=5,
        cursor_factory=psycopg2.extras.RealDictCursor
    )


def _detect_time_col_by_type(cur, schema, table):
    """
    Query information_schema for actual timestamp/timestamptz/date columns.
    Priority: preferred names first, then any timestamp col, then any date col.
    Returns (column_name, data_type) or (None, None).
    """
    cur.execute("""
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = %s
          AND table_name   = %s
          AND data_type IN (
              'timestamp with time zone',
              'timestamp without time zone',
              'date',
              'time with time zone',
              'time without time zone'
          )
        ORDER BY ordinal_position
    """, (schema, table))
    rows = cur.fetchall()
    if not rows:
        return None, None

    # Preferred name order — case-insensitive
    preferred = [
        "observation_time", "created_at", "inserted_at", "recorded_at",
        "ts", "timestamp", "time", "updated_at", "date", "event_time",
        "log_time", "report_time"
    ]
    col_map = {r["column_name"].lower(): r for r in rows}
    for p in preferred:
        if p in col_map:
            r = col_map[p]
            return r["column_name"], r["data_type"]

    # Fall back to first timestamp col, then first date col
    for dtype in ("timestamp with time zone", "timestamp without time zone",
                  "date", "time with time zone", "time without time zone"):
        match = next((r for r in rows if r["data_type"] == dtype), None)
        if match:
            return match["column_name"], match["data_type"]

    return None, None


def _send_alert(watch_row, subject, body):
    """Send alert email and log to unified alert_log."""
    emails = [e.strip() for e in (watch_row.get("alert_emails") or "").split(",") if e.strip()]
    ok = False
    if emails:
        smtp_host = os.getenv("SMTP_HOST", "")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_pass = os.getenv("SMTP_PASS", "")
        from_addr = os.getenv("ALERT_FROM", smtp_user)
        if smtp_host:
            try:
                msg = MIMEText(body, "plain")
                msg["Subject"] = subject
                msg["From"]    = from_addr
                msg["To"]      = ", ".join(emails)
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                    s.starttls()
                    if smtp_user:
                        s.login(smtp_user, smtp_pass)
                    s.sendmail(from_addr, emails, msg.as_string())
                ok = True
            except Exception as e:
                print(f"[dbmonitor] alert email failed: {e}")
    # Log to unified alert_log
    machine_key = f"{watch_row.get('schema_name','')}.{watch_row.get('table_name','')}"
    try:
        with get_db() as conn:
            conn.cursor().execute("""
                INSERT INTO alert_log (alert_type, source, machine_key, subject, body, success)
                VALUES ('db_dead', 'dbmonitor', %s, %s, %s, %s)
            """, (machine_key, subject, body, ok))
    except Exception as e:
        print(f"[dbmonitor] alert_log write failed: {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

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
                INSERT INTO dbmon_connections (name,host,port,dbname,username,password)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (name, host, int(port), dbname, username, password))
        flash(f"Connection '{name}' added.", "success")
    except Exception as e:
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
    alert_emails = request.form.get("alert_emails", "").strip()
    if not all([conn_id, schema_name, table_name]):
        flash("Connection, schema and table are required.", "danger")
        return redirect(url_for("dbmonitor.index"))
    try:
        with get_db() as conn:
            conn.cursor().execute("""
                INSERT INTO dbmon_watches (conn_id, schema_name, table_name, display_name, alert_emails)
                VALUES (%s,%s,%s,%s,%s)
            """, (conn_id, schema_name, table_name,
                  display_name or f"{schema_name}.{table_name}", alert_emails))
        flash(f"Now watching {schema_name}.{table_name}.", "success")
    except Exception as e:
        if "unique" in str(e).lower():
            flash("Already watching this table.", "warning")
        else:
            flash(f"Error: {e}", "danger")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/delete", methods=["POST"])
@login_required
def delete_watch(watch_id):
    _admin_required()
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM dbmon_watches WHERE id=%s", (watch_id,))
    flash("Watch removed.", "success")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/toggle-monitoring", methods=["POST"])
@login_required
def toggle_monitoring(watch_id):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT monitoring FROM dbmon_watches WHERE id=%s", (watch_id,))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE dbmon_watches SET monitoring=%s WHERE id=%s",
                        (not row["monitoring"], watch_id))
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/toggle-alerts", methods=["POST"])
@login_required
def toggle_alerts(watch_id):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT alerts_enabled FROM dbmon_watches WHERE id=%s", (watch_id,))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE dbmon_watches SET alerts_enabled=%s WHERE id=%s",
                        (not row["alerts_enabled"], watch_id))
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/update-emails", methods=["POST"])
@login_required
def update_emails(watch_id):
    _admin_required()
    emails = request.form.get("alert_emails", "").strip()
    with get_db() as conn:
        conn.cursor().execute("UPDATE dbmon_watches SET alert_emails=%s WHERE id=%s",
                              (emails, watch_id))
    flash("Alert emails updated.", "success")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/status")
@login_required
def watch_status(watch_id):
    """
    Returns JSON with live/dead status + stats for one watched table.
    Also handles alert email logic (fire once, repeat every 1hr while dead).
    """
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT w.*, c.host, c.port, c.dbname, c.username, c.password, c.name as conn_name
            FROM dbmon_watches w
            JOIN dbmon_connections c ON c.id = w.conn_id
            WHERE w.id=%s
        """, (watch_id,))
        watch = cur.fetchone()

    if not watch:
        return jsonify({"error": "Not found"}), 404

    if not watch["monitoring"]:
        return jsonify({"monitoring": False})

    try:
        c = _ext_conn(watch)
        cur2 = c.cursor()
        schema = watch["schema_name"]
        table  = watch["table_name"]

        # Detect timestamp column by querying information_schema data types
        # This handles mixed-case names like "Observation_Time" correctly
        time_col, _ = _detect_time_col_by_type(cur2, schema, table)

        if not time_col:
            # Verify table exists at all
            cur2.execute("""
                SELECT COUNT(*) as cnt FROM information_schema.columns
                WHERE table_schema=%s AND table_name=%s
            """, (schema, table))
            if cur2.fetchone()["cnt"] == 0:
                c.close()
                return jsonify({"error": f"Table {schema}.{table} not found"})

        # Fast estimated total row count via pg_class (avoids COUNT(*) on millions of rows)
        cur2.execute("""
            SELECT reltuples::BIGINT as est
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND c.relname = %s
        """, (schema, table))
        est_row = cur2.fetchone()
        total_rows = int(est_row["est"]) if est_row and est_row["est"] >= 0 else None

        # Last row time + rows in last 5 min + rows in last 1 min
        last_row_time  = None
        rows_last_5min = 0
        rows_last_1min = 0

        if time_col:
            # Use MAX on the time column — fast with an index, OK without
            cur2.execute(
                f'SELECT MAX("{time_col}") as last_t FROM "{schema}"."{table}"'
            )
            r = cur2.fetchone()
            if r and r["last_t"]:
                last_row_time = r["last_t"].isoformat()

            # Count rows in last 5 minutes (dead threshold)
            cur2.execute(
                f'SELECT COUNT(*) as cnt FROM "{schema}"."{table}" '
                f'WHERE "{time_col}" > NOW() - INTERVAL \'{DEAD_THRESHOLD_MINUTES} minutes\''
            )
            rows_last_5min = cur2.fetchone()["cnt"]

            # Count rows in last 1 minute (rows/min rate)
            cur2.execute(
                f'SELECT COUNT(*) as cnt FROM "{schema}"."{table}" '
                f'WHERE "{time_col}" > NOW() - INTERVAL \'1 minute\''
            )
            rows_last_1min = cur2.fetchone()["cnt"]

        c.close()

        # Determine live/dead
        is_dead = (rows_last_5min == 0)

        # ── Alert logic ──────────────────────────────────────────────────────
        now = datetime.now(timezone.utc)
        if watch["alerts_enabled"] and watch.get("alert_emails"):
            last_sent = watch["last_alert_sent"]
            was_dead  = watch["was_dead"]

            if is_dead:
                # Send if never sent, or last sent > 1 hour ago
                should_send = (last_sent is None) or \
                              ((now - last_sent).total_seconds() >= ALERT_REPEAT_HOURS * 3600)
                if should_send:
                    stopped_info = f"Last data received: {last_row_time or 'unknown'}"
                    _send_alert(
                        watch,
                        subject=f"[REFORMMED] ⚠ Data stopped: {watch['display_name'] or schema+'.'+table}",
                        body=(
                            f"Table: {schema}.{table}\n"
                            f"Connection: {watch['conn_name'] if 'conn_name' in watch else ''}\n"
                            f"Status: No new rows in the last {DEAD_THRESHOLD_MINUTES} minutes.\n"
                            f"{stopped_info}\n"
                            f"Total rows: {total_rows}\n\n"
                            f"This alert repeats every {ALERT_REPEAT_HOURS} hour(s) until data resumes."
                        )
                    )
                    with get_db() as conn:
                        conn.cursor().execute(
                            "UPDATE dbmon_watches SET last_alert_sent=%s, was_dead=TRUE WHERE id=%s",
                            (now, watch_id)
                        )
            else:
                # Data is live — send recovery email if it was previously dead
                if was_dead:
                    _send_alert(
                        watch,
                        subject=f"[REFORMMED] ✅ Data resumed: {watch['display_name'] or schema+'.'+table}",
                        body=(
                            f"Table: {schema}.{table}\n"
                            f"Status: Data is flowing again.\n"
                            f"Last row time: {last_row_time or 'unknown'}\n"
                            f"Total rows: {total_rows}\n"
                        )
                    )
                    with get_db() as conn:
                        conn.cursor().execute(
                            "UPDATE dbmon_watches SET was_dead=FALSE, last_alert_sent=NULL WHERE id=%s",
                            (watch_id,)
                        )

        return jsonify({
            "monitoring":      True,
            "is_dead":         is_dead,
            "total_rows":      total_rows,
            "last_row_time":   last_row_time,
            "rows_last_5min":  rows_last_5min,
            "rows_last_1min":  rows_last_1min,
            "time_col":        time_col,
        })

    except Exception as e:
        return jsonify({"error": str(e)})