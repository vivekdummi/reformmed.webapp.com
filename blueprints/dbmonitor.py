"""
DB Monitor blueprint — watches external PostgreSQL tables for live data.
Shows LIVE / DEAD status per table (dead = no new rows in 5 min).
Sends alert email when data stops, repeats every 1 hour until data resumes.
Per-table controls: monitoring on/off, alerts on/off.

Per-location breakdown: many watched tables mix rows from several physical
locations (e.g. bodycraft_hospital_data has Vatika, JP Nagar, Sadashiva
Nagar, ...). A table can look LIVE overall while one location's cameras are
silently disconnected, because other locations keep rows flowing into the
same table. Expanding a watch row auto-discovers distinct "Location" values
and tracks live/dead + alert state for each one independently
(dbmon_watch_locations table).
"""
import smtplib
import os
from email.mime.text import MIMEText
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from db import get_db, list_alert_recipients
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
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS group_name TEXT",
        ]:
            try:
                cur.execute(col_sql)
            except Exception:
                pass

        # ── Per-location breakdown within a watched table ───────────────────
        # A single watch (e.g. bodycraft.bodycraft_hospital_data) mixes rows
        # from many physical locations. This table tracks live/dead + alert
        # state PER location value so one dead branch doesn't hide behind
        # other branches that are still pushing data into the same table.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dbmon_watch_locations (
                id               SERIAL PRIMARY KEY,
                watch_id         INTEGER NOT NULL REFERENCES dbmon_watches(id) ON DELETE CASCADE,
                location_value   TEXT NOT NULL,
                monitoring       BOOLEAN NOT NULL DEFAULT TRUE,
                alerts_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
                alert_emails     TEXT NOT NULL DEFAULT '',
                last_seen        TIMESTAMPTZ,
                last_alert_sent  TIMESTAMPTZ,
                was_dead         BOOLEAN NOT NULL DEFAULT FALSE,
                created_at       TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(watch_id, location_value)
            )
        """)

        # ── Per-area breakdown, nested one level under location ─────────────
        # Same idea one level finer: within one location, one camera/area
        # (e.g. "Sadashiva Nagar FF Reception") can go dead while siblings
        # under the same location keep pushing rows.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dbmon_watch_areas (
                id               SERIAL PRIMARY KEY,
                watch_id         INTEGER NOT NULL REFERENCES dbmon_watches(id) ON DELETE CASCADE,
                location_value   TEXT NOT NULL,
                area_value       TEXT NOT NULL,
                monitoring       BOOLEAN NOT NULL DEFAULT TRUE,
                alerts_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
                alert_emails     TEXT NOT NULL DEFAULT '',
                last_seen        TIMESTAMPTZ,
                last_alert_sent  TIMESTAMPTZ,
                was_dead         BOOLEAN NOT NULL DEFAULT FALSE,
                created_at       TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(watch_id, location_value, area_value)
            )
        """)


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


def _detect_location_col(cur, schema, table):
    """
    Find the column that holds the branch/location value, e.g. "Location".
    Case-insensitive; tries an exact-name match first, then a substring match.
    Returns column_name or None.
    """
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s
        ORDER BY ordinal_position
    """, (schema, table))
    cols = [r["column_name"] for r in cur.fetchall()]
    lower_map = {c.lower(): c for c in cols}

    for exact in ("location", "site", "branch", "hospital", "clinic"):
        if exact in lower_map:
            return lower_map[exact]
    for c in cols:
        if "location" in c.lower():
            return c
    return None


def _detect_area_col(cur, schema, table):
    """Find an optional secondary grouping column (e.g. "Area") for display only."""
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s
        ORDER BY ordinal_position
    """, (schema, table))
    cols = [r["column_name"] for r in cur.fetchall()]
    lower_map = {c.lower(): c for c in cols}
    for exact in ("area", "room", "zone"):
        if exact in lower_map:
            return lower_map[exact]
    return None


def _send_alert(watch_row, subject, body, machine_key=None, alert_emails=None):
    """Send alert email and log to unified alert_log.

    machine_key / alert_emails let callers override the defaults derived from
    watch_row — used for per-location alerts (e.g. "bodycraft.bodycraft_hospital_data:Bodycraft Sadashiva Nagar").
    """
    emails_src = alert_emails if alert_emails is not None else watch_row.get("alert_emails")
    emails = [e.strip() for e in (emails_src or "").split(",") if e.strip()]
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
    if machine_key is None:
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

    # Group watches sharing the same group_name (e.g. one hospital with
    # several tables) under a single card. Ungrouped watches (group_name
    # is NULL/empty) each become their own singleton group, so the template
    # can treat every entry uniformly.
    groups = []
    group_lookup = {}
    for w in watches:
        key = w.get("group_name") or None
        if key:
            if key not in group_lookup:
                group_lookup[key] = {"name": key, "watches": [], "idx": len(groups)}
                groups.append(group_lookup[key])
            group_lookup[key]["watches"].append(w)
        else:
            groups.append({"name": None, "watches": [w], "idx": len(groups)})

    # {group_idx: [watch_id, ...]} for named groups only — lets the frontend
    # roll up each child watch's live/dead status into one group-level pill.
    group_watch_ids = {g["idx"]: [w["id"] for w in g["watches"]] for g in groups if g["name"]}

    existing_group_names = sorted({g["name"] for g in groups if g["name"]})

    return render_template(
        "dbmonitor.html", connections=connections, watches=watches,
        groups=groups, group_watch_ids=group_watch_ids,
        existing_group_names=existing_group_names,
        recipients=list_alert_recipients(),
    )


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
    group_name   = _resolve_group_name(request.form)
    alert_emails = ", ".join(request.form.getlist("recipient_emails"))
    if not all([conn_id, schema_name, table_name]):
        flash("Connection, schema and table are required.", "danger")
        return redirect(url_for("dbmonitor.index"))
    try:
        with get_db() as conn:
            conn.cursor().execute("""
                INSERT INTO dbmon_watches (conn_id, schema_name, table_name, display_name, group_name, alert_emails)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (conn_id, schema_name, table_name,
                  display_name or f"{schema_name}.{table_name}",
                  group_name or None, alert_emails))
        flash(f"Now watching {schema_name}.{table_name}.", "success")
    except Exception as e:
        if "unique" in str(e).lower():
            flash("Already watching this table.", "warning")
        else:
            flash(f"Error: {e}", "danger")
    return redirect(url_for("dbmonitor.index"))


def _resolve_group_name(form):
    """
    The group picker is a <select> of existing hospital names plus a
    "+ New group..." option that reveals a text input. Whichever one the
    user actually used wins: a typed new name always takes priority over
    the dropdown value (which would just be the sentinel "__new__").
    """
    new_name = (form.get("new_group_name") or "").strip()
    if new_name:
        return new_name
    picked = (form.get("group_name") or "").strip()
    if picked == "__new__":
        return ""
    return picked


@dbmonitor_bp.route("/watch/<int:watch_id>/update-group", methods=["POST"])
@login_required
def update_group(watch_id):
    """
    Assign/rename/clear the hospital group a watch belongs to. Any watches
    sharing the same (case-sensitive) group_name get rendered together under
    one collapsible card instead of as separate top-level cards — useful when
    one hospital has multiple tables (e.g. camera events + a separate billing
    table).
    """
    _admin_required()
    src = request.get_json(silent=True) or request.form
    group_name = _resolve_group_name(src)
    with get_db() as conn:
        conn.cursor().execute(
            "UPDATE dbmon_watches SET group_name=%s WHERE id=%s",
            (group_name or None, watch_id)
        )
    if request.is_json:
        return jsonify({"ok": True})
    flash("Group updated.", "success")
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
    emails = ", ".join(request.form.getlist("recipient_emails"))
    with get_db() as conn:
        conn.cursor().execute("UPDATE dbmon_watches SET alert_emails=%s WHERE id=%s",
                              (emails, watch_id))
    flash("Alert recipients updated.", "success")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/location/<int:loc_id>/toggle-monitoring", methods=["POST"])
@login_required
def toggle_location_monitoring(watch_id, loc_id):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT monitoring FROM dbmon_watch_locations WHERE id=%s AND watch_id=%s",
            (loc_id, watch_id)
        )
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE dbmon_watch_locations SET monitoring=%s WHERE id=%s",
                (not row["monitoring"], loc_id)
            )
    return jsonify({"ok": bool(row)})


@dbmonitor_bp.route("/watch/<int:watch_id>/location/<int:loc_id>/toggle-alerts", methods=["POST"])
@login_required
def toggle_location_alerts(watch_id, loc_id):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT alerts_enabled FROM dbmon_watch_locations WHERE id=%s AND watch_id=%s",
            (loc_id, watch_id)
        )
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE dbmon_watch_locations SET alerts_enabled=%s WHERE id=%s",
                (not row["alerts_enabled"], loc_id)
            )
    return jsonify({"ok": bool(row)})


@dbmonitor_bp.route("/watch/<int:watch_id>/location/<int:loc_id>/update-emails", methods=["POST"])
@login_required
def update_location_emails(watch_id, loc_id):
    _admin_required()
    emails = (request.get_json(silent=True) or {}).get("alert_emails", "").strip()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE dbmon_watch_locations SET alert_emails=%s WHERE id=%s AND watch_id=%s",
            (emails, loc_id, watch_id)
        )
    return jsonify({"ok": True})


@dbmonitor_bp.route("/watch/<int:watch_id>/area/<int:area_id>/toggle-monitoring", methods=["POST"])
@login_required
def toggle_area_monitoring(watch_id, area_id):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT monitoring FROM dbmon_watch_areas WHERE id=%s AND watch_id=%s",
            (area_id, watch_id)
        )
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE dbmon_watch_areas SET monitoring=%s WHERE id=%s",
                (not row["monitoring"], area_id)
            )
    return jsonify({"ok": bool(row)})


@dbmonitor_bp.route("/watch/<int:watch_id>/area/<int:area_id>/toggle-alerts", methods=["POST"])
@login_required
def toggle_area_alerts(watch_id, area_id):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT alerts_enabled FROM dbmon_watch_areas WHERE id=%s AND watch_id=%s",
            (area_id, watch_id)
        )
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE dbmon_watch_areas SET alerts_enabled=%s WHERE id=%s",
                (not row["alerts_enabled"], area_id)
            )
    return jsonify({"ok": bool(row)})


@dbmonitor_bp.route("/watch/<int:watch_id>/area/<int:area_id>/update-emails", methods=["POST"])
@login_required
def update_area_emails(watch_id, area_id):
    _admin_required()
    emails = (request.get_json(silent=True) or {}).get("alert_emails", "").strip()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE dbmon_watch_areas SET alert_emails=%s WHERE id=%s AND watch_id=%s",
            (emails, area_id, watch_id)
        )
    return jsonify({"ok": True})


def _location_breakdown(cur2, schema, table, time_col):
    """
    Group the external table by Location (and Area, if present), bounded to
    the last 24h for performance — a full-table GROUP BY on a multi-million
    row table would be far too slow to run on every 10s poll.
    Returns (location_col_name, area_col_name, rows) where each row has
    loc / area / last_t / recent_cnt. Locations/areas with zero rows in the
    last 24h simply won't appear here — the caller falls back to cached
    last_seen for those.
    """
    loc_col = _detect_location_col(cur2, schema, table)
    if not loc_col or not time_col:
        return loc_col, None, []

    area_col = _detect_area_col(cur2, schema, table)
    area_select = f', "{area_col}" AS area' if area_col else ", NULL AS area"
    group_cols  = f'"{loc_col}", "{area_col}"' if area_col else f'"{loc_col}"'

    cur2.execute(f"""
        SELECT "{loc_col}" AS loc
               {area_select},
               MAX("{time_col}") AS last_t,
               COUNT(*) FILTER (
                   WHERE "{time_col}" > NOW() - INTERVAL '{DEAD_THRESHOLD_MINUTES} minutes'
               ) AS recent_cnt
        FROM "{schema}"."{table}"
        WHERE "{time_col}" > NOW() - INTERVAL '1 day'
        GROUP BY {group_cols}
    """)
    return loc_col, area_col, cur2.fetchall()


def _sync_and_check_locations(watch, watch_id, schema, table, area_col, raw_rows):
    """
    Upsert newly-seen locations AND areas, load per-item toggle state, run
    the same dead/alert logic as the table-level check but scoped to each
    location and each area within it, and return the nested list to embed
    in the /status JSON response. All bookkeeping happens on ONE connection
    to avoid opening a new connection per row on every poll.
    """
    now = datetime.now(timezone.utc)

    # ── Roll raw (loc, area) rows up into a per-location structure ──────────
    locs = {}  # loc_value -> {"last_t":..., "recent_cnt": int, "areas": {area_value: {last_t, recent_cnt}}}
    for r in raw_rows:
        lv = r["loc"] if r["loc"] is not None else "(blank)"
        av = (r["area"] if r["area"] is not None else "(blank)") if area_col else None
        recent = r["recent_cnt"] or 0
        last_t = r["last_t"]

        loc_entry = locs.setdefault(lv, {"last_t": None, "recent_cnt": 0, "areas": {}})
        loc_entry["recent_cnt"] += recent
        if last_t and (loc_entry["last_t"] is None or last_t > loc_entry["last_t"]):
            loc_entry["last_t"] = last_t

        if area_col:
            loc_entry["areas"][av] = {"last_t": last_t, "recent_cnt": recent}

    out = []
    with get_db() as conn:
        cur = conn.cursor()

        # Discover new locations
        for lv in locs:
            cur.execute("""
                INSERT INTO dbmon_watch_locations (watch_id, location_value)
                VALUES (%s, %s)
                ON CONFLICT (watch_id, location_value) DO NOTHING
            """, (watch_id, lv))

        # Discover new areas
        if area_col:
            for lv, ld in locs.items():
                for av in ld["areas"]:
                    cur.execute("""
                        INSERT INTO dbmon_watch_areas (watch_id, location_value, area_value)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (watch_id, location_value, area_value) DO NOTHING
                    """, (watch_id, lv, av))

        cur.execute(
            "SELECT * FROM dbmon_watch_locations WHERE watch_id=%s ORDER BY location_value",
            (watch_id,)
        )
        tracked_locs = cur.fetchall()

        tracked_areas_by_loc = {}
        if area_col:
            cur.execute(
                "SELECT * FROM dbmon_watch_areas WHERE watch_id=%s ORDER BY location_value, area_value",
                (watch_id,)
            )
            for a in cur.fetchall():
                tracked_areas_by_loc.setdefault(a["location_value"], []).append(a)

        for loc in tracked_locs:
            lv = loc["location_value"]
            ld = locs.get(lv)
            recent_cnt = ld["recent_cnt"] if ld else 0
            last_t     = ld["last_t"] if ld else loc["last_seen"]
            loc_is_dead = (recent_cnt == 0)

            if last_t and last_t != loc["last_seen"]:
                cur.execute(
                    "UPDATE dbmon_watch_locations SET last_seen=%s WHERE id=%s",
                    (last_t, loc["id"])
                )

            # ── Areas nested under this location ──
            areas_out = []
            for a in tracked_areas_by_loc.get(lv, []):
                av = a["area_value"]
                ad = ld["areas"].get(av) if ld else None
                a_recent = (ad["recent_cnt"] or 0) if ad else 0
                a_last_t = ad["last_t"] if ad else a["last_seen"]
                a_is_dead = (a_recent == 0)

                if a_last_t and a_last_t != a["last_seen"]:
                    cur.execute(
                        "UPDATE dbmon_watch_areas SET last_seen=%s WHERE id=%s",
                        (a_last_t, a["id"])
                    )

                area_entry = {
                    "id":             a["id"],
                    "area":           av,
                    "monitoring":     a["monitoring"],
                    "alerts_enabled": a["alerts_enabled"],
                    "alert_emails":   a["alert_emails"],
                    "is_dead":        a_is_dead if a["monitoring"] else None,
                    "last_seen":      a_last_t.isoformat() if a_last_t else None,
                    "recent_rows":    a_recent,
                }

                # Per-area alerting — only if both the area AND its parent location are being monitored
                if loc["monitoring"] and a["monitoring"] and a["alerts_enabled"]:
                    emails_for_area = a["alert_emails"] or loc["alert_emails"] or watch.get("alert_emails")
                    if emails_for_area:
                        last_sent = a["last_alert_sent"]
                        was_dead  = a["was_dead"]
                        machine_key = f"{schema}.{table}:{lv}:{av}"
                        label = watch["display_name"] or f"{schema}.{table}"

                        if a_is_dead:
                            should_send = (last_sent is None) or \
                                          ((now - last_sent).total_seconds() >= ALERT_REPEAT_HOURS * 3600)
                            if should_send:
                                _send_alert(
                                    watch,
                                    subject=f"[REFORMMED] ⚠ Data stopped: {lv} / {av} ({label})",
                                    body=(
                                        f"Table: {schema}.{table}\n"
                                        f"Location: {lv}\n"
                                        f"Area: {av}\n"
                                        f"Status: No new rows for this area in the last "
                                        f"{DEAD_THRESHOLD_MINUTES} minutes (other areas/locations in "
                                        f"this table may still be live).\n"
                                        f"Last data received: {area_entry['last_seen'] or 'unknown'}\n\n"
                                        f"This alert repeats every {ALERT_REPEAT_HOURS} hour(s) until data resumes."
                                    ),
                                    machine_key=machine_key,
                                    alert_emails=emails_for_area,
                                )
                                cur.execute(
                                    "UPDATE dbmon_watch_areas SET last_alert_sent=%s, was_dead=TRUE WHERE id=%s",
                                    (now, a["id"])
                                )
                        elif was_dead:
                            _send_alert(
                                watch,
                                subject=f"[REFORMMED] ✅ Data resumed: {lv} / {av} ({label})",
                                body=(
                                    f"Table: {schema}.{table}\n"
                                    f"Location: {lv}\n"
                                    f"Area: {av}\n"
                                    f"Status: Data is flowing again for this area.\n"
                                    f"Last row time: {area_entry['last_seen'] or 'unknown'}\n"
                                ),
                                machine_key=machine_key,
                                alert_emails=emails_for_area,
                            )
                            cur.execute(
                                "UPDATE dbmon_watch_areas SET was_dead=FALSE, last_alert_sent=NULL WHERE id=%s",
                                (a["id"],)
                            )

                areas_out.append(area_entry)

            entry = {
                "id":             loc["id"],
                "location":       lv,
                "monitoring":     loc["monitoring"],
                "alerts_enabled": loc["alerts_enabled"],
                "alert_emails":   loc["alert_emails"],
                "is_dead":        loc_is_dead if loc["monitoring"] else None,
                "last_seen":      last_t.isoformat() if last_t else None,
                "recent_rows":    recent_cnt,
                "area_count":     len(areas_out) if area_col else None,
                "areas":          areas_out,
            }

            # Per-location alerting — same cooldown/recovery pattern as the table-level alert
            if loc["monitoring"] and loc["alerts_enabled"]:
                emails_for_loc = loc["alert_emails"] or watch.get("alert_emails")
                if emails_for_loc:
                    last_sent = loc["last_alert_sent"]
                    was_dead  = loc["was_dead"]
                    machine_key = f"{schema}.{table}:{lv}"
                    label = watch["display_name"] or f"{schema}.{table}"

                    if loc_is_dead:
                        should_send = (last_sent is None) or \
                                      ((now - last_sent).total_seconds() >= ALERT_REPEAT_HOURS * 3600)
                        if should_send:
                            _send_alert(
                                watch,
                                subject=f"[REFORMMED] ⚠ Data stopped: {lv} ({label})",
                                body=(
                                    f"Table: {schema}.{table}\n"
                                    f"Location: {lv}\n"
                                    f"Status: No new rows for this location in the last "
                                    f"{DEAD_THRESHOLD_MINUTES} minutes (other locations in this "
                                    f"table may still be live).\n"
                                    f"Last data received: {entry['last_seen'] or 'unknown'}\n\n"
                                    f"This alert repeats every {ALERT_REPEAT_HOURS} hour(s) until data resumes."
                                ),
                                machine_key=machine_key,
                                alert_emails=emails_for_loc,
                            )
                            cur.execute(
                                "UPDATE dbmon_watch_locations SET last_alert_sent=%s, was_dead=TRUE WHERE id=%s",
                                (now, loc["id"])
                            )
                    elif was_dead:
                        _send_alert(
                            watch,
                            subject=f"[REFORMMED] ✅ Data resumed: {lv} ({label})",
                            body=(
                                f"Table: {schema}.{table}\n"
                                f"Location: {lv}\n"
                                f"Status: Data is flowing again for this location.\n"
                                f"Last row time: {entry['last_seen'] or 'unknown'}\n"
                            ),
                            machine_key=machine_key,
                            alert_emails=emails_for_loc,
                        )
                        cur.execute(
                            "UPDATE dbmon_watch_locations SET was_dead=FALSE, last_alert_sent=NULL WHERE id=%s",
                            (loc["id"],)
                        )

            out.append(entry)

    return out


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

        # ── Per-location breakdown (Location column within this same table) ──
        loc_col = area_col = None
        loc_rows = []
        if time_col:
            loc_col, area_col, loc_rows = _location_breakdown(cur2, schema, table, time_col)

        c.close()

        locations_out = []
        if loc_col:
            locations_out = _sync_and_check_locations(watch, watch_id, schema, table, area_col, loc_rows)

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
            "location_col":    loc_col,
            "area_col":        area_col,
            "locations":       locations_out,
        })

    except Exception as e:
        return jsonify({"error": str(e)})