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
import ssl
import os
import threading
import time
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from alert_sender import clean_header
from db import get_db, list_alert_recipients, _get_fernet
import psycopg2
import psycopg2.extras

dbmonitor_bp = Blueprint("dbmonitor", __name__, url_prefix="/dbmonitor")


@dbmonitor_bp.before_request
def _require_dbmon_feature():
    """can_view_dbmon used to only hide the nav link — enforce it on the routes too."""
    if current_user.is_authenticated and not (current_user.is_admin or current_user.can_view_dbmon):
        abort(403)

DEAD_THRESHOLD_MINUTES = 5   # no rows in this window = DEAD
ALERT_REPEAT_HOURS     = 1   # re-send alert every N hours while still dead


def _qi(name):
    """Quote a SQL identifier (schema/table/column names entered by an admin or
    read from the external DB's catalog). Embedded double quotes are doubled,
    so a name like  x"; DROP TABLE y; --  can't break out of the quoting."""
    return '"' + str(name).replace('"', '""') + '"'


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
            # Result of the last background check (offline_checker.py) — the
            # /status endpoint serves this instead of querying the external DB.
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS last_check JSONB",
            "ALTER TABLE dbmon_watches ADD COLUMN IF NOT EXISTS last_checked_at TIMESTAMPTZ",
        ]:
            # A failed statement aborts the whole transaction, so isolate each
            # ALTER in a savepoint — a plain `except: pass` would leave the
            # connection unusable for the CREATE TABLEs below.
            cur.execute("SAVEPOINT dbmon_alter")
            try:
                cur.execute(col_sql)
                cur.execute("RELEASE SAVEPOINT dbmon_alter")
            except Exception:
                cur.execute("ROLLBACK TO SAVEPOINT dbmon_alter")

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
        cur.execute("ALTER TABLE dbmon_watch_locations ADD COLUMN IF NOT EXISTS recent_rows INTEGER")
        cur.execute("ALTER TABLE dbmon_watch_areas ADD COLUMN IF NOT EXISTS recent_rows INTEGER")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ext_conn(row):
    return psycopg2.connect(
        host=row["host"], port=row["port"], dbname=row["dbname"],
        user=row["username"], password=row["password"],
        connect_timeout=5,
        # Bound every query on the external DB — /status is polled every
        # 10s by every viewer and runs aggregates on possibly huge tables.
        options="-c statement_timeout=15000",
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


_ALERT_SETTING_DEFAULTS = {
    "alerts_master_enabled": "1",
    "smtp_host":             "smtp.gmail.com",
    "smtp_port":             "465",
    "smtp_username":         "",
    "smtp_password":         "",
    "alert_from_email":      "",
}
_ENCRYPTED_ALERT_SETTINGS = ("smtp_username", "smtp_password")


def _load_alert_settings():
    """Read every setting _send_alert needs in ONE query on ONE pooled
    connection (instead of a get_db() per key). Mirrors db.get_setting /
    db.get_encrypted_setting semantics: missing key -> default; encrypted
    values that can't be decrypted (or no key configured) -> default."""
    keys = list(_ALERT_SETTING_DEFAULTS)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM app_settings WHERE key = ANY(%s)", (keys,))
        found = {r["key"]: r["value"] for r in cur.fetchall()}

    out = {}
    fernet = None
    for k in keys:
        default = _ALERT_SETTING_DEFAULTS[k]
        if k not in found:
            out[k] = default
            continue
        if k in _ENCRYPTED_ALERT_SETTINGS:
            if fernet is None:
                fernet = _get_fernet()
            if fernet is None:
                out[k] = default
                continue
            try:
                out[k] = fernet.decrypt(found[k].encode()).decode()
            except Exception as e:
                print(f"[dbmonitor] failed to decrypt setting '{k}': {e}")
                out[k] = default
        else:
            out[k] = found[k]
    return out


def _send_alert(watch_row, subject, body, machine_key=None, alert_emails=None, settings=None):
    """Send alert email and log to unified alert_log.

    machine_key / alert_emails let callers override the defaults derived from
    watch_row — used for per-location alerts (e.g. "bodycraft.bodycraft_hospital_data:Bodycraft Sadashiva Nagar").
    settings: pre-loaded _load_alert_settings() dict, so a batch of sends
    reads app_settings once. Must NOT be called while holding a get_db()
    connection (it does SMTP I/O and opens its own connection for the log).
    """
    if settings is None:
        settings = _load_alert_settings()
    if settings["alerts_master_enabled"] != "1":
        return  # app-wide kill-switch — Settings → General → Alerts Master Switch

    emails_src = alert_emails if alert_emails is not None else watch_row.get("alert_emails")
    emails = [e.strip() for e in (emails_src or "").split(",") if e.strip()]
    ok = False
    if emails:
        # SMTP config comes from Settings → Email/SMTP (DB-backed, password
        # encrypted) — falls back to GMAIL_USER/GMAIL_APP_PASS in .env for
        # anyone who hasn't set DB-based credentials yet.
        smtp_host = settings["smtp_host"]
        try:
            smtp_port = int(settings["smtp_port"])
        except (TypeError, ValueError):
            smtp_port = 465
        smtp_user = settings["smtp_username"] or os.getenv("GMAIL_USER", "")
        smtp_pass = settings["smtp_password"] or os.getenv("GMAIL_APP_PASS", "")
        from_addr = settings["alert_from_email"] or smtp_user

        if smtp_host and smtp_user and smtp_pass:
            try:
                msg = MIMEText(body, "plain")
                msg["Subject"] = clean_header(subject)
                msg["From"]    = from_addr
                msg["To"]      = ", ".join(emails)
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10, context=ctx) as s:
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(from_addr, emails, msg.as_string())
                ok = True
            except Exception as e:
                print(f"[dbmonitor] alert email failed: {e}")
        else:
            print("[dbmonitor] alert email skipped — SMTP not configured "
                  "(Settings → Email/SMTP, or GMAIL_USER/GMAIL_APP_PASS in .env)")
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


def _send_pending(watch_row, pending):
    """Send alerts that were already claimed (state committed) — called only
    after the claiming transaction's get_db() block has exited. A failed send
    does not release the claim: the previous code also marked the alert as
    sent regardless of the SMTP outcome, so there is no retry-on-failure
    behaviour to preserve."""
    if not pending:
        return
    try:
        settings = _load_alert_settings()
    except Exception as e:
        print(f"[dbmonitor] could not load alert settings: {e}")
        return
    for p in pending:
        try:
            _send_alert(watch_row, settings=settings, **p)
        except Exception as e:
            print(f"[dbmonitor] alert send failed: {e}")


# ── Column-detection cache ─────────────────────────────────────────────────────
# information_schema lookups on the external DB ran on every 10s poll from
# every viewer. Schema changes are rare, so cache per watch for a few minutes.
_COLS_CACHE_TTL = 300  # seconds
_cols_cache = {}       # watch_id -> (expires_at, signature, (time_col, loc_col, area_col))
_cols_cache_lock = threading.Lock()


def _cols_cache_get(watch_id, sig):
    with _cols_cache_lock:
        hit = _cols_cache.get(watch_id)
        if hit and hit[0] > time.monotonic() and hit[1] == sig:
            return hit[2]
        return None


def _cols_cache_put(watch_id, sig, cols):
    with _cols_cache_lock:
        _cols_cache[watch_id] = (time.monotonic() + _COLS_CACHE_TTL, sig, cols)


def _cols_cache_invalidate(watch_id=None):
    with _cols_cache_lock:
        if watch_id is None:
            _cols_cache.clear()
        else:
            _cols_cache.pop(watch_id, None)


# The app DB session runs with timezone=Asia/Kolkata (see db.DB_CONFIG), so a
# naive timestamp written to a TIMESTAMPTZ column is interpreted as IST. Use
# the same zone when normalising naive external timestamps for comparison
# (IST has no DST, so a fixed offset is exact).
_APP_DB_TZ = timezone(timedelta(hours=5, minutes=30))


def _aware(dt):
    if dt is None:
        return dt
    if not isinstance(dt, datetime):
        if hasattr(dt, "toordinal"):  # plain date column -> midnight, as Postgres stores it
            return datetime(dt.year, dt.month, dt.day, tzinfo=_APP_DB_TZ)
        return dt
    return dt.replace(tzinfo=_APP_DB_TZ) if dt.tzinfo is None else dt


def _changed(new_t, stored_t):
    """True if new_t differs from the stored TIMESTAMPTZ value. Comparing a
    naive external timestamp with the aware stored one was always unequal,
    which caused an UPDATE on every poll."""
    try:
        return _aware(new_t) != _aware(stored_t)
    except TypeError:
        return True


# ── Routes ────────────────────────────────────────────────────────────────────

@dbmonitor_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        # Explicit columns: keep the stored DB password out of the template context.
        cur.execute("SELECT id, name, host, port, dbname, username, created_at FROM dbmon_connections ORDER BY name")
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

    # {group_name: [watch_id, ...]} — lets the "+ Hospital Group" modal
    # pre-check the right tables the instant you pick an existing group,
    # with no extra AJAX round-trip.
    group_members = {g["name"]: [w["id"] for w in g["watches"]] for g in groups if g["name"]}

    return render_template(
        "dbmonitor.html", connections=connections, watches=watches,
        groups=groups, group_watch_ids=group_watch_ids,
        existing_group_names=existing_group_names,
        group_members=group_members,
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
    _cols_cache_invalidate()  # cascades to this connection's watches
    flash("Connection removed.", "success")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/connection/<int:conn_id>/test")
@login_required
def test_connection(conn_id):
    _admin_required()  # opens an outbound DB connection — admin only
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM dbmon_connections WHERE id=%s", (conn_id,))
        row = cur.fetchone()
    if not row:
        return jsonify({"ok": False, "error": "Not found"})
    try:
        c = _ext_conn(row)
        try:
            cur2 = c.cursor()
            # _ext_conn uses RealDictCursor — rows are dicts, so ver[0] was a
            # KeyError and this endpoint always reported failure.
            cur2.execute("SELECT version() AS v")
            ver = cur2.fetchone()
        finally:
            c.close()
        return jsonify({"ok": True, "version": str(ver["v"] if ver else "OK")})
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


@dbmonitor_bp.route("/group/save", methods=["POST"])
@login_required
def save_group():
    """
    Create or edit a hospital group's membership in one shot — powers the
    dedicated "+ Hospital Group" modal (which replaced the per-table group
    picker). Reuses _resolve_group_name() so this stays consistent with
    update_group() above: whichever checked watch_ids come in become this
    group's exact membership — anything previously in the group that got
    unchecked has its group_name cleared, and everything checked gets set.
    """
    _admin_required()
    group_name = _resolve_group_name(request.form)
    if not group_name:
        flash("Group name is required.", "danger")
        return redirect(url_for("dbmonitor.index"))

    try:
        watch_ids = [int(x) for x in request.form.getlist("watch_ids")]
    except ValueError:
        watch_ids = []

    with get_db() as conn:
        cur = conn.cursor()
        if watch_ids:
            cur.execute(
                "UPDATE dbmon_watches SET group_name=NULL "
                "WHERE group_name=%s AND id != ALL(%s)",
                (group_name, watch_ids)
            )
            cur.execute(
                "UPDATE dbmon_watches SET group_name=%s WHERE id = ANY(%s)",
                (group_name, watch_ids)
            )
        else:
            # Nothing checked — this group ends up with no members
            cur.execute(
                "UPDATE dbmon_watches SET group_name=NULL WHERE group_name=%s",
                (group_name,)
            )

    flash(f"Hospital group '{group_name}' saved.", "success")
    return redirect(url_for("dbmonitor.index"))


@dbmonitor_bp.route("/watch/<int:watch_id>/delete", methods=["POST"])
@login_required
def delete_watch(watch_id):
    _admin_required()
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM dbmon_watches WHERE id=%s", (watch_id,))
    _cols_cache_invalidate(watch_id)
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
            # Clear the stored check so a resumed watch shows "checking"
            # rather than stale numbers from before it was paused.
            cur.execute("UPDATE dbmon_watches SET monitoring=%s, last_check=NULL WHERE id=%s",
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


# Cap on distinct (location, area) pairs tracked per watch. The values come
# from the external table, so without a cap a flood of distinct values would
# create unbounded rows here and an alert email per value.
MAX_LOCATION_ROWS = 500


def _location_breakdown(cur2, schema, table, time_col, loc_col, area_col):
    """
    Group the external table by Location (and Area, if present), bounded to
    the last 24h for performance — a full-table GROUP BY on a multi-million
    row table would be far too slow to run on every 10s poll.
    loc_col / area_col come from the (cached) column detection.
    Returns rows with loc / area / last_t / recent_cnt. Locations/areas with
    zero rows in the last 24h simply won't appear here — the caller falls
    back to cached last_seen for those.
    """
    if not loc_col or not time_col:
        return []

    area_select = f', {_qi(area_col)} AS area' if area_col else ", NULL AS area"
    group_cols  = f'{_qi(loc_col)}, {_qi(area_col)}' if area_col else f'{_qi(loc_col)}'

    cur2.execute(f"""
        SELECT {_qi(loc_col)} AS loc
               {area_select},
               MAX({_qi(time_col)}) AS last_t,
               COUNT(*) FILTER (
                   WHERE {_qi(time_col)} > NOW() - INTERVAL '{DEAD_THRESHOLD_MINUTES} minutes'
               ) AS recent_cnt
        FROM {_qi(schema)}.{_qi(table)}
        WHERE {_qi(time_col)} > NOW() - INTERVAL '1 day'
        GROUP BY {group_cols}
        ORDER BY last_t DESC
        LIMIT {MAX_LOCATION_ROWS}
    """)
    return cur2.fetchall()


def _claim_dead_alert(cur, tbl, row_id, now):
    """Atomically claim a 'data stopped' alert: succeeds only if none was sent
    within ALERT_REPEAT_HOURS (same cooldown as before). Concurrent viewers
    block on the row lock and then re-check the WHERE against the committed
    value, so exactly one of them wins."""
    cur.execute(
        f"UPDATE {tbl} SET last_alert_sent=%s, was_dead=TRUE "
        f"WHERE id=%s AND (last_alert_sent IS NULL OR last_alert_sent <= %s) RETURNING id",
        (now, row_id, now - timedelta(hours=ALERT_REPEAT_HOURS))
    )
    return cur.fetchone() is not None


def _claim_resumed_alert(cur, tbl, row_id):
    """Atomically claim the one-off 'data resumed' alert (was_dead TRUE -> FALSE)."""
    cur.execute(
        f"UPDATE {tbl} SET was_dead=FALSE, last_alert_sent=NULL "
        f"WHERE id=%s AND was_dead RETURNING id",
        (row_id,)
    )
    return cur.fetchone() is not None


def _sync_and_check_locations(cur, watch, watch_id, schema, table, area_col, raw_rows, now, pending):
    """
    Upsert newly-seen locations AND areas, load per-item toggle state, run
    the same dead/alert logic as the table-level check but scoped to each
    location and each area within it (per-item results are stored for
    /status to serve). Runs on the caller's app-DB cursor; alerts
    are only CLAIMED here (atomic UPDATE ... RETURNING) and appended to
    `pending` — the caller sends them after its transaction commits.
    """
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

    label = watch["display_name"] or f"{schema}.{table}"

    for loc in tracked_locs:
        lv = loc["location_value"]
        ld = locs.get(lv)
        recent_cnt = ld["recent_cnt"] if ld else 0
        last_t     = ld["last_t"] if ld else loc["last_seen"]
        loc_is_dead = (recent_cnt == 0)

        new_seen = last_t if (last_t and _changed(last_t, loc["last_seen"])) else None
        if new_seen is not None or loc.get("recent_rows") != recent_cnt:
            cur.execute(
                "UPDATE dbmon_watch_locations SET last_seen=COALESCE(%s, last_seen), recent_rows=%s WHERE id=%s",
                (new_seen, recent_cnt, loc["id"])
            )

        # ── Areas nested under this location ──
        areas_out = []
        for a in tracked_areas_by_loc.get(lv, []):
            av = a["area_value"]
            ad = ld["areas"].get(av) if ld else None
            a_recent = (ad["recent_cnt"] or 0) if ad else 0
            a_last_t = ad["last_t"] if ad else a["last_seen"]
            a_is_dead = (a_recent == 0)

            a_new_seen = a_last_t if (a_last_t and _changed(a_last_t, a["last_seen"])) else None
            if a_new_seen is not None or a.get("recent_rows") != a_recent:
                cur.execute(
                    "UPDATE dbmon_watch_areas SET last_seen=COALESCE(%s, last_seen), recent_rows=%s WHERE id=%s",
                    (a_new_seen, a_recent, a["id"])
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
                    machine_key = f"{schema}.{table}:{lv}:{av}"

                    if a_is_dead:
                        if _claim_dead_alert(cur, "dbmon_watch_areas", a["id"], now):
                            pending.append(dict(
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
                            ))
                    elif a["was_dead"]:
                        if _claim_resumed_alert(cur, "dbmon_watch_areas", a["id"]):
                            pending.append(dict(
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
                            ))

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
                machine_key = f"{schema}.{table}:{lv}"

                if loc_is_dead:
                    if _claim_dead_alert(cur, "dbmon_watch_locations", loc["id"], now):
                        pending.append(dict(
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
                        ))
                elif loc["was_dead"]:
                    if _claim_resumed_alert(cur, "dbmon_watch_locations", loc["id"]):
                        pending.append(dict(
                            subject=f"[REFORMMED] ✅ Data resumed: {lv} ({label})",
                            body=(
                                f"Table: {schema}.{table}\n"
                                f"Location: {lv}\n"
                                f"Status: Data is flowing again for this location.\n"
                                f"Last row time: {entry['last_seen'] or 'unknown'}\n"
                            ),
                            machine_key=machine_key,
                            alert_emails=emails_for_loc,
                        ))

        out.append(entry)

    return out


def monitored_watch_ids():
    """Watches the background checker should evaluate."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM dbmon_watches WHERE monitoring ORDER BY id")
        return [r["id"] for r in cur.fetchall()]


def _store_check(watch_id, result):
    with get_db() as conn:
        conn.cursor().execute(
            "UPDATE dbmon_watches SET last_check=%s, last_checked_at=NOW() WHERE id=%s",
            (psycopg2.extras.Json(result), watch_id))


def check_watch(watch_id):
    """
    Evaluate one watched table against its external DB: live/dead status,
    stats, per-location/area breakdown, and alert emails (fire once, repeat
    every ALERT_REPEAT_HOURS while dead). Called by the background checker
    (offline_checker.py), never from a web request — so external queries and
    SMTP never hold a webserver thread, and alerts fire whether or not anyone
    has the DB Monitor page open. The result is stored for /status to serve.
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

    if not watch or not watch["monitoring"]:
        return

    c = None
    try:
        c = _ext_conn(watch)
        cur2 = c.cursor()
        schema = watch["schema_name"]
        table  = watch["table_name"]

        # Detect timestamp / location / area columns via information_schema
        # (handles mixed-case names like "Observation_Time"); cached per watch.
        sig = (watch.get("conn_id"), schema, table)
        cols = _cols_cache_get(watch_id, sig)
        if cols is None:
            time_col, _ = _detect_time_col_by_type(cur2, schema, table)
            loc_col = area_col = None
            if time_col:
                loc_col = _detect_location_col(cur2, schema, table)
                if loc_col:
                    area_col = _detect_area_col(cur2, schema, table)
                _cols_cache_put(watch_id, sig, (time_col, loc_col, area_col))
        else:
            time_col, loc_col, area_col = cols

        if not time_col:
            # Verify table exists at all
            cur2.execute("""
                SELECT COUNT(*) as cnt FROM information_schema.columns
                WHERE table_schema=%s AND table_name=%s
            """, (schema, table))
            if cur2.fetchone()["cnt"] == 0:
                c.close()
                _store_check(watch_id, {"error": f"Table {schema}.{table} not found"})
                return

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
        loc_rows = []

        if time_col:
            # Use MAX on the time column — fast with an index, OK without
            cur2.execute(
                f'SELECT MAX({_qi(time_col)}) as last_t FROM {_qi(schema)}.{_qi(table)}'
            )
            r = cur2.fetchone()
            if r and r["last_t"]:
                last_row_time = r["last_t"].isoformat()

            # Rows in the last 5 min (dead threshold) and last 1 min (rate) in
            # one scan — the 1-min window is a subset of the 5-min window.
            cur2.execute(
                f'SELECT COUNT(*) AS cnt5, '
                f'COUNT(*) FILTER (WHERE {_qi(time_col)} > NOW() - INTERVAL \'1 minute\') AS cnt1 '
                f'FROM {_qi(schema)}.{_qi(table)} '
                f'WHERE {_qi(time_col)} > NOW() - INTERVAL \'{DEAD_THRESHOLD_MINUTES} minutes\''
            )
            r = cur2.fetchone()
            rows_last_5min = r["cnt5"]
            rows_last_1min = r["cnt1"]

            # ── Per-location breakdown (Location column within this same table) ──
            loc_rows = _location_breakdown(cur2, schema, table, time_col, loc_col, area_col)
        else:
            loc_col = area_col = None

        c.close()

        # Determine live/dead
        is_dead = (rows_last_5min == 0)

        # ── State sync + alert claims (one short app-DB transaction) ─────────
        # Alerts are claimed with conditional UPDATE ... RETURNING so that
        # concurrent viewers polling the same watch can't both send; emails go
        # out only after the transaction commits, so no pooled connection is
        # held during SMTP I/O (and _send_alert's own get_db() isn't nested).
        now = datetime.now(timezone.utc)
        pending_locs  = []  # location/area alerts
        pending_watch = []  # table-level alerts (default machine_key/emails)
        table_alerts = bool(watch["alerts_enabled"] and watch.get("alert_emails"))
        result = {
            "is_dead":         is_dead,
            "total_rows":      total_rows,
            "last_row_time":   last_row_time,
            "rows_last_5min":  rows_last_5min,
            "rows_last_1min":  rows_last_1min,
            "time_col":        time_col,
            "location_col":    loc_col,
            "area_col":        area_col,
        }
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE dbmon_watches SET last_check=%s, last_checked_at=NOW() WHERE id=%s",
                (psycopg2.extras.Json(result), watch_id))
            if loc_col or (table_alerts and (is_dead or watch["was_dead"])):
                if loc_col:
                    _sync_and_check_locations(
                        cur, watch, watch_id, schema, table, area_col, loc_rows, now, pending_locs
                    )

                if table_alerts:
                    name = watch['display_name'] or schema + '.' + table
                    if is_dead:
                        # Send if never sent, or last sent >= ALERT_REPEAT_HOURS ago
                        if _claim_dead_alert(cur, "dbmon_watches", watch_id, now):
                            pending_watch.append(dict(
                                subject=f"[REFORMMED] ⚠ Data stopped: {name}",
                                body=(
                                    f"Table: {schema}.{table}\n"
                                    f"Connection: {watch['conn_name'] if 'conn_name' in watch else ''}\n"
                                    f"Status: No new rows in the last {DEAD_THRESHOLD_MINUTES} minutes.\n"
                                    f"Last data received: {last_row_time or 'unknown'}\n"
                                    f"Total rows: {total_rows}\n\n"
                                    f"This alert repeats every {ALERT_REPEAT_HOURS} hour(s) until data resumes."
                                ),
                            ))
                    elif watch["was_dead"]:
                        # Data is live — send recovery email if it was previously dead
                        if _claim_resumed_alert(cur, "dbmon_watches", watch_id):
                            pending_watch.append(dict(
                                subject=f"[REFORMMED] ✅ Data resumed: {name}",
                                body=(
                                    f"Table: {schema}.{table}\n"
                                    f"Status: Data is flowing again.\n"
                                    f"Last row time: {last_row_time or 'unknown'}\n"
                                    f"Total rows: {total_rows}\n"
                                ),
                            ))

        # Committed — now send what was claimed (same order as before:
        # location/area alerts first, then the table-level one).
        _send_pending(watch, pending_locs + pending_watch)

    except Exception as e:
        print(f"[dbmonitor] status check for watch {watch_id} failed: {e}")
        try:
            _store_check(watch_id, {"error": str(e)})
        except Exception as e2:
            print(f"[dbmonitor] could not store check error for watch {watch_id}: {e2}")
    finally:
        if c is not None and not c.closed:
            c.close()  # a failed query used to leak the external connection


@dbmonitor_bp.route("/watch/<int:watch_id>/status")
@login_required
def watch_status(watch_id):
    """
    Latest live/dead status + stats for one watched table, as recorded by the
    background checker (check_watch). Only reads the app DB — the external
    database is never queried on a web request.
    """
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, monitoring, last_check, last_checked_at FROM dbmon_watches WHERE id=%s",
            (watch_id,))
        watch = cur.fetchone()
        if not watch:
            return jsonify({"error": "Not found"}), 404
        if not watch["monitoring"]:
            return jsonify({"monitoring": False})

        check = watch["last_check"]
        if not check:
            return jsonify({"monitoring": True, "pending": True})
        if check.get("error"):
            # Driver errors name the internal host/port/DB user — only admins
            # (who can already see the connection settings) get the details.
            return jsonify({"error": check["error"] if current_user.is_admin else "Status check failed."})

        locations = []
        if check.get("location_col"):
            locations = _stored_locations(cur, watch_id, bool(check.get("area_col")))

    return jsonify(dict(
        check,
        monitoring=True,
        checked_at=watch["last_checked_at"].isoformat() if watch["last_checked_at"] else None,
        locations=locations,
    ))


def _stored_locations(cur, watch_id, has_areas):
    """Per-location/area breakdown from the last check, with the current
    toggle state (so a toggle shows immediately, not after the next check)."""
    is_admin = current_user.is_admin
    cur.execute(
        "SELECT * FROM dbmon_watch_locations WHERE watch_id=%s ORDER BY location_value", (watch_id,))
    locs = cur.fetchall()
    areas_by_loc = {}
    if has_areas:
        cur.execute(
            "SELECT * FROM dbmon_watch_areas WHERE watch_id=%s ORDER BY location_value, area_value",
            (watch_id,))
        for a in cur.fetchall():
            areas_by_loc.setdefault(a["location_value"], []).append(a)

    def _item(row):
        recent = row["recent_rows"] or 0
        return {
            "id":             row["id"],
            "monitoring":     row["monitoring"],
            "alerts_enabled": row["alerts_enabled"],
            "alert_emails":   row["alert_emails"] if is_admin else "",
            "is_dead":        (recent == 0) if row["monitoring"] else None,
            "last_seen":      row["last_seen"].isoformat() if row["last_seen"] else None,
            "recent_rows":    recent,
        }

    out = []
    for loc in locs:
        areas = [dict(_item(a), area=a["area_value"])
                 for a in areas_by_loc.get(loc["location_value"], [])]
        out.append(dict(
            _item(loc),
            location=loc["location_value"],
            area_count=len(areas) if has_areas else None,
            areas=areas,
        ))
    return out
