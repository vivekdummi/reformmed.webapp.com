"""
Database helpers — psycopg2 (sync) for Flask.
Reuses the existing PostgreSQL instance created by main.py / docker-compose.
"""

import os
import logging
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)

DB_CONFIG = {
    "host":     os.getenv("POSTGRES_HOST", "reformmed_postgres"),
    "port":     int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname":   os.getenv("POSTGRES_DB", "monitor_machine"),
    "user":     os.getenv("POSTGRES_USER", "admin"),
    "password": os.getenv("POSTGRES_PASSWORD", ""),
    # Every session on this connection reads/writes timestamps as IST (UTC+5:30).
    # TIMESTAMPTZ columns still store the correct absolute instant underneath —
    # this only changes the timezone Postgres converts to when handing values
    # back to psycopg2 (and therefore what str()/.strftime() show in templates).
    "options":  "-c timezone=Asia/Kolkata",
}


@contextmanager
def get_db():
    """Yield a psycopg2 connection with RealDictCursor; auto-commit on exit."""
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create the webapp-specific tables if they don't exist yet."""
    with get_db() as conn:
        cur = conn.cursor()

        # machine_registry itself is created by the ingestion API (server/main.py)
        # — this guard just makes sure the alerts_enabled column exists regardless
        # of which service (webapp or api) happens to start first. Wrapped since
        # the table itself may not exist yet on a brand-new DB if webapp starts
        # before the API's own migration has run.
        try:
            cur.execute("""
                ALTER TABLE machine_registry
                ADD COLUMN IF NOT EXISTS alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE
            """)
        except Exception as e:
            conn.rollback()
            log.warning("alerts_enabled migration skipped (machine_registry not created yet): %s", e)

        # ── Users table ──────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS webapp_users (
                id           SERIAL PRIMARY KEY,
                username     TEXT UNIQUE NOT NULL,
                email        TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role         TEXT NOT NULL DEFAULT 'user',
                is_active    BOOLEAN NOT NULL DEFAULT TRUE,
                created_at   TIMESTAMPTZ DEFAULT NOW(),
                last_login   TIMESTAMPTZ
            )
        """)

        # Feature permission columns (safe to add to existing installs)
        for col_sql in [
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS can_view_dvr     BOOLEAN NOT NULL DEFAULT TRUE",
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS can_view_dbmon   BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS can_view_alerts  BOOLEAN NOT NULL DEFAULT TRUE",
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS can_view_servers BOOLEAN NOT NULL DEFAULT TRUE",
            # Two-factor auth (TOTP): totp_secret is set once the user starts
            # setup; totp_enabled flips TRUE only after they confirm a code
            # (so login isn't gated on an unconfirmed secret); totp_required
            # is an admin-set flag that forces setup on next login.
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS totp_secret      TEXT",
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS totp_enabled     BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS totp_required    BOOLEAN NOT NULL DEFAULT FALSE",
            # Forgot-password OTP: hashed (not plaintext) 6-digit code + expiry.
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS reset_otp_hash    TEXT",
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS reset_otp_expires TIMESTAMPTZ",
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS reset_otp_attempts INTEGER NOT NULL DEFAULT 0",
            # Profile photo: bumped on every upload/remove (0 = no photo); the
            # image itself lives in user_avatars, never loaded on each request.
            "ALTER TABLE webapp_users ADD COLUMN IF NOT EXISTS avatar_ver INTEGER NOT NULL DEFAULT 0",
        ]:
            try:
                cur.execute(col_sql)
            except Exception:
                pass

        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_avatars (
                user_id    INTEGER PRIMARY KEY REFERENCES webapp_users(id) ON DELETE CASCADE,
                image      BYTEA NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # ── User ↔ server permissions ─────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_server_access (
                user_id     INTEGER REFERENCES webapp_users(id) ON DELETE CASCADE,
                table_name  TEXT NOT NULL,
                PRIMARY KEY (user_id, table_name)
            )
        """)

        # ── User ↔ DVR hospital permissions (same idea, scoped to dvr_hospitals) ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_hospital_access (
                user_id     INTEGER REFERENCES webapp_users(id) ON DELETE CASCADE,
                hospital_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, hospital_id)
            )
        """)

        # ── Alert configuration ──────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alert_config (
                id                    SERIAL PRIMARY KEY,
                alert_type            TEXT UNIQUE NOT NULL,
                enabled               BOOLEAN NOT NULL DEFAULT TRUE,
                threshold             FLOAT,
                cooldown_minutes      INTEGER NOT NULL DEFAULT 10,
                notify_emails         TEXT NOT NULL DEFAULT '',
                updated_at            TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # ── Per-machine alert overrides ──────────────────────────────────────
        # A row here for (table_name, alert_type) takes precedence over the
        # global alert_config row of the same type, for that one machine only
        # — e.g. a beefier server that's expected to run hot can have its own
        # higher CPU/temp threshold instead of triggering the fleet-wide rule.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS machine_alert_overrides (
                id                    SERIAL PRIMARY KEY,
                table_name            TEXT NOT NULL,
                alert_type            TEXT NOT NULL,
                enabled               BOOLEAN NOT NULL DEFAULT TRUE,
                threshold             FLOAT,
                cooldown_minutes      INTEGER NOT NULL DEFAULT 10,
                notify_emails         TEXT NOT NULL DEFAULT '',
                updated_at            TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(table_name, alert_type)
            )
        """)

        # ── Alert log (unified — system + DVR + DB monitor) ─────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alert_log (
                id           SERIAL PRIMARY KEY,
                alert_type   TEXT NOT NULL,
                source       TEXT NOT NULL DEFAULT 'system',
                machine_key  TEXT NOT NULL,
                subject      TEXT NOT NULL,
                body         TEXT NOT NULL,
                sent_at      TIMESTAMPTZ DEFAULT NOW(),
                success      BOOLEAN NOT NULL DEFAULT TRUE
            )
        """)
        # Add source column to existing installs
        try:
            cur.execute("ALTER TABLE alert_log ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'system'")
        except Exception:
            pass

        # ── App settings ─────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # ── Centralized alert recipients ────────────────────────────────────
        # A single address book of who *can* receive alerts. Every alert-email
        # field across the app (DB Monitor tables, DVR settings, ...) picks
        # from this list instead of retyping raw addresses each time — add or
        # remove someone here once and every assignment picker reflects it.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alert_recipients (
                id         SERIAL PRIMARY KEY,
                email      TEXT UNIQUE NOT NULL,
                label      TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        default_settings = [
            ("data_retention_days", "7"),
            ("home_refresh_secs",   "2"),
            ("smtp_host",           "smtp.gmail.com"),
            ("smtp_port",           "465"),
            ("alert_from_email",    ""),
            ("app_name",            "Reformmed INFRA Monitor"),
            ("sidebar_default",     "expanded"),
            # Master alert kill-switch — checked before every single alert
            # send, across System/Machine/DVR/DB Monitor alike. "0" mutes
            # the whole app regardless of any individual alert's own setting.
            ("alerts_master_enabled", "1"),
        ]
        for k, v in default_settings:
            cur.execute("""
                INSERT INTO app_settings (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO NOTHING
            """, (k, v))

        # Seed default alert configs
        defaults = [
            ("offline", True, None, 10),
            ("online",  True, None,  5),
            ("cpu",     True, 90.0, 10),
            ("ram",     True, 90.0, 10),
            ("disk",    True, 85.0, 10),
            ("temp",    True, 80.0, 10),
        ]
        for atype, enabled, thresh, cooldown in defaults:
            cur.execute("""
                INSERT INTO alert_config (alert_type, enabled, threshold, cooldown_minutes)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (alert_type) DO NOTHING
            """, (atype, enabled, thresh, cooldown))

        # Seed the first admin ONLY when no admin exists. The old seed re-created
        # admin/admin123 on every start (e.g. after the admin was renamed),
        # which left a well-known login open in production.
        cur.execute("SELECT COUNT(*) AS n FROM webapp_users WHERE role='admin'")
        if cur.fetchone()["n"] == 0:
            import secrets
            from werkzeug.security import generate_password_hash
            initial_pw = os.getenv("ADMIN_INITIAL_PASSWORD") or secrets.token_urlsafe(12)
            cur.execute("""
                INSERT INTO webapp_users (username, email, password_hash, role,
                                          can_view_dvr, can_view_dbmon, can_view_alerts, can_view_servers)
                VALUES ('admin', 'admin@reformmed.local', %s, 'admin', TRUE, TRUE, TRUE, TRUE)
                ON CONFLICT DO NOTHING
            """, (generate_password_hash(initial_pw),))
            if not os.getenv("ADMIN_INITIAL_PASSWORD"):
                log.warning("Created first admin user 'admin' with password: %s "
                            "— change it after logging in.", initial_pw)

        log.info("✅ Webapp DB tables ready")


def get_setting(key, default=""):
    """Read a single app_settings value."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key=%s", (key,))
        row = cur.fetchone()
    return row["value"] if row else default


def alerts_master_enabled() -> bool:
    """
    The one kill-switch checked before every alert send, everywhere in the
    app (System Alerts, Machine Alerts, DVR, DB Monitor). When this is off,
    nothing sends — regardless of what any individual alert type/machine/
    table has configured. Defaults to enabled if the row is somehow missing.
    """
    return get_setting("alerts_master_enabled", "1") == "1"


# ── Encrypted settings (SMTP password, etc.) ────────────────────────────────
# Values are encrypted with a key that lives OUTSIDE the database — in
# SETTINGS_ENCRYPTION_KEY (.env). This is the same reasoning FLASK_SECRET
# already follows: an encryption key has to live somewhere outside the
# thing it protects. What this DOES achieve: the actual SMTP password no
# longer sits in a plaintext DB column visible to anyone with read access
# to app_settings, or in .env where it was before.

def _get_fernet():
    key = os.getenv("SETTINGS_ENCRYPTION_KEY", "")
    if not key:
        log.warning(
            "SETTINGS_ENCRYPTION_KEY is not set — encrypted settings (SMTP "
            "password) can't be read or written until it is. Generate one "
            "with: python3 -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\" and add it to .env."
        )
        return None
    try:
        return Fernet(key.encode())
    except Exception as e:
        log.error("SETTINGS_ENCRYPTION_KEY is invalid: %s", e)
        return None


def set_encrypted_setting(key, value):
    """Encrypt `value` and store it in app_settings under `key`. No-op (with
    a warning already logged by _get_fernet) if no encryption key is set."""
    f = _get_fernet()
    if f is None:
        return False
    token = f.encrypt(value.encode()).decode()
    with get_db() as conn:
        conn.cursor().execute("""
            INSERT INTO app_settings (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
        """, (key, token))
    return True


def get_encrypted_setting(key, default=""):
    """Decrypt and return the value stored under `key`, or `default` if
    missing/undecryptable (e.g. no encryption key configured yet)."""
    f = _get_fernet()
    if f is None:
        return default
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key=%s", (key,))
        row = cur.fetchone()
    if not row:
        return default
    try:
        return f.decrypt(row["value"].encode()).decode()
    except (InvalidToken, Exception) as e:
        log.error("Failed to decrypt setting '%s': %s", key, e)
        return default


def list_alert_recipients():
    """All registered alert recipients, for the recipient_picker macro."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM alert_recipients ORDER BY label, email")
        return cur.fetchall()


RETENTION_MIN_DAYS = 1
RETENTION_MAX_DAYS = 3650
_PURGE_BATCH = 20000


def retention_days():
    """data_retention_days from Settings, clamped to a sane range."""
    try:
        days = int(get_setting("data_retention_days", "7"))
    except (TypeError, ValueError):
        days = 7
    return max(RETENTION_MIN_DAYS, min(RETENTION_MAX_DAYS, days))


def _batched_delete(conn, table, ts_col, days):
    """Delete rows older than `days` in small batches, committing after each
    one, so a big purge on a busy production table never holds a long lock
    or a huge transaction. Returns the number of rows removed."""
    from psycopg2 import sql
    q = sql.SQL("""
        DELETE FROM {t} WHERE ctid IN (
            SELECT ctid FROM {t}
            WHERE {c} < NOW() - make_interval(days => %s)
            LIMIT %s
        )
    """).format(t=sql.Identifier(table), c=sql.Identifier(ts_col))
    removed = 0
    while True:
        cur = conn.cursor()
        cur.execute(q, (days, _PURGE_BATCH))
        n = cur.rowcount or 0
        conn.commit()
        removed += n
        if n < _PURGE_BATCH:
            return removed


def purge_old_data():
    """
    Delete metric rows and alert-log entries older than data_retention_days.
    Runs automatically from the checker daemon (offline_checker.py) every
    PURGE_INTERVAL_HOURS, and on demand from Settings → Data retention.
    Records the outcome in app_settings (last_purge_*) for the Settings page.
    Returns {"days", "metric_rows", "alert_rows", "tables", "errors"}.
    """
    import re
    from datetime import datetime, timezone
    days = retention_days()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM machine_registry")
        tables = [r["table_name"] for r in cur.fetchall()
                  if re.fullmatch(r"[a-z0-9_]{1,63}", r["table_name"] or "")]

    result = {"days": days, "metric_rows": 0, "alert_rows": 0, "tables": 0, "errors": 0}
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        for tbl in tables:
            try:
                result["metric_rows"] += _batched_delete(conn, tbl, "ts", days)
                result["tables"] += 1
            except Exception as e:
                conn.rollback()
                result["errors"] += 1
                log.warning("purge_old_data: skipped table %s: %s", tbl, e)
        try:
            result["alert_rows"] = _batched_delete(conn, "alert_log", "sent_at", days)
        except Exception as e:
            conn.rollback()
            result["errors"] += 1
            log.warning("purge_old_data: alert_log skipped: %s", e)

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cur = conn.cursor()
        for k, v in (("last_purge_at", now),
                     ("last_purge_rows", str(result["metric_rows"] + result["alert_rows"])),
                     ("last_purge_errors", str(result["errors"]))):
            cur.execute("""
                INSERT INTO app_settings (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
            """, (k, v))
        conn.commit()
    finally:
        conn.close()
    log.info("purge_old_data: removed %d metric rows from %d tables + %d alert rows "
             "(retention=%d days, %d errors)", result["metric_rows"], result["tables"],
             result["alert_rows"], days, result["errors"])
    return result
