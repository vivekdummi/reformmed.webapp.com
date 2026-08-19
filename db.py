"""
Database helpers — psycopg2 (sync) for Flask.
Reuses the existing PostgreSQL instance created by main.py / docker-compose.
"""

import os
import logging
import psycopg2
import psycopg2.extras
from contextlib import contextmanager

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
        ]:
            try:
                cur.execute(col_sql)
            except Exception:
                pass

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
            ("app_name",            "REFORMMED Monitor"),
            ("sidebar_default",     "expanded"),
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

        # Seed default admin user
        from werkzeug.security import generate_password_hash
        cur.execute("""
            INSERT INTO webapp_users (username, email, password_hash, role,
                                      can_view_dvr, can_view_dbmon, can_view_alerts, can_view_servers)
            VALUES ('admin', 'admin@reformmed.local', %s, 'admin', TRUE, TRUE, TRUE, TRUE)
            ON CONFLICT (username) DO NOTHING
        """, (generate_password_hash("admin123"),))

        log.info("✅ Webapp DB tables ready")


def get_setting(key, default=""):
    """Read a single app_settings value."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key=%s", (key,))
        row = cur.fetchone()
    return row["value"] if row else default


def list_alert_recipients():
    """All registered alert recipients, for the recipient_picker macro."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM alert_recipients ORDER BY label, email")
        return cur.fetchall()


def purge_old_data():
    """
    Delete metric rows older than data_retention_days from all machine tables.
    Call this from a scheduled job or on startup.
    """
    days = int(get_setting("data_retention_days", "7"))
    with get_db() as conn:
        cur = conn.cursor()
        # Get all machine metric tables
        cur.execute("SELECT table_name FROM machine_registry")
        tables = [r["table_name"] for r in cur.fetchall()]
    deleted_total = 0
    for tbl in tables:
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute(f"""
                    DELETE FROM {tbl}
                    WHERE ts < NOW() - INTERVAL '{days} days'
                """)
                deleted_total += cur.rowcount
        except Exception as e:
            log.warning("purge_old_data: skipped table %s: %s", tbl, e)
    # Also prune alert_log
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(f"""
            DELETE FROM alert_log WHERE sent_at < NOW() - INTERVAL '{days} days'
        """)
    log.info("purge_old_data: deleted %d rows (retention=%d days)", deleted_total, days)