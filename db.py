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

        # ── Users table ──────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS webapp_users (
                id           SERIAL PRIMARY KEY,
                username     TEXT UNIQUE NOT NULL,
                email        TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role         TEXT NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
                is_active    BOOLEAN NOT NULL DEFAULT TRUE,
                created_at   TIMESTAMPTZ DEFAULT NOW(),
                last_login   TIMESTAMPTZ
            )
        """)

        # ── User ↔ server permissions (for role='user') ─────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_server_access (
                user_id     INTEGER REFERENCES webapp_users(id) ON DELETE CASCADE,
                table_name  TEXT NOT NULL,
                PRIMARY KEY (user_id, table_name)
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

        # ── Alert log ────────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alert_log (
                id           SERIAL PRIMARY KEY,
                alert_type   TEXT NOT NULL,
                machine_key  TEXT NOT NULL,
                subject      TEXT NOT NULL,
                body         TEXT NOT NULL,
                sent_at      TIMESTAMPTZ DEFAULT NOW(),
                success      BOOLEAN NOT NULL DEFAULT TRUE
            )
        """)

        # Seed default alert configs if missing
        defaults = [
            ("offline",   True,  None, 10),
            ("online",    True,  None, 5),
            ("cpu",       True,  90.0, 10),
            ("ram",       True,  90.0, 10),
            ("disk",      True,  85.0, 10),
            ("temp",      True,  80.0, 10),
        ]
        for atype, enabled, thresh, cooldown in defaults:
            cur.execute("""
                INSERT INTO alert_config (alert_type, enabled, threshold, cooldown_minutes)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (alert_type) DO NOTHING
            """, (atype, enabled, thresh, cooldown))

        # Seed default admin user (admin / admin123 — change on first login)
        from werkzeug.security import generate_password_hash
        cur.execute("""
            INSERT INTO webapp_users (username, email, password_hash, role)
            VALUES ('admin', 'admin@reformmed.local', %s, 'admin')
            ON CONFLICT (username) DO NOTHING
        """, (generate_password_hash("admin123"),))

        log.info("✅ Webapp DB tables ready")
