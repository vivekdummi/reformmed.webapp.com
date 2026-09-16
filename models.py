"""
User model — Flask-Login compatible.
"""

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
import pyotp
from db import get_db


class User(UserMixin):
    def __init__(self, row):
        self.id            = row["id"]
        self.username      = row["username"]
        self.email         = row["email"]
        self.password_hash = row["password_hash"]
        self.role          = row["role"]
        self.is_active_    = row["is_active"]
        # Feature permissions (default True for backward compat)
        self.can_view_dvr     = row.get("can_view_dvr",     True)
        self.can_view_dbmon   = row.get("can_view_dbmon",   False)
        self.can_view_alerts  = row.get("can_view_alerts",  True)
        self.can_view_servers = row.get("can_view_servers", True)
        # Two-factor auth
        self.totp_secret   = row.get("totp_secret")
        self.totp_enabled  = row.get("totp_enabled",  False)
        self.totp_required = row.get("totp_required", False)

    @property
    def is_active(self):
        return self.is_active_

    @property
    def is_admin(self):
        return self.role == "admin"

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ── DB accessors ─────────────────────────────────────────────────────────

    @staticmethod
    def get_by_id(user_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM webapp_users WHERE id=%s", (user_id,))
            row = cur.fetchone()
        return User(row) if row else None

    @staticmethod
    def get_by_username(username):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM webapp_users WHERE username=%s", (username,))
            row = cur.fetchone()
        return User(row) if row else None

    @staticmethod
    def get_by_email(email):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM webapp_users WHERE email=%s", (email,))
            row = cur.fetchone()
        return User(row) if row else None

    @staticmethod
    def all():
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM webapp_users ORDER BY id")
            return [User(r) for r in cur.fetchall()]

    @staticmethod
    def create(username, email, password, role="user", **perms):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO webapp_users
                    (username, email, password_hash, role,
                     can_view_dvr, can_view_dbmon, can_view_alerts, can_view_servers)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (
                username, email, generate_password_hash(password), role,
                perms.get("can_view_dvr",     True),
                perms.get("can_view_dbmon",   False),
                perms.get("can_view_alerts",  True),
                perms.get("can_view_servers", True),
            ))
            return cur.fetchone()["id"]

    @staticmethod
    def update(user_id, **kwargs):
        allowed = {
            "username", "email", "role", "is_active", "password_hash",
            "can_view_dvr", "can_view_dbmon", "can_view_alerts", "can_view_servers",
        }
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        if "password" in kwargs:
            fields["password_hash"] = generate_password_hash(kwargs["password"])
        set_clause = ", ".join(f"{k}=%s" for k in fields)
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE webapp_users SET {set_clause} WHERE id=%s",
                list(fields.values()) + [user_id]
            )

    @staticmethod
    def delete(user_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM webapp_users WHERE id=%s", (user_id,))

    @staticmethod
    def touch_login(user_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE webapp_users SET last_login=NOW() WHERE id=%s", (user_id,))

    # ── Server access ─────────────────────────────────────────────────────────

    def allowed_servers(self):
        """Returns set of table_names this user is allowed to view. None = all."""
        if self.is_admin:
            return None
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT table_name FROM user_server_access WHERE user_id=%s", (self.id,)
            )
            return {r["table_name"] for r in cur.fetchall()}

    @staticmethod
    def set_server_access(user_id, table_names):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM user_server_access WHERE user_id=%s", (user_id,))
            for tn in table_names:
                cur.execute(
                    "INSERT INTO user_server_access (user_id, table_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (user_id, tn)
                )

    # ── DVR hospital access ─────────────────────────────────────────────────

    def allowed_hospitals(self):
        """Returns set of dvr_hospitals.id this user is allowed to view. None = all."""
        if self.is_admin:
            return None
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT hospital_id FROM user_hospital_access WHERE user_id=%s", (self.id,)
            )
            return {r["hospital_id"] for r in cur.fetchall()}

    @staticmethod
    def set_hospital_access(user_id, hospital_ids):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM user_hospital_access WHERE user_id=%s", (user_id,))
            for hid in hospital_ids:
                cur.execute(
                    "INSERT INTO user_hospital_access (user_id, hospital_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (user_id, hid)
                )

    # ── Two-factor auth (TOTP) ───────────────────────────────────────────────

    def check_totp(self, code):
        """Verify a 6-digit code against this user's secret. False if 2FA isn't set up."""
        if not self.totp_secret:
            return False
        return pyotp.TOTP(self.totp_secret).verify(str(code).strip(), valid_window=1)

    def totp_provisioning_uri(self, secret):
        """otpauth:// URI for a QR code, using a given (possibly not-yet-saved) secret."""
        return pyotp.TOTP(secret).provisioning_uri(name=self.email, issuer_name="REFORMMED Monitor")

    @staticmethod
    def start_totp_setup(user_id, secret):
        """Store a freshly generated secret, unconfirmed — totp_enabled stays False
        until the user proves they can generate a matching code."""
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE webapp_users SET totp_secret=%s, totp_enabled=FALSE WHERE id=%s",
                (secret, user_id)
            )

    @staticmethod
    def confirm_totp_setup(user_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE webapp_users SET totp_enabled=TRUE WHERE id=%s", (user_id,))

    @staticmethod
    def disable_totp(user_id):
        """Used both by a user turning their own 2FA off, and by an admin
        resetting a user's 2FA (e.g. after a lost device)."""
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE webapp_users SET totp_secret=NULL, totp_enabled=FALSE WHERE id=%s",
                (user_id,)
            )

    @staticmethod
    def set_totp_required(user_id, required: bool):
        """Admin-only: force (or stop forcing) this user to set up 2FA."""
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE webapp_users SET totp_required=%s WHERE id=%s", (required, user_id))