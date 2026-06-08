"""
Settings blueprint — app-wide configuration via UI.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from db import get_db, purge_old_data

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


def _admin_required():
    if not current_user.is_admin:
        abort(403)


def _all_settings():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM app_settings ORDER BY key")
        return {r["key"]: r["value"] for r in cur.fetchall()}


@settings_bp.route("/")
@login_required
def index():
    _admin_required()
    s = _all_settings()
    return render_template("settings.html", s=s)


@settings_bp.route("/save", methods=["POST"])
@login_required
def save():
    _admin_required()
    keys = [
        "data_retention_days", "home_refresh_secs",
        "smtp_host", "smtp_port", "alert_from_email",
        "app_name", "sidebar_default",
    ]
    with get_db() as conn:
        cur = conn.cursor()
        for k in keys:
            v = request.form.get(k, "").strip()
            if v:
                cur.execute("""
                    INSERT INTO app_settings (key, value) VALUES (%s, %s)
                    ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
                """, (k, v))
    flash("Settings saved.", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/purge-now", methods=["POST"])
@login_required
def purge_now():
    _admin_required()
    try:
        purge_old_data()
        flash("Old data purged successfully.", "success")
    except Exception as e:
        flash(f"Purge failed: {e}", "danger")
    return redirect(url_for("settings.index"))