"""
Settings blueprint — app-wide configuration via UI.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from db import (
    get_db, purge_old_data, list_alert_recipients,
    alerts_master_enabled, set_encrypted_setting, get_encrypted_setting,
)

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
    recipients = list_alert_recipients()
    return render_template(
        "settings.html", s=s, recipients=recipients,
        alerts_master_enabled=alerts_master_enabled(),
        smtp_username=get_encrypted_setting("smtp_username", ""),
        # Password itself is NEVER sent back to the browser — the field
        # always renders empty; we only report whether one is already set,
        # so the UI can say "a password is saved" without exposing it.
        smtp_password_is_set=bool(get_encrypted_setting("smtp_password", "")),
    )


@settings_bp.route("/alerts-master/toggle", methods=["POST"])
@login_required
def toggle_alerts_master():
    """
    The kill-switch. Flips alerts_master_enabled in app_settings — every
    alert-sending code path (offline_checker.py, dbmonitor.py, dvr.py)
    checks this before doing anything else, so this one toggle mutes the
    entire app's alerting regardless of any other setting.
    """
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key='alerts_master_enabled'")
        row = cur.fetchone()
        current = (row["value"] if row else "1") == "1"
        new_val = "0" if current else "1"
        cur.execute("""
            INSERT INTO app_settings (key, value) VALUES ('alerts_master_enabled', %s)
            ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
        """, (new_val,))
    flash(
        "All alerts are now DISABLED app-wide." if new_val == "0"
        else "Alerts are back ON app-wide.",
        "warning" if new_val == "0" else "success"
    )
    return redirect(url_for("settings.index") + "#general")


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

    # SMTP username/password — encrypted, handled separately from the plain
    # keys above. Username can be blanked out deliberately; password only
    # updates if the field was actually filled in (it always renders empty,
    # so a blank submit means "leave the existing one alone", not "clear it").
    smtp_username = request.form.get("smtp_username", "").strip()
    if "smtp_username" in request.form:
        set_encrypted_setting("smtp_username", smtp_username)

    smtp_password = request.form.get("smtp_password", "").strip()
    if smtp_password:
        set_encrypted_setting("smtp_password", smtp_password)

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


# ── Alert Recipients (centralized address book) ────────────────────────────

@settings_bp.route("/recipients/add", methods=["POST"])
@login_required
def add_recipient():
    _admin_required()
    email = request.form.get("email", "").strip().lower()
    label = request.form.get("label", "").strip()
    if not email:
        flash("Email is required.", "danger")
        return redirect(url_for("settings.index") + "#recipients")
    try:
        with get_db() as conn:
            conn.cursor().execute(
                "INSERT INTO alert_recipients (email, label) VALUES (%s, %s)",
                (email, label)
            )
        flash(f"Added recipient {email}.", "success")
    except Exception as e:
        if "unique" in str(e).lower():
            flash("That email is already in the list.", "warning")
        else:
            flash(f"Error: {e}", "danger")
    return redirect(url_for("settings.index") + "#recipients")


@settings_bp.route("/recipients/<int:recipient_id>/delete", methods=["POST"])
@login_required
def delete_recipient(recipient_id):
    _admin_required()
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM alert_recipients WHERE id=%s", (recipient_id,))
    flash("Recipient removed.", "success")
    return redirect(url_for("settings.index") + "#recipients")