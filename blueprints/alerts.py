from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from db import get_db

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM alert_config ORDER BY id")
        configs = cur.fetchall()
        cur.execute("SELECT * FROM alert_log ORDER BY sent_at DESC LIMIT 100")
        logs = cur.fetchall()
    return render_template("alerts.html", configs=configs, logs=logs)


@alerts_bp.route("/config/update", methods=["POST"])
@login_required
def update_config():
    if not current_user.is_admin:
        abort(403)

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, alert_type FROM alert_config")
        rows = cur.fetchall()

        for row in rows:
            aid        = row["id"]
            atype      = row["alert_type"]
            enabled    = request.form.get(f"enabled_{aid}") == "1"
            threshold  = request.form.get(f"threshold_{aid}", "").strip() or None
            cooldown   = request.form.get(f"cooldown_{aid}", "10").strip()
            emails     = request.form.get(f"emails_{aid}", "").strip()

            try:
                thresh_val = float(threshold) if threshold else None
                cooldown_val = int(cooldown)
            except ValueError:
                flash(f"Invalid value for {atype}.", "danger")
                return redirect(url_for("alerts.index"))

            cur.execute("""
                UPDATE alert_config
                SET enabled=%s, threshold=%s, cooldown_minutes=%s,
                    notify_emails=%s, updated_at=NOW()
                WHERE id=%s
            """, (enabled, thresh_val, cooldown_val, emails, aid))

    flash("Alert configuration saved.", "success")
    return redirect(url_for("alerts.index"))


@alerts_bp.route("/test/<alert_type>", methods=["POST"])
@login_required
def test_alert(alert_type):
    """Send a test email for the given alert type."""
    if not current_user.is_admin:
        abort(403)

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM alert_config WHERE alert_type=%s", (alert_type,))
        config = cur.fetchone()

    if not config:
        flash("Alert type not found.", "danger")
        return redirect(url_for("alerts.index"))

    from alert_sender import send_alert_email
    ok = send_alert_email(
        subject=f"[TEST] {alert_type.upper()} alert — REFORMMED",
        body=f"This is a test alert for type '{alert_type}'.\nSent from REFORMMED Monitor.",
        recipients=config["notify_emails"],
    )
    if ok:
        flash(f"Test email sent for '{alert_type}'.", "success")
    else:
        flash(f"Failed to send test email (check SMTP config).", "danger")

    return redirect(url_for("alerts.index"))


@alerts_bp.route("/log/clear", methods=["POST"])
@login_required
def clear_log():
    if not current_user.is_admin:
        abort(403)
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM alert_log")
    flash("Alert log cleared.", "success")
    return redirect(url_for("alerts.index"))
