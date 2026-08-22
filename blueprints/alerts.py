"""
Alerts blueprint — unified system + DVR + DB monitor alerts.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, jsonify
from flask_login import login_required, current_user
from db import get_db, list_alert_recipients

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        # System alert configs
        cur.execute("SELECT * FROM alert_config ORDER BY id")
        configs = cur.fetchall()
        # Unified alert log (all sources)
        cur.execute("SELECT * FROM alert_log ORDER BY sent_at DESC LIMIT 200")
        logs = cur.fetchall()
        # DVR settings for DVR alerts tab
        cur.execute("SELECT key, value FROM dvr_settings")
        dvr_raw = cur.fetchall()
        dvr_settings = {r["key"]: r["value"] for r in dvr_raw}
        # DB monitor watches for DB alerts tab
        cur.execute("""
            SELECT w.*, c.name AS conn_name
            FROM dbmon_watches w
            JOIN dbmon_connections c ON c.id = w.conn_id
            ORDER BY c.name, w.display_name
        """)
        dbmon_watches = cur.fetchall()
        # Machines (for the "add machine alert" picker) + existing overrides
        cur.execute("""
            SELECT system_name, location, table_name FROM machine_registry
            ORDER BY system_name
        """)
        machines = cur.fetchall()
        cur.execute("""
            SELECT o.*, m.system_name, m.location
            FROM machine_alert_overrides o
            LEFT JOIN machine_registry m ON m.table_name = o.table_name
            ORDER BY m.system_name, o.alert_type
        """)
        machine_overrides = cur.fetchall()

    return render_template("alerts.html",
                           configs=configs,
                           logs=logs,
                           dvr_settings=dvr_settings,
                           dbmon_watches=dbmon_watches,
                           machines=machines,
                           machine_overrides=machine_overrides,
                           recipients=list_alert_recipients())


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
            aid      = row["id"]
            atype    = row["alert_type"]
            enabled  = request.form.get(f"enabled_{aid}") == "1"
            threshold = request.form.get(f"threshold_{aid}", "").strip() or None
            cooldown  = request.form.get(f"cooldown_{aid}", "10").strip()
            emails    = ", ".join(request.form.getlist(f"emails_{aid}"))
            try:
                thresh_val   = float(threshold) if threshold else None
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
    flash("System alert configuration saved.", "success")
    return redirect(url_for("alerts.index") + "#system")


@alerts_bp.route("/machine/add", methods=["POST"])
@login_required
def add_machine_alert():
    """
    Create or update a per-machine alert override. A row for
    (table_name, alert_type) takes precedence over the fleet-wide
    alert_config rule of the same type, for that one machine only.
    """
    if not current_user.is_admin:
        abort(403)
    table_name = request.form.get("table_name", "").strip()
    atype      = request.form.get("alert_type", "").strip()
    if not table_name or not atype:
        flash("Pick a machine and an alert type.", "danger")
        return redirect(url_for("alerts.index") + "#machine")

    enabled   = request.form.get("enabled") == "1"
    threshold = request.form.get("threshold", "").strip() or None
    cooldown  = request.form.get("cooldown_minutes", "10").strip()
    emails    = ", ".join(request.form.getlist("recipient_emails"))

    try:
        thresh_val   = float(threshold) if threshold else None
        cooldown_val = int(cooldown)
    except ValueError:
        flash("Invalid threshold or cooldown value.", "danger")
        return redirect(url_for("alerts.index") + "#machine")

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO machine_alert_overrides
                (table_name, alert_type, enabled, threshold, cooldown_minutes, notify_emails, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (table_name, alert_type) DO UPDATE
            SET enabled=EXCLUDED.enabled, threshold=EXCLUDED.threshold,
                cooldown_minutes=EXCLUDED.cooldown_minutes, notify_emails=EXCLUDED.notify_emails,
                updated_at=NOW()
        """, (table_name, atype, enabled, thresh_val, cooldown_val, emails))
    flash(f"Machine alert rule saved for {atype}.", "success")
    return redirect(url_for("alerts.index") + "#machine")


@alerts_bp.route("/machine/<int:override_id>/delete", methods=["POST"])
@login_required
def delete_machine_alert(override_id):
    if not current_user.is_admin:
        abort(403)
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM machine_alert_overrides WHERE id=%s", (override_id,))
    flash("Machine alert rule removed.", "success")
    return redirect(url_for("alerts.index") + "#machine")


@alerts_bp.route("/dvr/update", methods=["POST"])
@login_required
def update_dvr():
    if not current_user.is_admin:
        abort(403)
    with get_db() as conn:
        cur = conn.cursor()
        for k in ("ping_interval_sec", "alerts_enabled"):
            v = request.form.get(k, "").strip()
            if v is not None:
                cur.execute("""
                    INSERT INTO dvr_settings (key, value) VALUES (%s, %s)
                    ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
                """, (k, v))
        emails = ", ".join(request.form.getlist("recipient_emails"))
        cur.execute("""
            INSERT INTO dvr_settings (key, value) VALUES ('alert_emails', %s)
            ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
        """, (emails,))
    flash("DVR alert settings saved.", "success")
    return redirect(url_for("alerts.index") + "#dvr")


@alerts_bp.route("/dbmon/watch/<int:watch_id>/update", methods=["POST"])
@login_required
def update_dbmon_watch(watch_id):
    if not current_user.is_admin:
        abort(403)
    alerts_enabled = request.form.get("alerts_enabled") == "1"
    monitoring     = request.form.get("monitoring") == "1"
    alert_emails   = ", ".join(request.form.getlist("recipient_emails"))
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE dbmon_watches
            SET alerts_enabled=%s, monitoring=%s, alert_emails=%s
            WHERE id=%s
        """, (alerts_enabled, monitoring, alert_emails, watch_id))
    flash("DB Monitor watch updated.", "success")
    return redirect(url_for("alerts.index") + "#dbmon")


@alerts_bp.route("/test/<alert_type>", methods=["POST"])
@login_required
def test_alert(alert_type):
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
    flash(f"Test email {'sent' if ok else 'failed'} for '{alert_type}'.", "success" if ok else "danger")
    return redirect(url_for("alerts.index") + "#system")


@alerts_bp.route("/log/clear", methods=["POST"])
@login_required
def clear_log():
    if not current_user.is_admin:
        abort(403)
    source = request.form.get("source", "all")
    with get_db() as conn:
        cur = conn.cursor()
        if source == "all":
            cur.execute("DELETE FROM alert_log")
        else:
            cur.execute("DELETE FROM alert_log WHERE source=%s", (source,))
    flash(f"Alert log cleared ({source}).", "success")
    return redirect(url_for("alerts.index") + "#log")