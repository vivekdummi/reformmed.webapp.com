"""
Alerts blueprint — unified system + DB monitor alerts (DVR alerts are no longer shown).
"""
import os

from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, jsonify
from flask_login import login_required, current_user
from db import get_db, list_alert_recipients

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.before_request
def _require_alerts_feature():
    """can_view_alerts used to only hide the nav link — enforce it on the routes too."""
    if current_user.is_authenticated and not (current_user.is_admin or current_user.can_view_alerts):
        abort(403)


OVERVIEW_DAYS = 14


def _visible_log_filter(cur):
    """Returns a predicate for alert_log rows this user may see: admins see
    everything; others only their own servers' alerts (+ DB Monitor alerts
    with that permission). DVR alerts are hidden — that feature was removed."""
    allowed = current_user.allowed_servers()
    keys = None
    if allowed is not None:
        cur.execute("SELECT system_name, location, table_name FROM machine_registry")
        keys = {f"{r['system_name']}@{r['location']}" for r in cur.fetchall() if r["table_name"] in allowed}
    can_db = current_user.is_admin or current_user.can_view_dbmon

    def visible(row):
        src = row.get("source") or "system"
        if src == "dvr":
            return False
        if src == "dbmonitor":
            return can_db
        return keys is None or row.get("machine_key") in keys
    return visible


def _alert_overview(cur, visible):
    """KPIs + chart data for the overview strip: per-day counts by alert type
    for the last OVERVIEW_DAYS days (IST — the DB session timezone)."""
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    cur.execute("""
        SELECT sent_at::date AS d, COALESCE(source,'system') AS source,
               split_part(alert_type, ':', 1) AS atype, machine_key, success,
               sent_at::date = CURRENT_DATE AS is_today,
               sent_at >= NOW() - INTERVAL '7 days' AS in_7d
        FROM alert_log
        WHERE sent_at >= date_trunc('day', NOW()) - make_interval(days => %s)
        LIMIT 50000
    """, (OVERVIEW_DAYS - 1,))
    today = datetime.now(ZoneInfo("Asia/Kolkata")).date()
    days = [today - timedelta(days=i) for i in range(OVERVIEW_DAYS - 1, -1, -1)]
    idx = {d: i for i, d in enumerate(days)}
    per_type, totals = {}, {}
    k = {"today": 0, "week": 0, "sent": 0, "failed": 0}
    for r in cur.fetchall():
        if not visible(r):
            continue
        t = r["atype"] or "other"
        i = idx.get(r["d"])
        if i is not None:
            per_type.setdefault(t, [0] * OVERVIEW_DAYS)[i] += 1
        totals[t] = totals.get(t, 0) + 1
        if r["is_today"]:
            k["today"] += 1
        if r["in_7d"]:
            k["week"] += 1
            k["sent" if r["success"] else "failed"] += 1
    ranked = sorted(totals, key=lambda t: -totals[t])
    # Keep the five biggest types; fold the rest into "other"
    if len(ranked) > 5:
        other = [0] * OVERVIEW_DAYS
        for t in ranked[4:]:
            other = [a + b for a, b in zip(other, per_type.get(t, [0] * OVERVIEW_DAYS))]
        series = [{"type": t, "data": per_type.get(t, [0] * OVERVIEW_DAYS), "total": totals[t]} for t in ranked[:4]]
        series.append({"type": "other", "data": other, "total": sum(totals[t] for t in ranked[4:])})
    else:
        series = [{"type": t, "data": per_type.get(t, [0] * OVERVIEW_DAYS), "total": totals[t]} for t in ranked]
    week_total = k["sent"] + k["failed"]
    return {
        "labels": [d.strftime("%d %b") for d in days],
        "series": series,
        "total": sum(totals.values()),
        "today": k["today"], "week": k["week"],
        "sent": k["sent"], "failed": k["failed"],
        "delivered_pct": round(k["sent"] / week_total * 100) if week_total else None,
    }


@alerts_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        # System alert configs
        cur.execute("SELECT * FROM alert_config ORDER BY id")
        configs = cur.fetchall()
        visible = _visible_log_filter(cur)
        # Unified alert log (no DVR — that feature was removed from the app)
        cur.execute("""
            SELECT * FROM alert_log
            WHERE COALESCE(source,'system') <> 'dvr'
            ORDER BY sent_at DESC LIMIT 500
        """)
        logs = [r for r in cur.fetchall() if visible(r)]
        overview = _alert_overview(cur, visible)
        # DB monitor watches for DB alerts tab
        cur.execute("""
            SELECT w.*, c.name AS conn_name
            FROM dbmon_watches w
            JOIN dbmon_connections c ON c.id = w.conn_id
            ORDER BY c.name, w.display_name
        """)
        dbmon_watches = cur.fetchall()
        if not (current_user.is_admin or current_user.can_view_dbmon):
            dbmon_watches = []
        # Machines (for the "add machine alert" picker) + existing overrides
        cur.execute("""
            SELECT system_name, location, table_name, alerts_enabled FROM machine_registry
            ORDER BY system_name
        """)
        machines = cur.fetchall()
        allowed = current_user.allowed_servers()
        if allowed is not None:
            machines = [m for m in machines if m["table_name"] in allowed]
        cur.execute("""
            SELECT o.*, m.system_name, m.location
            FROM machine_alert_overrides o
            LEFT JOIN machine_registry m ON m.table_name = o.table_name
            ORDER BY m.system_name, o.alert_type
        """)
        machine_overrides = cur.fetchall()
        if allowed is not None:
            machine_overrides = [o for o in machine_overrides if o["table_name"] in allowed]

    overview["rules_on"] = sum(1 for c in configs if c["enabled"])
    overview["rules_total"] = len(configs)
    overview["muted"] = sum(1 for m in machines if not m["alerts_enabled"])
    overview["overridden"] = len({o["table_name"] for o in machine_overrides})

    return render_template("alerts.html",
                           configs=configs,
                           logs=logs,
                           overview=overview,
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
            try:
                thresh_val   = float(threshold) if threshold else None
                cooldown_val = int(cooldown)
            except ValueError:
                flash(f"Invalid value for {atype}.", "danger")
                return redirect(url_for("alerts.index"))
            # Notify Emails is no longer set here — recipients are chosen
            # per-machine in the Machine Alerts tab instead. This only
            # touches enabled/threshold/cooldown, which stay fleet-wide.
            cur.execute("""
                UPDATE alert_config
                SET enabled=%s, threshold=%s, cooldown_minutes=%s, updated_at=NOW()
                WHERE id=%s
            """, (enabled, thresh_val, cooldown_val, aid))
    flash("System alert configuration saved.", "success")
    return redirect(url_for("alerts.index") + "#system")


@alerts_bp.route("/machine/<table_name>/overrides")
@login_required
def machine_overrides_json(table_name):
    """
    Per-machine alert routing for one machine. Only 'enabled' and
    'notify_emails' are configurable per machine — threshold and cooldown
    always come from the fleet-wide System Alerts config (see alert_config),
    not from here.
    """
    if not current_user.is_admin:
        abort(403)
    types = ["offline", "online", "cpu", "ram", "disk", "temp"]
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT alert_type, enabled FROM alert_config")
        global_cfg = {r["alert_type"]: r for r in cur.fetchall()}
        cur.execute("SELECT * FROM machine_alert_overrides WHERE table_name=%s", (table_name,))
        existing = {r["alert_type"]: r for r in cur.fetchall()}

    out = []
    for t in types:
        o = existing.get(t)
        g = global_cfg.get(t, {})
        out.append({
            "alert_type": t,
            "enabled": bool(o["enabled"]) if o else bool(g.get("enabled", True)),
            "notify_emails": (o["notify_emails"] if o else "") or "",
            "has_override": o is not None,
        })
    return jsonify(out)


@alerts_bp.route("/machine/<table_name>/save-all", methods=["POST"])
@login_required
def save_machine_alerts_all(table_name):
    """
    Bulk-save the per-machine routing (enabled + recipients) for all six
    alert types in one go. Threshold/cooldown aren't set here — those stay
    fleet-wide, configured once in System Alerts.
    """
    if not current_user.is_admin:
        abort(403)
    types = ["offline", "online", "cpu", "ram", "disk", "temp"]
    with get_db() as conn:
        cur = conn.cursor()
        for t in types:
            enabled = request.form.get(f"enabled_{t}") == "1"
            emails  = ", ".join(request.form.getlist(f"emails_{t}"))
            cur.execute("""
                INSERT INTO machine_alert_overrides
                    (table_name, alert_type, enabled, notify_emails, updated_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (table_name, alert_type) DO UPDATE
                SET enabled=EXCLUDED.enabled, notify_emails=EXCLUDED.notify_emails,
                    updated_at=NOW()
            """, (table_name, t, enabled, emails))
    flash("Machine alert rules saved.", "success")
    return redirect(url_for("alerts.index") + "#machine")


@alerts_bp.route("/machine/add", methods=["POST"])
@login_required
def add_machine_alert():
    """
    Create or update a per-machine alert override (enabled + recipients
    only — threshold/cooldown stay fleet-wide, set once in System Alerts).
    """
    if not current_user.is_admin:
        abort(403)
    table_name = request.form.get("table_name", "").strip()
    atype      = request.form.get("alert_type", "").strip()
    if not table_name or not atype:
        flash("Pick a machine and an alert type.", "danger")
        return redirect(url_for("alerts.index") + "#machine")

    enabled = request.form.get("enabled") == "1"
    emails  = ", ".join(request.form.getlist("recipient_emails"))

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO machine_alert_overrides
                (table_name, alert_type, enabled, notify_emails, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (table_name, alert_type) DO UPDATE
            SET enabled=EXCLUDED.enabled, notify_emails=EXCLUDED.notify_emails,
                updated_at=NOW()
        """, (table_name, atype, enabled, emails))
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
    # Global notify_emails is no longer editable in the UI, so fall back to
    # ALERT_TO and then to every registered recipient.
    recipients = (config.get("notify_emails") or os.getenv("ALERT_TO", "")
                  or ", ".join(r["email"] for r in list_alert_recipients()))
    ok = send_alert_email(
        subject=f"[TEST] {alert_type.upper()} alert — Reformmed INFRA Monitor",
        body=f"This is a test alert for type '{alert_type}'.\nSent from Reformmed INFRA Monitor.",
        recipients=recipients,
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