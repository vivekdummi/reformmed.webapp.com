"""
DVR Monitor — Hospital > Location > DVR hierarchy
Ping-based online/offline detection with email alerts.
"""
import os, ssl, smtplib, asyncio, subprocess
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from db import get_db, list_alert_recipients

dvr_bp = Blueprint("dvr", __name__, url_prefix="/dvr")

def _admin_required():
    if not current_user.is_admin:
        abort(403)


@dvr_bp.before_request
def _require_dvr_feature():
    """
    can_view_dvr previously only hid the nav link — a logged-in user without
    it could still hit /dvr/... directly. Enforce it here so 'give a user
    access to only DVR Monitor' (or the reverse: block DVR entirely) actually
    works at the route level, not just in the sidebar.
    """
    if current_user.is_authenticated and not (current_user.is_admin or current_user.can_view_dvr):
        abort(403)


def _check_hospital_access(hospital_id):
    """Abort 403 if the current user isn't allowed to view this hospital."""
    if current_user.is_admin:
        return
    allowed = current_user.allowed_hospitals()
    if allowed is not None and hospital_id not in allowed:
        abort(403)

def init_dvr_tables():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dvr_hospitals (
                id         SERIAL PRIMARY KEY,
                name       TEXT UNIQUE NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dvr_locations (
                id          SERIAL PRIMARY KEY,
                hospital_id INTEGER REFERENCES dvr_hospitals(id) ON DELETE CASCADE,
                name        TEXT NOT NULL,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(hospital_id, name)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dvr_devices (
                id           SERIAL PRIMARY KEY,
                location_id  INTEGER REFERENCES dvr_locations(id) ON DELETE CASCADE,
                name         TEXT NOT NULL,
                ip           TEXT NOT NULL,
                port         INTEGER NOT NULL DEFAULT 80,
                status       TEXT NOT NULL DEFAULT 'unknown',
                last_seen    TIMESTAMPTZ,
                went_offline TIMESTAMPTZ,
                alert_sent   BOOLEAN NOT NULL DEFAULT FALSE,
                created_at   TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dvr_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        # Default settings
        for k, v in [("ping_interval_sec","30"),("alert_emails",""),("alerts_enabled","1")]:
            cur.execute("""
                INSERT INTO dvr_settings (key,value) VALUES (%s,%s)
                ON CONFLICT (key) DO NOTHING
            """, (k, v))


def get_setting(key, default=""):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM dvr_settings WHERE key=%s", (key,))
        row = cur.fetchone()
    return row["value"] if row else default


def _ping(ip, port, timeout=3):
    """Try TCP connect to ip:port. Returns True if reachable."""
    import socket
    try:
        sock = socket.create_connection((ip, int(port)), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


# Same accent-color / icon scheme as the server offline_checker alert cards,
# so DVR emails look like siblings of the server alerts instead of a
# different, plain-text system.
_ALERT_STYLE = {
    "offline": ("#e5484d", "🔴", "DVR OFFLINE"),
    "online":  ("#2fb344", "🟢", "DVR ONLINE"),
}


def _render_dvr_alert(kind, hospital, location, dvr_name, ip, port, rows, now=None):
    """
    Build (subject, plain_text, html) for a DVR alert — mirrors
    offline_checker.py's _render_alert() card layout (colored header,
    icon, key/value table, footer) so DVR and server alerts look alike.
    rows: extra ordered (label, value) pairs, e.g. [("Last seen", "...")]
    """
    color, icon, label = _ALERT_STYLE.get(kind, ("#6b7280", "⚠️", kind.upper()))
    now = now or datetime.now(timezone.utc)
    subject = f"{icon} {label} — {dvr_name} ({hospital})"

    all_rows = [
        ("Hospital", hospital),
        ("Location", location),
        ("DVR", dvr_name),
        ("Address", f"{ip}:{port}"),
    ] + rows + [("Time", now.strftime("%d %b %Y, %I:%M %p"))]

    plain_lines = [f"{label} — {dvr_name} ({hospital})", ""]
    plain_lines += [f"{lbl}: {val}" for lbl, val in all_rows]
    plain = "\n".join(plain_lines)

    html_rows = "".join(
        f'<tr>'
        f'<td style="padding:7px 0;color:#8a8f98;font-size:13px;width:120px;">{lbl}</td>'
        f'<td style="padding:7px 0;color:#1c1e21;font-size:13px;font-weight:600;">{val}</td>'
        f'</tr>'
        for lbl, val in all_rows
    )
    html = f"""\
<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:480px;margin:0 auto;
            border:1px solid #e6e6e9;border-radius:10px;overflow:hidden;">
  <div style="background:{color};padding:16px 22px;">
    <span style="color:#ffffff;font-size:15px;font-weight:700;letter-spacing:.2px;">
      {icon}&nbsp; {label}
    </span>
  </div>
  <div style="padding:20px 22px;background:#ffffff;">
    <table style="width:100%;border-collapse:collapse;">{html_rows}</table>
  </div>
  <div style="background:#f7f7f9;padding:10px 22px;border-top:1px solid #eee;">
    <span style="font-size:11px;color:#a0a4ab;">REFORMMED Monitor · automated alert</span>
  </div>
</div>
"""
    return subject, plain, html


def _send_alert(kind, hospital, location, dvr_name, ip, port, rows=None, machine_key="dvr"):
    """Send the styled DVR alert email and log it to the unified alert_log."""
    subject, plain, html = _render_dvr_alert(kind, hospital, location, dvr_name, ip, port, rows or [])

    emails = get_setting("alert_emails", "")
    gmail_user = os.getenv("GMAIL_USER", "")
    gmail_pass = os.getenv("GMAIL_APP_PASS", "")
    recipients = [e.strip() for e in emails.split(",") if e.strip()]
    ok = False
    if gmail_user and gmail_pass and recipients:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[REFORMMED] {subject}"
            msg["From"] = gmail_user
            msg["To"] = ", ".join(recipients)
            msg.attach(MIMEText(plain, "plain"))
            msg.attach(MIMEText(html, "html"))
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(os.getenv("SMTP_HOST", "smtp.gmail.com"),
                                   int(os.getenv("SMTP_PORT", "465")), context=ctx) as srv:
                srv.login(gmail_user, gmail_pass)
                srv.sendmail(gmail_user, recipients, msg.as_string())
            ok = True
        except Exception as e:
            print(f"DVR alert failed: {e}")
    # Log to unified alert_log
    try:
        with get_db() as conn:
            conn.cursor().execute("""
                INSERT INTO alert_log (alert_type, source, machine_key, subject, body, success)
                VALUES ('dvr_offline', 'dvr', %s, %s, %s, %s)
            """, (machine_key, subject, plain, ok))
    except Exception as e:
        print(f"DVR alert_log write failed: {e}")
    return ok


# ── Pages ──────────────────────────────────────────────────────────────────

@dvr_bp.route("/")
@login_required
def index():
    """Hospital list with summary counts — scoped to this user's allowed hospitals."""
    allowed = current_user.allowed_hospitals()  # None = admin sees all
    with get_db() as conn:
        cur = conn.cursor()
        base_sql = """
            SELECT h.*,
                COUNT(DISTINCT l.id) as loc_count,
                COUNT(DISTINCT d.id) as dvr_total,
                SUM(CASE WHEN d.status='online'  THEN 1 ELSE 0 END) as dvr_online,
                SUM(CASE WHEN d.status='offline' THEN 1 ELSE 0 END) as dvr_offline
            FROM dvr_hospitals h
            LEFT JOIN dvr_locations l ON l.hospital_id=h.id
            LEFT JOIN dvr_devices d ON d.location_id=l.id
        """
        if allowed is None:
            cur.execute(base_sql + " GROUP BY h.id ORDER BY h.name")
            hospitals = cur.fetchall()
        elif not allowed:
            hospitals = []
        else:
            cur.execute(base_sql + " WHERE h.id = ANY(%s) GROUP BY h.id ORDER BY h.name",
                        (list(allowed),))
            hospitals = cur.fetchall()

        # Overall summary — scoped the same way, so a restricted user's
        # totals reflect only the hospitals they're allowed to see.
        if allowed is None:
            cur.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) as online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) as offline,
                    SUM(CASE WHEN status='unknown' THEN 1 ELSE 0 END) as unknown
                FROM dvr_devices
            """)
            summary = cur.fetchone()
        elif not allowed:
            summary = {"total": 0, "online": 0, "offline": 0, "unknown": 0}
        else:
            cur.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN d.status='online'  THEN 1 ELSE 0 END) as online,
                    SUM(CASE WHEN d.status='offline' THEN 1 ELSE 0 END) as offline,
                    SUM(CASE WHEN d.status='unknown' THEN 1 ELSE 0 END) as unknown
                FROM dvr_devices d
                JOIN dvr_locations l ON l.id=d.location_id
                WHERE l.hospital_id = ANY(%s)
            """, (list(allowed),))
            summary = cur.fetchone()
    settings = {
        "ping_interval_sec": get_setting("ping_interval_sec","30"),
        "alert_emails": get_setting("alert_emails",""),
        "alerts_enabled": get_setting("alerts_enabled","1"),
    }
    return render_template("dvr_index.html", hospitals=hospitals, summary=summary, settings=settings)


@dvr_bp.route("/hospital/<int:hid>")
@login_required
def hospital(hid):
    """Hospital dashboard — locations + DVR status."""
    _check_hospital_access(hid)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM dvr_hospitals WHERE id=%s", (hid,))
        hosp = cur.fetchone()
        if not hosp:
            abort(404)
        cur.execute("""
            SELECT l.*,
                COUNT(d.id) as dvr_total,
                SUM(CASE WHEN d.status='online'  THEN 1 ELSE 0 END) as dvr_online,
                SUM(CASE WHEN d.status='offline' THEN 1 ELSE 0 END) as dvr_offline
            FROM dvr_locations l
            LEFT JOIN dvr_devices d ON d.location_id=l.id
            WHERE l.hospital_id=%s
            GROUP BY l.id ORDER BY l.name
        """, (hid,))
        locations = cur.fetchall()
        cur.execute("""
            SELECT d.*, l.name as loc_name
            FROM dvr_devices d
            JOIN dvr_locations l ON l.id=d.location_id
            WHERE l.hospital_id=%s
            ORDER BY l.name, d.name
        """, (hid,))
        devices = cur.fetchall()
    return render_template("dvr_hospital.html", hosp=hosp, locations=locations, devices=devices)


@dvr_bp.route("/settings", methods=["GET","POST"])
@login_required
def settings():
    _admin_required()
    if request.method == "POST":
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE dvr_settings SET value=%s WHERE key=%s",
                        (request.form.get("ping_interval_sec","").strip(), "ping_interval_sec"))
            cur.execute("UPDATE dvr_settings SET value=%s WHERE key=%s",
                        (request.form.get("alerts_enabled","").strip(), "alerts_enabled"))
            emails = ", ".join(request.form.getlist("recipient_emails"))
            cur.execute("UPDATE dvr_settings SET value=%s WHERE key=%s",
                        (emails, "alert_emails"))
        flash("Settings saved.", "success")
        return redirect(url_for("dvr.settings"))
    settings_data = {
        "ping_interval_sec": get_setting("ping_interval_sec","30"),
        "alert_emails": get_setting("alert_emails",""),
        "alerts_enabled": get_setting("alerts_enabled","1"),
    }
    return render_template("dvr_settings.html", settings=settings_data, recipients=list_alert_recipients())


# ── CRUD ───────────────────────────────────────────────────────────────────

@dvr_bp.route("/hospital/add", methods=["POST"])
@login_required
def add_hospital():
    _admin_required()
    name = request.form.get("name","").strip()
    if not name:
        flash("Name required.", "danger")
        return redirect(url_for("dvr.index"))
    try:
        with get_db() as conn:
            conn.cursor().execute("INSERT INTO dvr_hospitals (name) VALUES (%s)", (name,))
        flash(f"Hospital '{name}' created.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dvr.index"))


@dvr_bp.route("/hospital/<int:hid>/delete", methods=["POST"])
@login_required
def delete_hospital(hid):
    _admin_required()
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM dvr_hospitals WHERE id=%s", (hid,))
    flash("Hospital deleted.", "success")
    return redirect(url_for("dvr.index"))


@dvr_bp.route("/hospital/<int:hid>/location/add", methods=["POST"])
@login_required
def add_location(hid):
    _admin_required()
    name = request.form.get("name","").strip()
    try:
        with get_db() as conn:
            conn.cursor().execute(
                "INSERT INTO dvr_locations (hospital_id,name) VALUES (%s,%s)", (hid,name))
        flash(f"Location '{name}' added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dvr.hospital", hid=hid))


@dvr_bp.route("/location/<int:lid>/delete", methods=["POST"])
@login_required
def delete_location(lid):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT hospital_id FROM dvr_locations WHERE id=%s", (lid,))
        row = cur.fetchone()
        cur.execute("DELETE FROM dvr_locations WHERE id=%s", (lid,))
    flash("Location deleted.", "success")
    return redirect(url_for("dvr.hospital", hid=row["hospital_id"]) if row else url_for("dvr.index"))


@dvr_bp.route("/location/<int:lid>/dvr/add", methods=["POST"])
@login_required
def add_dvr(lid):
    _admin_required()
    f = request.form
    try:
        with get_db() as conn:
            conn.cursor().execute("""
                INSERT INTO dvr_devices (location_id, name, ip, port)
                VALUES (%s,%s,%s,%s)
            """, (lid, f["name"].strip(), f["ip"].strip(), int(f.get("port",80))))
        flash("DVR added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT hospital_id FROM dvr_locations WHERE id=%s", (lid,))
        row = cur.fetchone()
    return redirect(url_for("dvr.hospital", hid=row["hospital_id"]) if row else url_for("dvr.index"))


@dvr_bp.route("/dvr/<int:did>/delete", methods=["POST"])
@login_required
def delete_dvr(did):
    _admin_required()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT l.hospital_id FROM dvr_devices d
            JOIN dvr_locations l ON l.id=d.location_id WHERE d.id=%s
        """, (did,))
        row = cur.fetchone()
        cur.execute("DELETE FROM dvr_devices WHERE id=%s", (did,))
    return redirect(url_for("dvr.hospital", hid=row["hospital_id"]) if row else url_for("dvr.index"))


# ── Ping API ───────────────────────────────────────────────────────────────

@dvr_bp.route("/dvr/<int:did>/ping")
@login_required
def ping_dvr(did):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT d.*, l.hospital_id, l.name as loc_name, h.name as hosp_name
            FROM dvr_devices d
            JOIN dvr_locations l ON l.id=d.location_id
            JOIN dvr_hospitals h ON h.id=l.hospital_id
            WHERE d.id=%s
        """, (did,))
        dev = cur.fetchone()
    if not dev:
        return jsonify({"error":"not found"}), 404
    _check_hospital_access(dev["hospital_id"])

    now    = datetime.now(timezone.utc)
    online = _ping(dev["ip"], dev["port"])
    status = "online" if online else "offline"
    alerts_enabled = get_setting("alerts_enabled","1") == "1"

    with get_db() as conn:
        cur = conn.cursor()
        prev_status  = dev["status"]
        went_offline = dev["went_offline"]
        alert_sent   = dev["alert_sent"]

        if status == "offline" and prev_status != "offline":
            went_offline = now
            alert_sent   = False

        if status == "online" and prev_status == "offline":
            offline_since = went_offline  # capture before we clear it below
            went_offline = None
            alert_sent   = False
            if alerts_enabled:
                _send_alert(
                    "online", dev["hosp_name"], dev["loc_name"], dev["name"],
                    dev["ip"], dev["port"],
                    rows=[("Was offline since", offline_since.strftime("%d %b %Y, %I:%M %p") if offline_since else "unknown")],
                    machine_key=f"{dev['name']}@{dev['ip']}"
                )

        if status == "offline" and not alert_sent and alerts_enabled:
            ok = _send_alert(
                "offline", dev["hosp_name"], dev["loc_name"], dev["name"],
                dev["ip"], dev["port"],
                rows=[("Last seen", dev["last_seen"].strftime("%d %b %Y, %I:%M %p") if dev["last_seen"] else "never")],
                machine_key=f"{dev['name']}@{dev['ip']}"
            )
            if ok:
                alert_sent = True

        cur.execute("""
            UPDATE dvr_devices SET status=%s,
                last_seen=%s,
                went_offline=%s,
                alert_sent=%s
            WHERE id=%s
        """, (status,
              now if online else dev["last_seen"],
              went_offline,
              alert_sent, did))

    return jsonify({
        "id": did, "status": status,
        "ip": dev["ip"], "port": dev["port"],
        "last_seen": dev["last_seen"].isoformat() if dev["last_seen"] else None,
        "went_offline": went_offline.isoformat() if went_offline else None,
    })


@dvr_bp.route("/ping/all")
@login_required
def ping_all_ids():
    """Return device IDs for the frontend to ping — scoped to allowed hospitals."""
    allowed = current_user.allowed_hospitals()
    with get_db() as conn:
        cur = conn.cursor()
        if allowed is None:
            cur.execute("SELECT id FROM dvr_devices ORDER BY id")
        elif not allowed:
            cur.execute("SELECT id FROM dvr_devices WHERE FALSE")
        else:
            cur.execute("""
                SELECT d.id FROM dvr_devices d
                JOIN dvr_locations l ON l.id=d.location_id
                WHERE l.hospital_id = ANY(%s) ORDER BY d.id
            """, (list(allowed),))
        ids = [r["id"] for r in cur.fetchall()]
    interval = int(get_setting("ping_interval_sec","30"))
    return jsonify({"ids": ids, "interval": interval})