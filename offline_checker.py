"""
REFORMMED Offline Checker + Alerter (v2 — DB-driven config)
Reads thresholds and recipients from the alert_config table (managed via webapp).
Falls back to env vars if table not yet populated.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import asyncpg

IST = ZoneInfo("Asia/Kolkata")


def _fmt_ist(dt: datetime) -> str:
    """Format a UTC-aware datetime as an IST string, e.g. '04 Aug 2026, 03:13 PM IST'."""
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST).strftime("%d %b %Y, %I:%M %p IST")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CHECKER] %(message)s")
log = logging.getLogger("checker")

# ── DB config ────────────────────────────────────────────────────────────────
DB_HOST = os.getenv("POSTGRES_HOST", "reformmed_postgres")
DB_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME = os.getenv("POSTGRES_DB", "monitor_machine")
DB_USER = os.getenv("POSTGRES_USER", "admin")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "")

OFFLINE_THRESHOLD_SECS = int(os.getenv("OFFLINE_AFTER_SECS", "60"))
CHECK_INTERVAL_SECS    = int(os.getenv("CHECK_INTERVAL_SECS", "15"))

SKIP_MOUNT_PREFIXES = ("/snap/", "/proc", "/sys", "/dev", "/run")

# ── cooldown tracker ─────────────────────────────────────────────────────────
_last_alert: dict[tuple, datetime] = {}


def _cooldown_ok(machine_key: str, alert_type: str, cooldown_mins: int) -> bool:
    key  = (machine_key, alert_type)
    last = _last_alert.get(key)
    if last is None:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() > cooldown_mins * 60


def _mark_sent(machine_key: str, alert_type: str):
    _last_alert[(machine_key, alert_type)] = datetime.now(timezone.utc)


# ── email ────────────────────────────────────────────────────────────────────
import ssl, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_PASS = os.getenv("GMAIL_APP_PASS", "")
SMTP_HOST  = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(os.getenv("SMTP_PORT", "465"))

# Per-alert-type look (accent color + icon) for the HTML card
_ALERT_STYLE = {
    "offline": ("#e5484d", "🔴", "OFFLINE"),
    "online":  ("#2fb344", "🟢", "ONLINE"),
    "cpu":     ("#f0883e", "🔥", "HIGH CPU"),
    "ram":     ("#f0883e", "🧠", "HIGH RAM"),
    "temp":    ("#f0883e", "🌡️", "HIGH TEMP"),
    "disk":    ("#f0883e", "💿", "DISK FULL"),
}


def _style_for(alert_type: str):
    base_type = alert_type.split(":", 1)[0]  # "disk:/mount" → "disk"
    return _ALERT_STYLE.get(base_type, ("#6b7280", "⚠️", alert_type.upper()))


def _render_alert(alert_type: str, system_name: str, location: str,
                   rows: list[tuple[str, str]], now: datetime = None) -> tuple[str, str, str]:
    """
    Build (subject, plain_text, html) for an alert.
    rows: ordered list of (label, value) pairs shown in the email body,
          e.g. [("Last seen", "..."), ("Threshold", "90%")]
    """
    color, icon, label = _style_for(alert_type)
    now = now or datetime.now(timezone.utc)
    subject = f"{icon} {label} — {system_name} ({location})"

    all_rows = [("Machine", system_name), ("Location", location)] + rows + \
               [("Time", _fmt_ist(now))]

    plain_lines = [f"{label} — {system_name} ({location})", ""]
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


def _send_email(subject: str, plain: str, html: str, to_list: list[str]) -> bool:
    if not GMAIL_USER or not GMAIL_PASS or not to_list:
        log.warning("Email not configured or no recipients — skipping: %s", subject)
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[REFORMMED] {subject}"
        msg["From"]    = GMAIL_USER
        msg["To"]      = ", ".join(to_list)
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html, "html"))
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as srv:
            srv.login(GMAIL_USER, GMAIL_PASS)
            srv.sendmail(GMAIL_USER, to_list, msg.as_string())
        log.info("📧 Alert sent: %s", subject)
        return True
    except Exception as e:
        log.error("Email failed: %s", e)
        return False


async def _log_alert(conn, alert_type, machine_key, subject, body, success):
    try:
        await conn.execute("""
            INSERT INTO alert_log (alert_type, machine_key, subject, body, success)
            VALUES ($1,$2,$3,$4,$5)
        """, alert_type, machine_key, subject, body, success)
    except Exception as e:
        log.error("alert_log write failed: %s", e)


async def _get_alert_config(conn) -> dict:
    """Load alert config from DB into a dict keyed by alert_type."""
    rows = await conn.fetch("SELECT * FROM alert_config")
    return {r["alert_type"]: dict(r) for r in rows}


def _recipients(config: dict, atype: str) -> list[str]:
    cfg = config.get(atype, {})
    emails = cfg.get("notify_emails", "") or os.getenv("ALERT_TO", "")
    return [e.strip() for e in emails.split(",") if e.strip()]


async def _alert(conn, config: dict, machine_key: str, alert_type: str,
                  system_name: str, location: str, rows: list[tuple[str, str]]):
    cfg = config.get(alert_type, {})
    if not cfg.get("enabled", True):
        return
    cooldown = cfg.get("cooldown_minutes", 10)
    if _cooldown_ok(machine_key, alert_type, cooldown):
        subject, plain, html = _render_alert(alert_type, system_name, location, rows)
        to_list = _recipients(config, alert_type)
        ok = _send_email(subject, plain, html, to_list)
        _mark_sent(machine_key, alert_type)
        await _log_alert(conn, alert_type, machine_key, subject, plain, ok)


async def check_metrics(conn, machine, config, alerts_enabled=True):
    system_name = machine["system_name"]
    location    = machine["location"]
    table_name  = machine["table_name"]
    key         = f"{system_name}@{location}"

    try:
        row = await conn.fetchrow(
            f"SELECT cpu_percent, ram_percent, cpu_temp, disk_partitions "
            f"FROM {table_name} ORDER BY ts DESC LIMIT 1"
        )
    except Exception as e:
        log.error("Could not read metrics from %s: %s", table_name, e)
        return

    if not row:
        return

    if not alerts_enabled:
        return  # metrics still collected/stored as normal — only alerting is muted

    cpu_cfg  = config.get("cpu",  {})
    ram_cfg  = config.get("ram",  {})
    temp_cfg = config.get("temp", {})
    disk_cfg = config.get("disk", {})

    cpu  = row["cpu_percent"]
    ram  = row["ram_percent"]
    temp = row["cpu_temp"]

    if cpu is not None and cpu_cfg.get("enabled") and cpu >= (cpu_cfg.get("threshold") or 90):
        await _alert(conn, config, key, "cpu", system_name, location,
                     [("CPU usage", f"{cpu:.1f}%"), ("Threshold", f"{cpu_cfg.get('threshold')}%")])

    if ram is not None and ram_cfg.get("enabled") and ram >= (ram_cfg.get("threshold") or 90):
        await _alert(conn, config, key, "ram", system_name, location,
                     [("RAM usage", f"{ram:.1f}%"), ("Threshold", f"{ram_cfg.get('threshold')}%")])

    if temp is not None and temp_cfg.get("enabled") and temp >= (temp_cfg.get("threshold") or 80):
        await _alert(conn, config, key, "temp", system_name, location,
                     [("CPU temp", f"{temp:.1f}°C"), ("Threshold", f"{temp_cfg.get('threshold')}°C")])

    if row["disk_partitions"] and disk_cfg.get("enabled"):
        partitions = row["disk_partitions"]
        if isinstance(partitions, str):
            partitions = json.loads(partitions)
        disk_thresh = disk_cfg.get("threshold") or 85
        for part in partitions:
            mount = part.get("mountpoint", "?")
            if any(mount.startswith(p) for p in SKIP_MOUNT_PREFIXES):
                continue
            pct = float(part.get("percent", 0))
            if pct >= disk_thresh:
                await _alert(conn, config, key, f"disk:{mount}", system_name, location,
                             [("Mount", mount), ("Usage", f"{pct:.1f}%"), ("Threshold", f"{disk_thresh}%")])


async def main():
    log.info("🚀 Offline Checker v2 (DB-driven alerts) starting...")
    pool = await asyncpg.create_pool(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS,
        min_size=2, max_size=5,
        server_settings={"timezone": "Asia/Kolkata"},
    )
    log.info("✅ Connected to database")

    while True:
        try:
            async with pool.acquire() as conn:
                config   = await _get_alert_config(conn)
                machines = await conn.fetch("SELECT * FROM machine_registry")
                now      = datetime.now(timezone.utc)

                offline_cfg = config.get("offline", {})
                online_cfg  = config.get("online",  {})
                thresh_secs = OFFLINE_THRESHOLD_SECS

                for machine in machines:
                    system_name    = machine["system_name"]
                    location       = machine["location"]
                    current_status = machine["status"]
                    last_seen      = machine["last_seen"]
                    alerts_enabled = machine["alerts_enabled"]
                    key            = f"{system_name}@{location}"

                    seconds_offline = (now - last_seen).total_seconds()
                    new_status = "offline" if seconds_offline > thresh_secs else "online"

                    if current_status != new_status:
                        await conn.execute(
                            "UPDATE machine_registry SET status=$1 WHERE system_name=$2 AND location=$3",
                            new_status, system_name, location,
                        )
                        # Status always updates so the dashboard reflects reality —
                        # alerts_enabled only controls whether we email about it.
                        if not alerts_enabled:
                            log.info("🔕 %s (%s) → %s (alerts muted for this machine)",
                                     system_name, location, new_status)
                        elif new_status == "offline" and offline_cfg.get("enabled", True):
                            log.warning("🔴 %s (%s) went OFFLINE", system_name, location)
                            await _alert(conn, config, key, "offline", system_name, location,
                                         [("Last seen", _fmt_ist(last_seen))])
                        elif new_status == "online" and online_cfg.get("enabled", True):
                            log.info("🟢 %s (%s) came back ONLINE", system_name, location)
                            await _alert(conn, config, key, "online", system_name, location,
                                         [("Back online since", _fmt_ist(now))])

                    if new_status == "online":
                        await check_metrics(conn, machine, config, alerts_enabled)

            await asyncio.sleep(CHECK_INTERVAL_SECS)

        except Exception as e:
            log.error("Check error: %s", e)
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())