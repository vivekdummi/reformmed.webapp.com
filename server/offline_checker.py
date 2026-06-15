"""
REFORMMED Offline Checker + Alerter
Improvements over original:
  - Reads OFFLINE_AFTER_SECS and CHECK_INTERVAL_SECS from env (was hardcoded)
  - Email alerts for: machine offline/online, CPU/RAM/disk/temp threshold breaches
  - Per-machine per-alert-type cooldown (ALERT_COOLDOWN_MINUTES) to avoid spam
  - Excludes snap/proc/sys/tmpfs mounts from disk alerts
"""
import asyncio
import json
import logging
import os
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import asyncpg

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CHECKER] %(message)s")
log = logging.getLogger("checker")

# ── config from env ──────────────────────────────────────────────────────────
DB_HOST     = os.getenv("POSTGRES_HOST", "reformmed_postgres")
DB_PORT     = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME     = os.getenv("POSTGRES_DB", "monitor_machine")
DB_USER     = os.getenv("POSTGRES_USER", "admin")
DB_PASS     = os.getenv("POSTGRES_PASSWORD", "")

OFFLINE_THRESHOLD_SECS = int(os.getenv("OFFLINE_AFTER_SECS", "60"))
CHECK_INTERVAL_SECS    = int(os.getenv("CHECK_INTERVAL_SECS", "15"))
ALERT_COOLDOWN_MINS    = int(os.getenv("ALERT_COOLDOWN_MINUTES", "10"))

# Thresholds (% or °C)
CPU_THRESH  = float(os.getenv("CPU_ALERT_THRESH", "90"))
RAM_THRESH  = float(os.getenv("RAM_ALERT_THRESH", "90"))
DISK_THRESH = float(os.getenv("DISK_ALERT_THRESH", "90"))
TEMP_THRESH = float(os.getenv("TEMP_ALERT_THRESH", "80"))

# Email
GMAIL_USER    = os.getenv("GMAIL_USER", "")
GMAIL_PASS    = os.getenv("GMAIL_APP_PASS", "")
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "465"))
ALERT_TO      = os.getenv("ALERT_TO", "")
EMAIL_ENABLED = bool(GMAIL_USER and GMAIL_PASS and ALERT_TO)

# Mount prefixes to skip for disk alerts (snap mounts are always 100% — read-only squashfs)
SKIP_MOUNT_PREFIXES = ("/snap/", "/proc", "/sys", "/dev", "/run")

# ── cooldown tracker ─────────────────────────────────────────────────────────
_last_alert: dict[tuple, datetime] = {}

def _cooldown_ok(machine_key: str, alert_type: str) -> bool:
    key = (machine_key, alert_type)
    last = _last_alert.get(key)
    if last is None:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() > ALERT_COOLDOWN_MINS * 60

def _mark_sent(machine_key: str, alert_type: str):
    _last_alert[(machine_key, alert_type)] = datetime.now(timezone.utc)

# ── email ────────────────────────────────────────────────────────────────────
def send_email(subject: str, body: str):
    if not EMAIL_ENABLED:
        log.warning("Email not configured — skipping alert: %s", subject)
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[REFORMMED] {subject}"
        msg["From"]    = GMAIL_USER
        msg["To"]      = ALERT_TO
        msg.attach(MIMEText(body, "plain"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as srv:
            srv.login(GMAIL_USER, GMAIL_PASS)
            srv.sendmail(GMAIL_USER, ALERT_TO, msg.as_string())
        log.info("📧 Alert sent: %s", subject)
    except Exception as e:
        log.error("Failed to send email: %s", e)

def _alert(machine_key: str, alert_type: str, subject: str, body: str):
    if _cooldown_ok(machine_key, alert_type):
        send_email(subject, body)
        _mark_sent(machine_key, alert_type)

# ── metric checks ─────────────────────────────────────────────────────────────
async def check_metrics(conn, machine):
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

    cpu  = row["cpu_percent"]
    ram  = row["ram_percent"]
    temp = row["cpu_temp"]

    if cpu is not None and cpu >= CPU_THRESH:
        _alert(key, "cpu",
               f"🔥 HIGH CPU — {system_name} ({location})",
               f"CPU usage is {cpu:.1f}% (threshold: {CPU_THRESH}%)\nMachine: {system_name} | Location: {location}")

    if ram is not None and ram >= RAM_THRESH:
        _alert(key, "ram",
               f"🧠 HIGH RAM — {system_name} ({location})",
               f"RAM usage is {ram:.1f}% (threshold: {RAM_THRESH}%)\nMachine: {system_name} | Location: {location}")

    if temp is not None and temp >= TEMP_THRESH:
        _alert(key, "temp",
               f"🌡️ HIGH TEMP — {system_name} ({location})",
               f"CPU temperature is {temp:.1f}°C (threshold: {TEMP_THRESH}°C)\nMachine: {system_name} | Location: {location}")

    # Disk: check real partitions only — skip snap, proc, sys, dev, run
    if row["disk_partitions"]:
        partitions = row["disk_partitions"]
        if isinstance(partitions, str):
            partitions = json.loads(partitions)
        for part in partitions:
            mount = part.get("mountpoint", "?")
            # Skip virtual/read-only mounts — snap is always 100% full by design
            if any(mount.startswith(prefix) for prefix in SKIP_MOUNT_PREFIXES):
                continue
            pct = float(part.get("percent", 0))
            if pct >= DISK_THRESH:
                _alert(key, f"disk:{mount}",
                       f"💿 DISK FULL — {system_name} ({location}) [{mount}]",
                       f"Disk {mount} is {pct:.1f}% full (threshold: {DISK_THRESH}%)\nMachine: {system_name} | Location: {location}")

# ── main loop ────────────────────────────────────────────────────────────────
async def main():
    log.info("🚀 Offline Checker + Alerter starting...")
    log.info("⏱  Offline threshold : %ds", OFFLINE_THRESHOLD_SECS)
    log.info("⏱  Check interval    : %ds", CHECK_INTERVAL_SECS)
    log.info("⏱  Alert cooldown    : %dmin", ALERT_COOLDOWN_MINS)
    log.info("📧 Email alerts      : %s", "enabled" if EMAIL_ENABLED else "DISABLED (check env)")
    log.info("🚨 Thresholds        : CPU=%s%% RAM=%s%% Disk=%s%% Temp=%s°C",
             CPU_THRESH, RAM_THRESH, DISK_THRESH, TEMP_THRESH)
    log.info("🚫 Skipping mounts   : %s", ", ".join(SKIP_MOUNT_PREFIXES))

    pool = await asyncpg.create_pool(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS,
        min_size=2, max_size=5,
    )
    log.info("✅ Connected to database")

    while True:
        try:
            async with pool.acquire() as conn:
                machines = await conn.fetch("SELECT * FROM machine_registry")
                now = datetime.now(timezone.utc)

                for machine in machines:
                    system_name    = machine["system_name"]
                    location       = machine["location"]
                    current_status = machine["status"]
                    last_seen      = machine["last_seen"]
                    key            = f"{system_name}@{location}"

                    seconds_offline = (now - last_seen).total_seconds()
                    new_status = "offline" if seconds_offline > OFFLINE_THRESHOLD_SECS else "online"

                    if current_status != new_status:
                        await conn.execute(
                            "UPDATE machine_registry SET status=$1 WHERE system_name=$2 AND location=$3",
                            new_status, system_name, location,
                        )
                        if new_status == "offline":
                            log.warning("🔴 %s (%s) went OFFLINE (last seen %ds ago)", system_name, location, int(seconds_offline))
                            _alert(key, "offline",
                                   f"🔴 OFFLINE — {system_name} ({location})",
                                   f"{system_name} at {location} went OFFLINE.\nLast seen: {last_seen.isoformat()}\nSeconds since last data: {int(seconds_offline)}")
                        else:
                            log.info("🟢 %s (%s) came back ONLINE", system_name, location)
                            _alert(key, "online",
                                   f"🟢 RECOVERED — {system_name} ({location})",
                                   f"{system_name} at {location} is back ONLINE.")
                    else:
                        if new_status == "offline":
                            log.debug("   %s still offline (%ds)", system_name, int(seconds_offline))
                        else:
                            log.debug("   %s online (last seen %ds ago)", system_name, int(seconds_offline))

                    # Only check metric thresholds for online machines
                    if new_status == "online":
                        await check_metrics(conn, machine)

            await asyncio.sleep(CHECK_INTERVAL_SECS)

        except Exception as e:
            log.error("Check error: %s", e)
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())