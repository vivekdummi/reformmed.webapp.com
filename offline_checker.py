"""
REFORMMED Offline Checker + Alerter (v2 — DB-driven config)
- Reads thresholds and recipients from alert_config table
- Sends email alerts
- Cleans up data older than 7 days (runs once per day)
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, date

import asyncpg

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CHECKER] %(message)s")
log = logging.getLogger("checker")

DB_HOST = os.getenv("POSTGRES_HOST", "reformmed_postgres")
DB_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME = os.getenv("POSTGRES_DB", "monitor_machine")
DB_USER = os.getenv("POSTGRES_USER", "admin")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "")

OFFLINE_THRESHOLD_SECS = int(os.getenv("OFFLINE_AFTER_SECS", "60"))
CHECK_INTERVAL_SECS    = int(os.getenv("CHECK_INTERVAL_SECS", "15"))
DATA_RETENTION_DAYS    = int(os.getenv("DATA_RETENTION_DAYS", "7"))

SKIP_MOUNT_PREFIXES = ("/snap/", "/proc", "/sys", "/dev", "/run")

_last_alert: dict = {}


def _cooldown_ok(machine_key: str, alert_type: str, cooldown_mins: int) -> bool:
    key  = (machine_key, alert_type)
    last = _last_alert.get(key)
    if last is None:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() > cooldown_mins * 60


def _mark_sent(machine_key: str, alert_type: str):
    _last_alert[(machine_key, alert_type)] = datetime.now(timezone.utc)


import ssl, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_PASS = os.getenv("GMAIL_APP_PASS", "")
SMTP_HOST  = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(os.getenv("SMTP_PORT", "465"))


def _send_email(subject: str, body: str, to_list: list) -> bool:
    if not GMAIL_USER or not GMAIL_PASS or not to_list:
        log.warning("Email not configured or no recipients — skipping: %s", subject)
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[REFORMMED] {subject}"
        msg["From"]    = GMAIL_USER
        msg["To"]      = ", ".join(to_list)
        msg.attach(MIMEText(body, "plain"))
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
    rows = await conn.fetch("SELECT * FROM alert_config")
    return {r["alert_type"]: dict(r) for r in rows}


def _recipients(config: dict, atype: str) -> list:
    cfg = config.get(atype, {})
    emails = cfg.get("notify_emails", "") or os.getenv("ALERT_TO", "")
    return [e.strip() for e in emails.split(",") if e.strip()]


async def _alert(conn, config: dict, machine_key: str, alert_type: str, subject: str, body: str):
    cfg = config.get(alert_type, {})
    if not cfg.get("enabled", True):
        return
    cooldown = cfg.get("cooldown_minutes", 10)
    if _cooldown_ok(machine_key, alert_type, cooldown):
        to_list = _recipients(config, alert_type)
        ok = _send_email(subject, body, to_list)
        _mark_sent(machine_key, alert_type)
        await _log_alert(conn, alert_type, machine_key, subject, body, ok)


async def cleanup_old_data(conn):
    """Delete metric rows older than DATA_RETENTION_DAYS from all machine tables."""
    try:
        machines = await conn.fetch("SELECT table_name, system_name, location FROM machine_registry")
        total_deleted = 0
        for m in machines:
            table = m["table_name"]
            try:
                result = await conn.execute(f"""
                    DELETE FROM {table}
                    WHERE ts < NOW() - INTERVAL '{DATA_RETENTION_DAYS} days'
                """)
                count = int(result.split()[-1]) if result else 0
                if count > 0:
                    log.info("🗑️  Cleaned %s rows from %s (%s @ %s)",
                             count, table, m["system_name"], m["location"])
                total_deleted += count
            except Exception as e:
                log.error("Cleanup error for table %s: %s", table, e)

        log.info("✅ Daily cleanup complete — %s total rows deleted (retention: %s days)",
                 total_deleted, DATA_RETENTION_DAYS)
    except Exception as e:
        log.error("Cleanup failed: %s", e)


async def check_metrics(conn, machine, config):
    system_name = machine["system_name"]
    location    = machine["location"]
    table_name  = machine["table_name"]
    key         = f"{system_name}@{location}"

    try:
        row = await conn.fetchrow(f"""
            SELECT cpu_percent, ram_percent, cpu_temp, disk_partitions
            FROM {table_name} ORDER BY ts DESC LIMIT 1
        """)
    except Exception as e:
        log.error("Could not read metrics from %s: %s", table_name, e)
        return

    if not row:
        return

    cpu_cfg  = config.get("cpu",  {})
    ram_cfg  = config.get("ram",  {})
    temp_cfg = config.get("temp", {})
    disk_cfg = config.get("disk", {})

    cpu  = row["cpu_percent"]
    ram  = row["ram_percent"]
    temp = row["cpu_temp"]

    if cpu is not None and cpu_cfg.get("enabled") and cpu >= (cpu_cfg.get("threshold") or 90):
        await _alert(conn, config, key, "cpu",
                     f"HIGH CPU — {system_name} ({location})",
                     f"CPU usage is {cpu:.1f}% (threshold: {cpu_cfg.get('threshold')}%)\nMachine: {system_name} | {location}")

    if ram is not None and ram_cfg.get("enabled") and ram >= (ram_cfg.get("threshold") or 90):
        await _alert(conn, config, key, "ram",
                     f"HIGH RAM — {system_name} ({location})",
                     f"RAM usage is {ram:.1f}% (threshold: {ram_cfg.get('threshold')}%)\nMachine: {system_name} | {location}")

    if temp is not None and temp_cfg.get("enabled") and temp >= (temp_cfg.get("threshold") or 80):
        await _alert(conn, config, key, "temp",
                     f"HIGH TEMP — {system_name} ({location})",
                     f"CPU temp is {temp:.1f}C (threshold: {temp_cfg.get('threshold')}C)\nMachine: {system_name} | {location}")

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
                await _alert(conn, config, key, f"disk",
                             f"DISK FULL — {system_name} ({location}) [{mount}]",
                             f"Disk {mount} is {pct:.1f}% full (threshold: {disk_thresh}%)\nMachine: {system_name} | {location}")


async def main():
    log.info("Offline Checker v2 starting (retention: %s days)...", DATA_RETENTION_DAYS)
    pool = await asyncpg.create_pool(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS,
        min_size=2, max_size=5,
    )
    log.info("Connected to database")

    last_cleanup_date = None

    while True:
        try:
            async with pool.acquire() as conn:
                config   = await _get_alert_config(conn)
                machines = await conn.fetch("SELECT * FROM machine_registry")
                now      = datetime.now(timezone.utc)
                today    = date.today()

                offline_cfg = config.get("offline", {})
                online_cfg  = config.get("online",  {})

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
                        if new_status == "offline" and offline_cfg.get("enabled", True):
                            log.warning("OFFLINE: %s (%s)", system_name, location)
                            await _alert(conn, config, key, "offline",
                                         f"OFFLINE — {system_name} ({location})",
                                         f"{system_name} at {location} went OFFLINE.\nLast seen: {last_seen.isoformat()}")
                        elif new_status == "online" and online_cfg.get("enabled", True):
                            log.info("ONLINE: %s (%s)", system_name, location)
                            await _alert(conn, config, key, "online",
                                         f"RECOVERED — {system_name} ({location})",
                                         f"{system_name} at {location} is back ONLINE.")

                    if new_status == "online":
                        await check_metrics(conn, machine, config)

                # Run cleanup once per day
                if last_cleanup_date != today:
                    await cleanup_old_data(conn)
                    last_cleanup_date = today

            await asyncio.sleep(CHECK_INTERVAL_SECS)

        except Exception as e:
            log.error("Check error: %s", e)
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
