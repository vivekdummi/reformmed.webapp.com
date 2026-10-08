"""
alert_sender.py — shared email helper.
Used by both the offline_checker daemon and the Flask webapp (test alerts).
Also handles writing to alert_log table.
"""

import os
import ssl
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger(__name__)


def clean_header(value, max_len=200) -> str:
    """Collapse CR/LF/tabs and bound the length of a value going into an email
    header. Subjects include agent- and external-DB-supplied strings (machine
    names, locations, mount points), which must not be able to inject headers."""
    return " ".join(str(value).split())[:max_len]

def _smtp_config():
    """Settings → Email/SMTP from the DB (what the UI saves), else env vars."""
    try:
        from db import smtp_settings
        return smtp_settings()
    except Exception as e:
        log.warning("Could not read SMTP settings from DB, using env: %s", e)
        user = os.getenv("GMAIL_USER", "")
        return {"host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
                "port": int(os.getenv("SMTP_PORT", "465")),
                "username": user, "password": os.getenv("GMAIL_APP_PASS", ""),
                "from_addr": user}


def send_alert_email(subject: str, body: str, recipients: str) -> bool:
    """
    Send an email alert.
    recipients: comma-separated email string or list of emails.
    Returns True on success, False on failure.
    """
    cfg = _smtp_config()
    if not cfg["username"] or not cfg["password"]:
        log.warning("SMTP not configured — skipping email: %s", subject)
        return False

    if isinstance(recipients, str):
        to_list = [e.strip() for e in recipients.split(",") if e.strip()]
    else:
        to_list = list(recipients)

    if not to_list:
        log.warning("No recipients configured — skipping email: %s", subject)
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = clean_header(subject)
        msg["From"]    = cfg["from_addr"]
        msg["To"]      = ", ".join(to_list)
        msg.attach(MIMEText(body, "plain"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=10, context=ctx) as srv:
            srv.login(cfg["username"], cfg["password"])
            srv.sendmail(cfg["from_addr"], to_list, msg.as_string())

        log.info("📧 Alert sent: %s → %s", subject, to_list)
        return True

    except Exception as e:
        log.error("Failed to send email '%s': %s", subject, e)
        return False


def log_alert(alert_type: str, machine_key: str, subject: str, body: str, success: bool):
    """Write alert to the alert_log table."""
    try:
        from db import get_db
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO alert_log (alert_type, machine_key, subject, body, success)
                VALUES (%s, %s, %s, %s, %s)
            """, (alert_type, machine_key, subject, body, success))
    except Exception as e:
        log.error("Failed to write alert_log: %s", e)
