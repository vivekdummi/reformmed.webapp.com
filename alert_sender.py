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

GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_PASS = os.getenv("GMAIL_APP_PASS", "")
SMTP_HOST  = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(os.getenv("SMTP_PORT", "465"))


def send_alert_email(subject: str, body: str, recipients: str) -> bool:
    """
    Send an email alert.
    recipients: comma-separated email string or list of emails.
    Returns True on success, False on failure.
    """
    if not GMAIL_USER or not GMAIL_PASS:
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
        msg["Subject"] = subject
        msg["From"]    = GMAIL_USER
        msg["To"]      = ", ".join(to_list)
        msg.attach(MIMEText(body, "plain"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as srv:
            srv.login(GMAIL_USER, GMAIL_PASS)
            srv.sendmail(GMAIL_USER, to_list, msg.as_string())

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
