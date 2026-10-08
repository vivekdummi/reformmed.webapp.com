import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from flask import Blueprint, render_template
from flask_login import login_required, current_user
from psycopg2 import sql

from db import get_db, get_setting

home_bp = Blueprint("home", __name__)


_SKIP_MOUNTS = ("/snap/", "/proc", "/sys", "/dev", "/run")


def _issue(metric, label, value, threshold, unit="%"):
    """One over-threshold reading. Critical when well past the limit."""
    value = float(value)
    critical = value >= 95 if unit == "%" else value >= threshold + 10
    return {"metric": metric, "label": label, "value": round(value, 1),
            "threshold": round(float(threshold), 1), "unit": unit,
            "severity": "critical" if critical else "warning"}


def _ago(ts):
    if ts is None:
        return "never"
    from datetime import timezone as _tz
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_tz.utc)
    secs = int((datetime.now(_tz.utc) - ts).total_seconds())
    if secs < 120:
        return f"{max(secs, 0)}s ago"
    if secs < 7200:
        return f"{secs // 60} min ago"
    if secs < 172800:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} days ago"


def _attention_list(machine_rows, limit=12):
    """
    Checks each accessible machine's LATEST reading against simple thresholds
    (CPU/RAM/temp/disk) and returns (needs_attention, fleet_metrics):
    the machines that need a look (worst first), and every online machine's
    current CPU / RAM / fullest-disk % for the overview charts.
    This is a real per-machine fan-out query (one per machine's own table),
    so it's computed once on full page load only — NOT on the 2s JS poll,
    to avoid hammering ~20+ tables every couple of seconds for every open tab.
    """
    out = []
    metrics = []
    with get_db() as conn:
        cur = conn.cursor()
        # Same thresholds the alert checker uses (System Alerts config),
        # instead of a hardcoded 90%.
        cur.execute("SELECT alert_type, threshold FROM alert_config")
        th = {r["alert_type"]: r["threshold"] for r in cur.fetchall()}
        cpu_th  = th.get("cpu")  or 90
        ram_th  = th.get("ram")  or 90
        temp_th = th.get("temp") or 80
        disk_th = th.get("disk") or 85
        for m in machine_rows:
            if m["status"] != "online":
                # Offline servers always need attention — they're the most urgent.
                out.append({
                    "system_name": m["system_name"], "location": m["location"],
                    "table_name": m["table_name"], "severity": "critical", "offline": True,
                    "last_seen": _ago(m.get("last_seen")), "issues": [],
                    "reasons": ["Offline"],
                })
                continue
            try:
                cur.execute(sql.SQL(
                    "SELECT cpu_percent, ram_percent, cpu_temp, disk_partitions "
                    "FROM {} ORDER BY ts DESC LIMIT 1"
                ).format(sql.Identifier(m["table_name"])))
                row = cur.fetchone()
            except Exception:
                conn.rollback()
                continue
            if not row:
                continue

            reasons, issues = [], []
            cpu = row.get("cpu_percent")
            ram = row.get("ram_percent")
            temp = row.get("cpu_temp")
            if cpu is not None and cpu >= cpu_th:
                reasons.append(f"CPU {cpu:.0f}%")
                issues.append(_issue("cpu", "CPU", cpu, cpu_th))
            if ram is not None and ram >= ram_th:
                reasons.append(f"RAM {ram:.0f}%")
                issues.append(_issue("ram", "Memory", ram, ram_th))
            if temp is not None and temp >= temp_th:
                reasons.append(f"Temp {temp:.0f}°C")
                issues.append(_issue("temp", "CPU temperature", temp, temp_th, "°C"))

            disk_max = None
            raw_disks = row.get("disk_partitions")
            if raw_disks:
                try:
                    disks = json.loads(raw_disks) if isinstance(raw_disks, str) else raw_disks
                    # Every real partition (Windows C:\, D:\ … too), not just "/".
                    for d in disks or []:
                        mount = str(d.get("mountpoint") or "")
                        if d.get("fstype") == "squashfs" or mount.startswith(_SKIP_MOUNTS):
                            continue
                        pct = float(d.get("percent") or 0)
                        disk_max = pct if disk_max is None else max(disk_max, pct)
                        if pct >= disk_th:
                            reasons.append(f"Disk {mount} {pct:.0f}%")
                            issues.append(_issue("disk", f"Disk {mount}", pct, disk_th))
                except Exception:
                    pass

            metrics.append({
                "name": m["system_name"], "location": m["location"], "table_name": m["table_name"],
                "cpu": round(float(cpu or 0), 1), "ram": round(float(ram or 0), 1),
                "disk": round(float(disk_max or 0), 1),
                "temp": round(float(temp), 1) if temp is not None else None,
            })

            if reasons:
                out.append({
                    "system_name": m["system_name"],
                    "location": m["location"],
                    "table_name": m["table_name"],
                    "reasons": reasons,
                    "issues": issues,
                    "offline": False,
                    "last_seen": _ago(m.get("last_seen")),
                    "severity": "critical" if any(i["severity"] == "critical" for i in issues) else "warning",
                })

    # Critical first (offline, then hottest), then warnings
    def _rank(a):
        worst = max((i["value"] / (i["threshold"] or 1) for i in a["issues"]), default=0)
        return (a["severity"] != "critical", not a["offline"], -worst, -len(a["issues"]))
    out.sort(key=_rank)
    return out[:limit], metrics


def _alert_overview(cur, allowed_keys, days=7):
    """Alert counts for the last `days` days: per day split by source, per
    alert type, and delivered vs failed. Scoped to what the user may see."""
    can_db = current_user.is_admin or current_user.can_view_dbmon
    cur.execute("""
        SELECT sent_at::date AS d,                -- session timezone is IST (db.py)
               COALESCE(source, 'system') AS src,
               split_part(alert_type, ':', 1) AS atype,
               machine_key, success
        FROM alert_log
        WHERE sent_at >= date_trunc('day', NOW()) - make_interval(days => %s)
        LIMIT 20000
    """, (days - 1,))
    today = datetime.now(ZoneInfo("Asia/Kolkata")).date()  # match the DB session timezone
    day_list = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
    by_day = {src: [0] * days for src in ("system", "dvr", "dbmonitor")}
    by_type, sent, failed = {}, 0, 0
    idx = {d: i for i, d in enumerate(day_list)}
    for r in cur.fetchall():
        src = r["src"] if r["src"] in by_day else "system"
        if src == "system" and allowed_keys is not None and r["machine_key"] not in allowed_keys:
            continue
        if src == "dvr" or (src == "dbmonitor" and not can_db):
            continue  # DVR monitoring is no longer shown in the app
        i = idx.get(r["d"])
        if i is not None:
            by_day[src][i] += 1
        by_type[r["atype"] or "other"] = by_type.get(r["atype"] or "other", 0) + 1
        if r["success"]:
            sent += 1
        else:
            failed += 1
    top_types = sorted(by_type.items(), key=lambda kv: -kv[1])
    if len(top_types) > 5:  # fold the tail into "other" so the donut stays readable
        top_types = top_types[:4] + [("other", sum(v for _, v in top_types[4:]))]
    return {
        "labels": [d.strftime("%a %d") for d in day_list],
        "by_day": by_day,
        "types": [{"type": t, "count": c} for t, c in top_types],
        "sent": sent, "failed": failed, "total": sent + failed,
    }


def _dbmon_health(cur):
    """Live / dead / paused counts for DB Monitor tables and locations, from
    the state the DB Monitor poller last recorded (was_dead)."""
    cur.execute("""
        SELECT COUNT(*) AS total,
               COUNT(*) FILTER (WHERE monitoring AND NOT was_dead) AS live,
               COUNT(*) FILTER (WHERE monitoring AND was_dead)     AS dead,
               COUNT(*) FILTER (WHERE NOT monitoring)              AS paused
        FROM dbmon_watches
    """)
    w = cur.fetchone()
    try:
        cur.execute("""
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE monitoring AND was_dead) AS dead
            FROM dbmon_watch_locations
        """)
        loc = cur.fetchone()
    except Exception:
        cur.connection.rollback()
        loc = {"total": 0, "dead": 0}
    return {"total": w["total"] or 0, "live": w["live"] or 0, "dead": w["dead"] or 0,
            "paused": w["paused"] or 0, "locations": loc["total"] or 0, "locations_dead": loc["dead"] or 0}


@home_bp.route("/")
@login_required
def index():
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()  # None = all

        if allowed is None:
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry
            """)
        else:
            if not allowed:
                return render_template("home.html", total=0, online=0, offline=0,
                                       recent=[], alerts=[], dvr_summary=None,
                                       dbmon_summary=None, attention=[], fleet=[],
                                       fleet_avg={"cpu": 0, "ram": 0, "disk": 0}, alert_stats=None)
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry WHERE table_name IN ({placeholders})
            """, list(allowed))

        row = cur.fetchone()
        total   = row["total"]   or 0
        online  = row["online"]  or 0
        offline = row["offline"] or 0

        # All accessible machines (for the attention-needed scan below)
        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry ORDER BY last_seen DESC NULLS LAST
            """)
        else:
            placeholders = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry WHERE table_name IN ({placeholders})
                ORDER BY last_seen DESC NULLS LAST
            """, list(allowed))
        all_machines = cur.fetchall()
        recent = all_machines[:6]

        # Recent alerts — non-admins only see their own servers' alerts (+ DVR /
        # DB Monitor alerts with those permissions), filtered before the LIMIT.
        from blueprints.api import alert_visibility_sql
        vis_sql, vis_params = alert_visibility_sql(cur)
        cur.execute(f"""
            SELECT alert_type, COALESCE(source,'system') AS source,
                   machine_key, subject, sent_at, success
            FROM alert_log WHERE {vis_sql} ORDER BY sent_at DESC LIMIT 10
        """, vis_params)
        alerts = cur.fetchall()

        allowed_keys = None
        if allowed is not None:
            allowed_keys = {f"{m['system_name']}@{m['location']}" for m in all_machines}

        try:
            alert_stats = _alert_overview(cur, allowed_keys)
        except Exception:
            conn.rollback()
            alert_stats = None

        # ── DVR summary — scoped to allowed hospitals if not admin ──
        dvr_allowed = current_user.allowed_hospitals()  # None = all
        if dvr_allowed is None:
            cur.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                       SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM dvr_devices
            """)
            dvr_row = cur.fetchone()
        elif not dvr_allowed:
            dvr_row = {"total": 0, "online": 0, "offline": 0}
        else:
            cur.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN d.status='online'  THEN 1 ELSE 0 END) AS online,
                       SUM(CASE WHEN d.status='offline' THEN 1 ELSE 0 END) AS offline
                FROM dvr_devices d
                JOIN dvr_locations l ON l.id = d.location_id
                WHERE l.hospital_id = ANY(%s)
            """, (list(dvr_allowed),))
            dvr_row = cur.fetchone()
        dvr_summary = {
            "total": dvr_row["total"] or 0,
            "online": dvr_row["online"] or 0,
            "offline": dvr_row["offline"] or 0,
        }

        # ── DB Monitor summary — table count only; live/dead status is
        # already computed by DB Monitor's own page, not cheap to repeat here ──
        cur.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN alerts_enabled THEN 1 ELSE 0 END) AS alerts_on
            FROM dbmon_watches
        """)
        dbmon_row = cur.fetchone()
        dbmon_summary = {
            "total": dbmon_row["total"] or 0,
            "alerts_on": dbmon_row["alerts_on"] or 0,
        }
        if current_user.is_admin or current_user.can_view_dbmon:
            try:
                dbmon_summary.update(_dbmon_health(cur))
            except Exception:
                conn.rollback()
        else:
            dbmon_summary = None
        dvr_summary = None  # DVR tab removed from the app

    # Per-machine "needs attention" scan — SSR only, not part of the 2s poll.
    attention, fleet = _attention_list(all_machines)
    fleet_avg = {
        k: round(sum(m[k] for m in fleet) / len(fleet), 1) if fleet else 0
        for k in ("cpu", "ram", "disk")
    }

    try:
        refresh_secs = max(5, int(get_setting("home_refresh_secs", "5") or 5))
    except ValueError:
        refresh_secs = 5

    return render_template("home.html",
                           home_refresh_secs=refresh_secs,
                           total=total, online=online, offline=offline,
                           recent=recent, alerts=alerts,
                           dvr_summary=dvr_summary, dbmon_summary=dbmon_summary,
                           attention=attention, fleet=fleet, fleet_avg=fleet_avg,
                           alert_stats=alert_stats)