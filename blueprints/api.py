"""
Internal JSON API — consumed by frontend JS (session-auth only).
"""
from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from db import get_db

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ── Machine summary / list ────────────────────────────────────────────────────

@api_bp.route("/machines/summary")
@login_required
def machines_summary():
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()
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
                return jsonify({"total": 0, "online": 0, "offline": 0})
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry WHERE table_name IN ({ph})
            """, list(allowed))
        row = cur.fetchone()
    return jsonify({
        "total":   row["total"]   or 0,
        "online":  row["online"]  or 0,
        "offline": row["offline"] or 0,
    })


@api_bp.route("/machines/list")
@login_required
def machines_list():
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()
        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry ORDER BY system_name
            """)
        else:
            if not allowed:
                return jsonify([])
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry WHERE table_name IN ({ph}) ORDER BY system_name
            """, list(allowed))
        rows = cur.fetchall()
    return jsonify([dict(r, last_seen=str(r["last_seen"])) for r in rows])


# ── Home dashboard data (partial refresh — no full page reload) ──────────────

@api_bp.route("/home/data")
@login_required
def home_data():
    """Returns all data needed by the home page for 2-second partial refresh."""
    with get_db() as conn:
        cur = conn.cursor()
        allowed = current_user.allowed_servers()

        # ── Counts ──
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
                return jsonify({"total": 0, "online": 0, "offline": 0, "recent": [], "alerts": [], "alerts_today": 0})
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline
                FROM machine_registry WHERE table_name IN ({ph})
            """, list(allowed))
        row = cur.fetchone()
        total   = int(row["total"]   or 0)
        online  = int(row["online"]  or 0)
        offline = int(row["offline"] or 0)

        # ── Recent machines ──
        if allowed is None:
            cur.execute("""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry ORDER BY last_seen DESC NULLS LAST LIMIT 6
            """)
        else:
            ph = ",".join(["%s"] * len(allowed))
            cur.execute(f"""
                SELECT system_name, location, table_name, status, last_seen, hostname, public_ip
                FROM machine_registry WHERE table_name IN ({ph})
                ORDER BY last_seen DESC NULLS LAST LIMIT 6
            """, list(allowed))
        recent = [dict(r, last_seen=str(r["last_seen"])) for r in cur.fetchall()]

        # ── Recent alerts ──
        try:
            cur.execute("""
                SELECT alert_type, COALESCE(source,'system') AS source,
                       machine_key, subject, sent_at, success
                FROM alert_log ORDER BY sent_at DESC LIMIT 10
            """)
        except Exception:
            cur.execute("""
                SELECT alert_type, 'system' AS source,
                       machine_key, subject, sent_at, success
                FROM alert_log ORDER BY sent_at DESC LIMIT 10
            """)
        alerts = [dict(r, sent_at=str(r['sent_at'])) for r in cur.fetchall()]

        # ── Alerts today count ──
        cur.execute("""
            SELECT COUNT(*) AS cnt FROM alert_log
            WHERE sent_at >= CURRENT_DATE
        """)
        alerts_today = int(cur.fetchone()["cnt"] or 0)

    return jsonify({
        "total": total, "online": online, "offline": offline,
        "recent": recent, "alerts": alerts, "alerts_today": alerts_today,
    })


# ── Unified alerts feed ────────────────────────────────────────────────────────

@api_bp.route("/alerts/all")
@login_required
def alerts_all():
    """Unified alert log: system + DVR + dbmonitor, last 200."""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, alert_type, source, machine_key, subject, sent_at, success
            FROM alert_log ORDER BY sent_at DESC LIMIT 200
        """)
        rows = cur.fetchall()
    return jsonify([dict(r, sent_at=str(r["sent_at"])) for r in rows])


# ── Settings read ────────────────────────────────────────────────────────────

@api_bp.route("/settings")
@login_required
def settings_all():
    if not current_user.is_admin:
        return jsonify({}), 403
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM app_settings ORDER BY key")
        rows = cur.fetchall()
    return jsonify({r["key"]: r["value"] for r in rows})


# ── AI Agent chat endpoint ─────────────────────────────────────────────────────

@api_bp.route("/agent/context")
@login_required
def agent_context():
    """Returns a JSON snapshot of DB data for the agent system prompt."""
    import json
    ctx = {}
    with get_db() as conn:
        cur = conn.cursor()
        # Machines
        try:
            cur.execute("""
                SELECT system_name, location, status, hostname, public_ip, last_seen
                FROM machine_registry ORDER BY system_name
            """)
            machines = cur.fetchall()
            ctx["machines"] = [dict(m, last_seen=str(m["last_seen"])) for m in machines]
            ctx["total"]   = len(machines)
            ctx["online"]  = sum(1 for m in machines if m["status"]=="online")
            ctx["offline"] = sum(1 for m in machines if m["status"]=="offline")
        except Exception as e:
            ctx["machines_error"] = str(e)

        # Latest metrics per machine
        metrics = []
        # Re-fetch with table_name
        try:
            cur.execute("SELECT system_name, table_name FROM machine_registry")
            tbl_map = {r["system_name"]: r["table_name"] for r in cur.fetchall()}
        except Exception:
            tbl_map = {}
        for m in ctx.get("machines", []):
            try:
                tbl = tbl_map.get(m["system_name"], "")
                if not tbl: continue
                cur.execute(f"SELECT cpu_percent,ram_percent,cpu_temp,disk_partitions FROM {tbl} ORDER BY ts DESC LIMIT 1")
                row = cur.fetchone()
                if row:
                    disks = []
                    try:
                        raw = row["disk_partitions"]
                        disks = json.loads(raw) if isinstance(raw,str) else (raw or [])
                        disks = [{"mount":d.get("mountpoint"),"pct":d.get("percent")} for d in disks]
                    except Exception:
                        pass
                    metrics.append({
                        "name": m["system_name"],
                        "cpu":  round(row["cpu_percent"] or 0, 1),
                        "ram":  round(row["ram_percent"] or 0, 1),
                        "temp": round(row["cpu_temp"]    or 0, 1),
                        "disks": disks,
                    })
            except Exception:
                pass
        ctx["metrics"] = metrics

        # Recent alerts (24h)
        try:
            cur.execute("""
                SELECT alert_type, COALESCE(source,'system') AS source,
                       machine_key, subject, sent_at
                FROM alert_log WHERE sent_at >= NOW() - INTERVAL '24 hours'
                ORDER BY sent_at DESC LIMIT 20
            """)
            ctx["alerts_24h"] = [dict(r, sent_at=str(r["sent_at"])) for r in cur.fetchall()]
        except Exception:
            ctx["alerts_24h"] = []

        # DVR status
        try:
            cur.execute("""
                SELECT d.name, d.ip, d.status, l.name AS loc, h.name AS hospital
                FROM dvr_devices d
                JOIN dvr_locations l ON l.id=d.location_id
                JOIN dvr_hospitals h ON h.id=l.hospital_id
            """)
            ctx["dvrs"] = [dict(r) for r in cur.fetchall()]
        except Exception:
            ctx["dvrs"] = []

        # DB watches
        try:
            cur.execute("""
                SELECT w.display_name, w.last_status, c.name AS conn_name
                FROM dbmon_watches w JOIN dbmon_connections c ON c.id=w.conn_id
            """)
            ctx["db_watches"] = [dict(r) for r in cur.fetchall()]
        except Exception:
            ctx["db_watches"] = []

    return jsonify(ctx)


@api_bp.route("/agent/chat", methods=["POST"])
@login_required
def agent_chat():
    """Simple (non-streaming) Claude response for the AI agent popup."""
    import json, urllib.request, os
    from flask import request

    body = request.get_json(silent=True) or {}
    messages  = body.get("messages", [])   # full conversation history
    context   = body.get("context",  {})   # DB snapshot passed from frontend

    # Build system prompt with live context
    machines_txt = ""
    for m in context.get("metrics", []):
        disk_txt = ", ".join(f"{d['mount']}:{d['pct']}%" for d in (m.get("disks") or []))
        machines_txt += f"  - {m['name']}: CPU {m['cpu']}%, RAM {m['ram']}%, Temp {m['temp']}°C  Disks: {disk_txt or '—'}\n"

    alerts_txt = ""
    for a in context.get("alerts_24h", [])[:10]:
        alerts_txt += f"  - [{a.get('source','system')}] {a.get('alert_type','')} on {a.get('machine_key','')}\n"

    dvr_txt = ""
    for d in context.get("dvrs", []):
        dvr_txt += f"  - {d['hospital']} / {d['loc']} / {d['name']} ({d['ip']}): {d['status']}\n"

    dbw_txt = ""
    for w in context.get("db_watches", []):
        dbw_txt += f"  - {w['conn_name']}.{w['display_name']}: {w.get('last_status','unknown')}\n"

    system = f"""You are ARIA (Automated REFORMMED Infrastructure Agent), an AI assistant embedded in the REFORMMED Monitor dashboard — a healthcare infrastructure monitoring platform.

You have real-time access to the following live data pulled from the PostgreSQL database:

MACHINES ({context.get('total',0)} total, {context.get('online',0)} online, {context.get('offline',0)} offline):
{machines_txt or '  No data'}

ALERTS (last 24h, {len(context.get('alerts_24h',[]))} total):
{alerts_txt or '  None'}

DVR DEVICES:
{dvr_txt or '  None'}

DB MONITOR WATCHES:
{dbw_txt or '  None'}

Current user: {current_user.username} (role: {current_user.role})
Current page: {body.get('page', 'unknown')}

You can answer questions about:
- Machine health, CPU/RAM/disk/temperature status
- Which machines are online or offline
- Recent alerts and patterns
- DVR connectivity
- DB monitor watch status
- General recommendations

Be concise, direct, and use bullet points for lists. For normal conversation, reply in 1-3 sentences. Always reference actual data from the context above when answering infrastructure questions."""

    payload = json.dumps({
        "model":      "claude-sonnet-4-6",
        "max_tokens": 800,
        "stream":     True,
        "system":     system,
        "messages":   messages,
    }).encode()

    try:
        # Non-streaming request
        payload_ns = json.loads(payload.decode())
        payload_ns["stream"] = False
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload_ns).encode(),
            headers={
                "x-api-key":         os.getenv("ANTHROPIC_API_KEY",""),
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
            text = data.get("content",[{}])[0].get("text","")
            return jsonify({"text": text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
