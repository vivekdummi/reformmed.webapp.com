"""
AI Review blueprint — Gemini-powered infrastructure summary.
Pulls live data from PostgreSQL and streams an AI analysis.
"""
import json
import os
from flask import Blueprint, render_template, Response, stream_with_context, abort, jsonify
from flask_login import login_required, current_user
from db import get_db

review_bp = Blueprint("review", __name__, url_prefix="/review")

# ── Gemini config (Google AI Studio — no GCP project/billing required) ──────
# Get a free key at https://aistudio.google.com/apikey — overridable via .env.
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def _gemini_url(stream: bool) -> str:
    method = "streamGenerateContent?alt=sse" if stream else "generateContent"
    return f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:{method}"


def _gemini_payload(prompt: str) -> bytes:
    return json.dumps({
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 4096},
    }).encode()


def _gemini_headers() -> dict:
    return {
        "x-goog-api-key": GEMINI_API_KEY,
        "content-type":   "application/json",
    }


def _extract_gemini_text(obj: dict) -> str:
    """Pull the text delta out of one Gemini response object, if present."""
    try:
        return obj["candidates"][0]["content"]["parts"][0].get("text", "")
    except (KeyError, IndexError, TypeError):
        return ""


def _collect_data():
    """Pull all relevant monitoring data from DB into a structured dict."""
    data = {}
    with get_db() as conn:
        cur = conn.cursor()

        # ── Machine registry ──
        cur.execute("""
            SELECT system_name, location, table_name, hostname, public_ip,
                   os_type, status, last_seen, registered_at
            FROM machine_registry ORDER BY system_name
        """)
        machines = list(cur.fetchall())
        data["total_machines"]   = len(machines)
        data["online_machines"]  = sum(1 for m in machines if m["status"] == "online")
        data["offline_machines"] = sum(1 for m in machines if m["status"] == "offline")
        data["machines"] = [dict(m, last_seen=str(m["last_seen"]),
                                    registered_at=str(m["registered_at"])) for m in machines]

        # ── Latest metrics per machine ──
        machine_metrics = []
        for m in machines:
            tbl = m["table_name"]
            try:
                cur.execute(f"""
                    SELECT ts, cpu_percent, ram_percent, swap_percent,
                           cpu_temp, net_bytes_sent, net_bytes_recv,
                           disk_partitions
                    FROM {tbl} ORDER BY ts DESC LIMIT 1
                """)
                row = cur.fetchone()
                if row:
                    disks = []
                    try:
                        raw = row["disk_partitions"]
                        disks = json.loads(raw) if isinstance(raw, str) else (raw or [])
                    except Exception:
                        pass
                    machine_metrics.append({
                        "system_name": m["system_name"],
                        "location":    m["location"],
                        "status":      m["status"],
                        "cpu":         round(row["cpu_percent"]  or 0, 1),
                        "ram":         round(row["ram_percent"]  or 0, 1),
                        "swap":        round(row["swap_percent"] or 0, 1),
                        "temp":        round(row["cpu_temp"]     or 0, 1),
                        "disks":       disks,
                        "last_seen":   str(row["ts"]),
                    })
            except Exception:
                pass
        data["machine_metrics"] = machine_metrics

        # ── Alert summary (last 24h) ──
        try:
            cur.execute("""
                SELECT alert_type, COALESCE(source,'system') AS source,
                       machine_key, subject, sent_at, success
                FROM alert_log
                WHERE sent_at >= NOW() - INTERVAL '24 hours'
                ORDER BY sent_at DESC LIMIT 50
            """)
            alerts = [dict(r, sent_at=str(r["sent_at"])) for r in cur.fetchall()]
        except Exception:
            alerts = []
        data["alerts_24h"]       = len(alerts)
        data["alerts_failed"]    = sum(1 for a in alerts if not a["success"])
        data["recent_alerts"]    = alerts[:20]

        # ── DVR status ──
        try:
            cur.execute("""
                SELECT d.name, d.ip, d.port, d.status,
                       l.name AS location, h.name AS hospital
                FROM dvr_devices d
                JOIN dvr_locations l ON l.id = d.location_id
                JOIN dvr_hospitals h ON h.id = l.hospital_id
                ORDER BY h.name, l.name, d.name
            """)
            dvrs = cur.fetchall()
            data["total_dvrs"]   = len(dvrs)
            data["online_dvrs"]  = sum(1 for d in dvrs if d["status"] == "online")
            data["offline_dvrs"] = sum(1 for d in dvrs if d["status"] == "offline")
            data["dvr_list"]     = [dict(d) for d in dvrs]
        except Exception:
            data["total_dvrs"] = data["online_dvrs"] = data["offline_dvrs"] = 0
            data["dvr_list"] = []

        # ── DB Monitor watches ──
        try:
            cur.execute("""
                SELECT w.display_name, w.schema_name, w.table_name,
                       w.monitoring, w.alerts_enabled, w.last_checked, w.last_status,
                       c.name AS connection_name, c.host
                FROM dbmon_watches w
                JOIN dbmon_connections c ON c.id = w.conn_id
                ORDER BY c.name, w.display_name
            """)
            watches = cur.fetchall()
            data["db_watches"]      = len(watches)
            data["db_watches_dead"] = sum(1 for w in watches if w["last_status"] == "dead")
            data["db_watch_list"]   = [dict(w, last_checked=str(w["last_checked"])) for w in watches]
        except Exception:
            data["db_watches"] = data["db_watches_dead"] = 0
            data["db_watch_list"] = []

    return data


def _build_prompt(data):
    """Build a concise, structured prompt for Claude."""
    lines = [
        "You are an infrastructure monitoring assistant for REFORMMED, a healthcare analytics platform.",
        "Analyze the following real-time data from the REFORMMED Monitor system and provide a clear, actionable summary.",
        "",
        "## Infrastructure Snapshot",
        f"- Machines: {data['online_machines']} online / {data['offline_machines']} offline (total: {data['total_machines']})",
        f"- DVRs: {data['online_dvrs']} online / {data['offline_dvrs']} offline (total: {data['total_dvrs']})",
        f"- DB Monitor watches: {data['db_watches']} total, {data['db_watches_dead']} in DEAD state",
        f"- Alerts in last 24h: {data['alerts_24h']} ({data['alerts_failed']} failed to send)",
        "",
        "## Machine Metrics (latest readings)",
    ]
    for m in data["machine_metrics"]:
        status_flag = "🔴 OFFLINE" if m["status"] == "offline" else "🟢"
        lines.append(f"  {status_flag} {m['system_name']} ({m['location']}): "
                     f"CPU {m['cpu']}%, RAM {m['ram']}%, Temp {m['temp']}°C")
        for disk in (m["disks"] or []):
            pct = disk.get("percent", 0)
            flag = " ⚠️ HIGH" if pct > 85 else ""
            lines.append(f"    Disk {disk.get('mountpoint','?')}: {pct}% used{flag}")

    if data["offline_machines"] > 0:
        offline = [m["system_name"] for m in data["machines"] if m["status"] == "offline"]
        lines.append(f"\n## Offline Machines\n  {', '.join(offline)}")

    if data["recent_alerts"]:
        lines.append("\n## Recent Alerts (last 24h, up to 20)")
        for a in data["recent_alerts"][:10]:
            lines.append(f"  [{a['source']}] {a['alert_type']} — {a['machine_key']}: {a['subject']}")

    if data["db_watch_list"]:
        lines.append("\n## DB Monitor Watches")
        for w in data["db_watch_list"]:
            status = w.get("last_status") or "unknown"
            flag = " ⚠️ DEAD" if status == "dead" else ""
            lines.append(f"  {w['connection_name']}.{w['display_name']}: {status}{flag}")

    lines += [
        "",
        "## Your Task",
        "Provide a structured summary with these sections:",
        "1. **Overall Health** — one sentence verdict (healthy / degraded / critical)",
        "2. **Issues Requiring Attention** — list only real problems (offline machines, high CPU/RAM/disk, dead DB watches, alert spikes)",
        "3. **Machine Status** — brief per-machine summary, highlight anything above 80% CPU/RAM or 85% disk",
        "4. **DVR Status** — any offline DVRs",
        "5. **Recommendations** — 2-3 specific, actionable next steps",
        "",
        "Be concise. Use bullet points. Flag critical issues clearly. Do not repeat data that is already normal.",
    ]
    return "\n".join(lines)


@review_bp.route("/")
@login_required
def index():
    if not current_user.is_admin:
        abort(403)
    return render_template("review.html")


@review_bp.route("/stream")
@login_required
def stream():
    if not current_user.is_admin:
        abort(403)

    def generate():
        import urllib.request
        import urllib.error

        try:
            data   = _collect_data()
            prompt = _build_prompt(data)

            req = urllib.request.Request(
                _gemini_url(stream=True),
                data=_gemini_payload(prompt),
                headers=_gemini_headers(),
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line.startswith("data:"):
                        continue
                    chunk = line[5:].strip()
                    if not chunk:
                        continue
                    try:
                        obj = json.loads(chunk)
                        delta = _extract_gemini_text(obj)
                        if delta:
                            yield f"data:{json.dumps({'text': delta})}\n\n"
                    except Exception:
                        pass
            yield "data:{\"done\":true}\n\n"

        except Exception as e:
            if isinstance(e, urllib.error.HTTPError):
                try:
                    body = e.read().decode()
                except Exception:
                    body = ""
                print(f"[review stream] Gemini API error {e.code}: {body}")
                yield f"data:{json.dumps({'error': f'Gemini API error {e.code}: {body}'})}\n\n"
            else:
                print(f"[review stream] Non-HTTP error ({type(e).__name__}): {e}")
                yield f"data:{json.dumps({'error': f'{type(e).__name__}: {e}'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@review_bp.route("/run", methods=["POST"])
@login_required
def run():
    """Non-streaming review endpoint — avoids nginx SSE buffering issues."""
    if not current_user.is_admin:
        abort(403)
    import urllib.request, urllib.error
    try:
        data   = _collect_data()
        prompt = _build_prompt(data)
        req = urllib.request.Request(
            _gemini_url(stream=False),
            data=_gemini_payload(prompt),
            headers=_gemini_headers(),
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode())
            text = _extract_gemini_text(result)
            return jsonify({"text": text})
    except urllib.error.HTTPError as e:
        # Gemini's real reason lives in the response body, not in str(e)
        # (which is just the generic "HTTP Error 400: Bad Request").
        try:
            body = e.read().decode()
        except Exception:
            body = ""
        print(f"[review] Gemini API error {e.code}: {body}")
        return jsonify({"error": f"Gemini API error {e.code}: {body}"}), 500
    except Exception as e:
        print(f"[review] Non-HTTP error ({type(e).__name__}): {e}")
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500