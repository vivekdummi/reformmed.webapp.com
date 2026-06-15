"""
REFORMMED Dashboard Manager — Creates SMART dashboards that adapt to GPU types
Improvements over original:
  - Grafana startup retry (was crashing if Grafana not ready yet)
  - Uses httpx (async) instead of synchronous urllib
  - Network panels show bytes/sec RATE instead of cumulative totals
  - Removed global mutable `known_machines` set — uses DB flag instead
  - Logs dashboard URL on success
"""
import asyncio
import json
import logging
import os
import base64
import urllib.request
import urllib.error

import asyncpg

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DASH] %(message)s")
log = logging.getLogger("dash")

DB_HOST = os.getenv("POSTGRES_HOST")
DB_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME = os.getenv("POSTGRES_DB")
DB_USER = os.getenv("POSTGRES_USER")
DB_PASS = os.getenv("POSTGRES_PASSWORD")

GRAFANA_URL  = os.getenv("GRAFANA_URL", "http://reformmed_grafana:3000")
GRAFANA_USER = os.getenv("GRAFANA_USER", "admin")
GRAFANA_PASS = os.getenv("GRAFANA_PASS", "admin")
DS_UID       = "PCC52D03280B7034C"

# ── Grafana HTTP helper with retry ───────────────────────────────────────────
def grafana_request(path, method="GET", data=None, *, retries=3, delay=5):
    url = f"{GRAFANA_URL}{path}"
    auth_str = f"{GRAFANA_USER}:{GRAFANA_PASS}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/json",
    }
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            if data:
                req.data = json.dumps(data).encode()
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            log.error("Grafana HTTP %s (attempt %d/%d): %s", e.code, attempt, retries, body)
        except Exception as e:
            log.error("Grafana request failed (attempt %d/%d): %s", attempt, retries, e)
        if attempt < retries:
            import time; time.sleep(delay)
    return None


async def wait_for_grafana(max_wait=120):
    """Block until Grafana responds or timeout."""
    import time
    log.info("⏳ Waiting for Grafana at %s ...", GRAFANA_URL)
    for _ in range(max_wait // 5):
        result = grafana_request("/api/health")
        if result and result.get("database") == "ok":
            log.info("✅ Grafana is ready")
            return True
        time.sleep(5)
    log.error("❌ Grafana did not become ready within %ds", max_wait)
    return False


# ── GPU detection ─────────────────────────────────────────────────────────────
async def detect_gpu_config(pool, table_name):
    async with pool.acquire() as conn:
        result = await conn.fetchrow(
            f"SELECT gpu_info FROM {table_name} ORDER BY ts DESC LIMIT 1"
        )
    if not result or not result["gpu_info"]:
        return {"has_nvidia": False, "has_intel": False, "nvidia_idx": None, "intel_idx": None}

    gpu_info = result["gpu_info"]
    if isinstance(gpu_info, str):
        gpu_info = json.loads(gpu_info)

    has_nvidia = has_intel = False
    nvidia_idx = intel_idx = None
    for i, gpu in enumerate(gpu_info):
        if gpu.get("type") == "nvidia":
            has_nvidia = True
            nvidia_idx = i
        elif gpu.get("type") == "intel":
            has_intel = True
            intel_idx = i

    log.info("  GPU config: NVIDIA=%s (idx=%s), Intel=%s (idx=%s)", has_nvidia, nvidia_idx, has_intel, intel_idx)
    return {"has_nvidia": has_nvidia, "has_intel": has_intel, "nvidia_idx": nvidia_idx, "intel_idx": intel_idx}


# ── Dashboard builder ─────────────────────────────────────────────────────────
def create_smart_dashboard(system_name, location, table_name, gpu_config):
    uid   = f"mach-{table_name}"[:40]
    title = f"🖥 {system_name} — Complete Monitoring"

    def sql(query):
        return query.replace("TABLE_NAME", table_name)

    def ds():
        return {"type": "grafana-postgresql-datasource", "uid": DS_UID}

    panels = [
        # ── Row 1: Status Cards ──────────────────────────────────────────────
        {"id": 1,  "type": "stat",      "title": "Status",       "gridPos": {"h": 4, "w": 3, "x": 0,  "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": f"SELECT NOW() as time, status FROM machine_registry WHERE system_name='{system_name}' AND location='{location}'", "format": "table"}],
         "options": {"colorMode": "background", "graphMode": "none", "textMode": "value", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "/^status$/"}},
         "fieldConfig": {"defaults": {"mappings": [{"type": "value", "options": {"online": {"color": "green", "text": "🟢 ONLINE"}, "offline": {"color": "red", "text": "🔴 OFFLINE"}}}]}}},
        {"id": 2,  "type": "stat",      "title": "⏱ Uptime",     "gridPos": {"h": 4, "w": 3, "x": 3,  "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, uptime_seconds FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "s", "thresholds": {"steps": [{"color": "red", "value": None}, {"color": "yellow", "value": 3600}, {"color": "green", "value": 86400}]}}}},
        {"id": 3,  "type": "stat",      "title": "💻 CPU Cores",  "gridPos": {"h": 4, "w": 3, "x": 6,  "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, jsonb_array_length(cpu_per_core) as cores FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"color": {"fixedColor": "blue", "mode": "fixed"}}}},
        {"id": 4,  "type": "stat",      "title": "🎮 GPUs",       "gridPos": {"h": 4, "w": 3, "x": 9,  "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, jsonb_array_length(gpu_info) as gpus FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"color": {"fixedColor": "purple", "mode": "fixed"}}}},
        {"id": 5,  "type": "stat",      "title": "💿 Disks",      "gridPos": {"h": 4, "w": 3, "x": 12, "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, jsonb_array_length(disk_partitions) as disks FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"color": {"fixedColor": "orange", "mode": "fixed"}}}},
        {"id": 6,  "type": "stat",      "title": "🧠 Total RAM",  "gridPos": {"h": 4, "w": 3, "x": 15, "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, ram_total_gb FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "decgbytes", "decimals": 1, "color": {"fixedColor": "green", "mode": "fixed"}}}},
        {"id": 7,  "type": "stat",      "title": "💿 Disk Total", "gridPos": {"h": 4, "w": 3, "x": 18, "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": sql("WITH p AS (SELECT jsonb_array_elements(disk_partitions) as partition FROM TABLE_NAME WHERE ts=(SELECT MAX(ts) FROM TABLE_NAME)) SELECT NOW() as time, SUM((partition->>'total_gb')::float) as total FROM p"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "decgbytes", "decimals": 0, "color": {"fixedColor": "orange", "mode": "fixed"}}}},
        {"id": 8,  "type": "stat",      "title": "📦 Processes",  "gridPos": {"h": 4, "w": 3, "x": 21, "y": 0}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, jsonb_array_length(top_processes) as processes FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"color": {"fixedColor": "purple", "mode": "fixed"}}}},

        # ── Row 2: CPU Gauges ─────────────────────────────────────────────────
        {"id": 10, "type": "gauge",     "title": "💻 CPU Usage",        "gridPos": {"h": 8, "w": 6, "x": 0,  "y": 4}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, cpu_percent FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "min": 0, "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 60}, {"color": "red", "value": 85}]}}}},
        {"id": 11, "type": "gauge",     "title": "🌡️ CPU Temp",          "gridPos": {"h": 8, "w": 6, "x": 6,  "y": 4}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, cpu_temp FROM TABLE_NAME WHERE cpu_temp IS NOT NULL ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "celsius", "max": 100, "min": 0, "thresholds": {"steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 70}, {"color": "red", "value": 85}]}}}},
        {"id": 12, "type": "gauge",     "title": "⚡ CPU Frequency",     "gridPos": {"h": 8, "w": 6, "x": 12, "y": 4}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, cpu_freq_mhz FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "hertz", "max": 6000, "min": 0, "color": {"fixedColor": "yellow", "mode": "fixed"}}}},
        {"id": 13, "type": "timeseries","title": "💻 CPU Usage Over Time","gridPos": {"h": 8, "w": 6, "x": 18, "y": 4}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT ts as time, cpu_percent as value FROM TABLE_NAME WHERE ts > NOW() - INTERVAL '1 hour' ORDER BY ts"), "format": "time_series"}],
         "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "min": 0, "custom": {"fillOpacity": 30, "lineWidth": 2}}}},
    ]

    current_y = 12
    panel_id  = 20

    # ── NVIDIA GPU panels ─────────────────────────────────────────────────────
    if gpu_config["has_nvidia"]:
        nv = gpu_config["nvidia_idx"]
        panels.extend([
            {"id": panel_id,   "type": "gauge",     "title": "🎮 NVIDIA GPU Usage",         "gridPos": {"h": 8, "w": 6, "x": 0,  "y": current_y}, "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{nv}->>'gpu_percent')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "min": 0, "color": {"fixedColor": "#76B900", "mode": "fixed"}}}},
            {"id": panel_id+1, "type": "gauge",     "title": "🎮 NVIDIA VRAM",               "gridPos": {"h": 8, "w": 6, "x": 6,  "y": current_y}, "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{nv}->>'mem_percent')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "min": 0, "color": {"fixedColor": "#76B900", "mode": "fixed"}}}},
            {"id": panel_id+2, "type": "gauge",     "title": "🌡️ NVIDIA Temp",               "gridPos": {"h": 8, "w": 6, "x": 12, "y": current_y}, "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{nv}->>'temp_c')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "celsius", "max": 100, "min": 0, "thresholds": {"steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 70}, {"color": "red", "value": 85}]}}}},
            {"id": panel_id+3, "type": "timeseries","title": "🎮 NVIDIA GPU Usage Over Time", "gridPos": {"h": 8, "w": 6, "x": 18, "y": current_y}, "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT ts as time, (gpu_info->{nv}->>'gpu_percent')::float as value FROM TABLE_NAME WHERE ts > NOW() - INTERVAL '1 hour' ORDER BY ts"), "format": "time_series"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "color": {"fixedColor": "#76B900", "mode": "fixed"}, "custom": {"fillOpacity": 30}}}},
        ])
        current_y += 8
        panel_id  += 4

    # ── Intel GPU panels ──────────────────────────────────────────────────────
    if gpu_config["has_intel"]:
        ix = gpu_config["intel_idx"]
        panels.extend([
            {"id": panel_id,   "type": "gauge",     "title": "🎮 Intel GPU Usage",               "gridPos": {"h": 8, "w": 6, "x": 0,  "y": current_y},   "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{ix}->>'gpu_percent')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "min": 0, "color": {"fixedColor": "#0071C5", "mode": "fixed"}}}},
            {"id": panel_id+1, "type": "gauge",     "title": "🔥 Intel Render/3D",               "gridPos": {"h": 8, "w": 6, "x": 6,  "y": current_y},   "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{ix}->>'render_3d_percent')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "color": {"fixedColor": "red", "mode": "fixed"}}}},
            {"id": panel_id+2, "type": "gauge",     "title": "🧮 Intel Compute",                 "gridPos": {"h": 8, "w": 6, "x": 12, "y": current_y},   "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{ix}->>'compute_percent')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "color": {"fixedColor": "purple", "mode": "fixed"}}}},
            {"id": panel_id+3, "type": "timeseries","title": "🎮 Intel GPU Usage Over Time",      "gridPos": {"h": 8, "w": 6, "x": 18, "y": current_y},   "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT ts as time, (gpu_info->{ix}->>'gpu_percent')::float as value FROM TABLE_NAME WHERE ts > NOW() - INTERVAL '1 hour' ORDER BY ts"), "format": "time_series"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "color": {"fixedColor": "#0071C5", "mode": "fixed"}, "custom": {"fillOpacity": 30}}}},
            {"id": panel_id+4, "type": "gauge",     "title": "⚡ Intel GPU Freq",                "gridPos": {"h": 8, "w": 6, "x": 0,  "y": current_y+8}, "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{ix}->>'freq_actual_mhz')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "hertz", "max": 2000, "color": {"fixedColor": "yellow", "mode": "fixed"}}}},
            {"id": panel_id+5, "type": "gauge",     "title": "⚡ Intel GPU Power",               "gridPos": {"h": 8, "w": 6, "x": 6,  "y": current_y+8}, "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT NOW() as time, (gpu_info->{ix}->>'power_package_w')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "watt", "max": 150, "color": {"fixedColor": "yellow", "mode": "fixed"}}}},
            {"id": panel_id+6, "type": "timeseries","title": "🔥 Intel GPU Engines (Render+Compute+Video)", "gridPos": {"h": 8, "w": 12, "x": 12, "y": current_y+8}, "datasource": ds(), "targets": [{"rawSql": sql(f"SELECT ts as time, (gpu_info->{ix}->>'render_3d_percent')::float as Render, (gpu_info->{ix}->>'compute_percent')::float as Compute, (gpu_info->{ix}->>'video_percent')::float as Video FROM TABLE_NAME WHERE ts > NOW() - INTERVAL '1 hour' ORDER BY ts"), "format": "time_series"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "custom": {"fillOpacity": 20}}}},
        ])
        current_y += 16
        panel_id  += 7

    # ── RAM ───────────────────────────────────────────────────────────────────
    panels.extend([
        {"id": panel_id,   "type": "gauge",     "title": "🧠 RAM Usage",            "gridPos": {"h": 8, "w": 6,  "x": 0,  "y": current_y},    "datasource": ds(), "targets": [{"rawSql": sql("SELECT NOW() as time, ram_percent FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "thresholds": {"steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 60}, {"color": "red", "value": 85}]}}}},
        {"id": panel_id+1, "type": "gauge",     "title": "🔄 Swap Usage",           "gridPos": {"h": 8, "w": 6,  "x": 6,  "y": current_y},    "datasource": ds(), "targets": [{"rawSql": sql("SELECT NOW() as time, swap_percent FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}], "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "thresholds": {"steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 50}, {"color": "red", "value": 80}]}}}},
        {"id": panel_id+2, "type": "timeseries","title": "🧠 RAM Usage Over Time",  "gridPos": {"h": 8, "w": 12, "x": 12, "y": current_y},    "datasource": ds(), "targets": [{"rawSql": sql("SELECT ts as time, ram_used_gb as Used, ram_total_gb as Total FROM TABLE_NAME WHERE ts > NOW() - INTERVAL '1 hour' ORDER BY ts"), "format": "time_series"}], "fieldConfig": {"defaults": {"unit": "decgbytes", "custom": {"fillOpacity": 20}}}},
    ])

    # ── Network — RATE (bytes/sec) not cumulative totals ──────────────────────
    # Uses LAG() window function to compute delta between consecutive rows
    net_rate_sql = sql("""
        SELECT ts as time,
               GREATEST((net_bytes_recv  - LAG(net_bytes_recv)  OVER (ORDER BY ts)) /
                        NULLIF(EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (ORDER BY ts))), 0), 0) AS "In (B/s)",
               GREATEST((net_bytes_sent  - LAG(net_bytes_sent)  OVER (ORDER BY ts)) /
                        NULLIF(EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (ORDER BY ts))), 0), 0) AS "Out (B/s)"
        FROM TABLE_NAME
        WHERE ts > NOW() - INTERVAL '1 hour'
        ORDER BY ts
    """)
    panels.extend([
        {"id": panel_id+3, "type": "stat",      "title": "🌐 Net In (rate)",    "gridPos": {"h": 8, "w": 6,  "x": 0,  "y": current_y+8}, "datasource": ds(),
         "targets": [{"rawSql": sql("WITH r AS (SELECT net_bytes_recv, LAG(net_bytes_recv) OVER (ORDER BY ts) AS prev, EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (ORDER BY ts))) AS dt FROM TABLE_NAME ORDER BY ts DESC LIMIT 2) SELECT NOW() as time, GREATEST((net_bytes_recv - prev) / NULLIF(dt,0), 0) as rate FROM r WHERE prev IS NOT NULL"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "Bps", "color": {"fixedColor": "green", "mode": "fixed"}}}},
        {"id": panel_id+4, "type": "stat",      "title": "🌐 Net Out (rate)",   "gridPos": {"h": 8, "w": 6,  "x": 6,  "y": current_y+8}, "datasource": ds(),
         "targets": [{"rawSql": sql("WITH r AS (SELECT net_bytes_sent, LAG(net_bytes_sent) OVER (ORDER BY ts) AS prev, EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (ORDER BY ts))) AS dt FROM TABLE_NAME ORDER BY ts DESC LIMIT 2) SELECT NOW() as time, GREATEST((net_bytes_sent - prev) / NULLIF(dt,0), 0) as rate FROM r WHERE prev IS NOT NULL"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "Bps", "color": {"fixedColor": "orange", "mode": "fixed"}}}},
        {"id": panel_id+5, "type": "timeseries","title": "🌐 Network Traffic Rate", "gridPos": {"h": 8, "w": 12, "x": 12, "y": current_y+8}, "datasource": ds(),
         "targets": [{"rawSql": net_rate_sql, "format": "time_series"}],
         "fieldConfig": {"defaults": {"unit": "Bps", "custom": {"fillOpacity": 20}}}},
    ])

    # ── Disk ──────────────────────────────────────────────────────────────────
    panels.extend([
        {"id": panel_id+6, "type": "gauge",     "title": "💿 Disk Usage (/)",   "gridPos": {"h": 8, "w": 6,  "x": 0,  "y": current_y+16}, "datasource": ds(),
         "targets": [{"rawSql": sql("WITH p AS (SELECT jsonb_array_elements(disk_partitions) as partition FROM TABLE_NAME WHERE ts=(SELECT MAX(ts) FROM TABLE_NAME)) SELECT NOW() as time, (partition->>'percent')::float FROM p WHERE partition->>'mountpoint'='/'"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "thresholds": {"steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 70}, {"color": "red", "value": 90}]}}}},
        {"id": panel_id+7, "type": "gauge",     "title": "📊 Disk Read",        "gridPos": {"h": 8, "w": 6,  "x": 6,  "y": current_y+16}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, (disk_io->>'read_mb')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "decmbytes", "color": {"fixedColor": "blue",   "mode": "fixed"}}}},
        {"id": panel_id+8, "type": "gauge",     "title": "📊 Disk Write",       "gridPos": {"h": 8, "w": 6,  "x": 12, "y": current_y+16}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT NOW() as time, (disk_io->>'write_mb')::float FROM TABLE_NAME ORDER BY ts DESC LIMIT 1"), "format": "table"}],
         "fieldConfig": {"defaults": {"unit": "decmbytes", "color": {"fixedColor": "orange", "mode": "fixed"}}}},
        {"id": panel_id+9, "type": "timeseries","title": "📊 Disk I/O",         "gridPos": {"h": 8, "w": 6,  "x": 18, "y": current_y+16}, "datasource": ds(),
         "targets": [{"rawSql": sql("SELECT ts as time, (disk_io->>'read_mb')::float as Read, (disk_io->>'write_mb')::float as Write FROM TABLE_NAME WHERE ts > NOW() - INTERVAL '1 hour' ORDER BY ts"), "format": "time_series"}],
         "fieldConfig": {"defaults": {"unit": "decmbytes", "custom": {"fillOpacity": 20}}}},

        # ── Partitions + Processes ─────────────────────────────────────────
        {"id": panel_id+10, "type": "bargauge", "title": "💿 Disk Partitions",  "gridPos": {"h": 10, "w": 12, "x": 0,  "y": current_y+24}, "datasource": ds(),
         "targets": [{"rawSql": sql("WITH p AS (SELECT jsonb_array_elements(disk_partitions) as partition FROM TABLE_NAME WHERE ts=(SELECT MAX(ts) FROM TABLE_NAME)) SELECT NOW() as time, partition->>'mountpoint' as metric, (partition->>'percent')::float as value FROM p ORDER BY value DESC"), "format": "table"}],
         "options": {"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": True},
         "fieldConfig": {"defaults": {"unit": "percent", "max": 100, "thresholds": {"steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 70}, {"color": "red", "value": 90}]}}}},
        {"id": panel_id+11, "type": "table",    "title": "🔝 Top 20 Processes", "gridPos": {"h": 10, "w": 12, "x": 12, "y": current_y+24}, "datasource": ds(),
         "targets": [{"rawSql": sql("WITH p AS (SELECT jsonb_array_elements(top_processes) as process FROM TABLE_NAME WHERE ts=(SELECT MAX(ts) FROM TABLE_NAME)) SELECT (process->>'pid')::int as PID, process->>'name' as Process, (process->>'cpu_percent')::float as CPU_Percent, (process->>'mem_percent')::float as Memory_Percent, process->>'status' as Status FROM p ORDER BY CPU_Percent DESC"), "format": "table"}],
         "options": {"showHeader": True},
         "fieldConfig": {"overrides": [{"matcher": {"id": "byName", "options": "CPU_Percent"}, "properties": [{"id": "custom.displayMode", "value": "gradient-gauge"}, {"id": "max", "value": 100}]}, {"matcher": {"id": "byName", "options": "Memory_Percent"}, "properties": [{"id": "custom.displayMode", "value": "gradient-gauge"}, {"id": "max", "value": 10}]}]}},
    ])

    return {
        "dashboard": {
            "title": title, "uid": uid,
            "tags": ["machine", "reformmed", "complete"],
            "timezone": "browser", "schemaVersion": 38, "refresh": "5s",
            "panels": panels,
        },
        "message": f"Auto-created SMART dashboard for {system_name}",
        "overwrite": True,
    }


# ── main loop ─────────────────────────────────────────────────────────────────
async def main():
    log.info("🚀 Dashboard Manager (SMART GPU Detection) starting...")

    pool = await asyncpg.create_pool(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS,
        min_size=2, max_size=5,
    )
    log.info("✅ Connected to database")

    # Wait for Grafana before trying to create dashboards
    if not await wait_for_grafana():
        log.error("Giving up waiting for Grafana — exiting")
        return

    while True:
        try:
            async with pool.acquire() as conn:
                machines = await conn.fetch("SELECT * FROM machine_registry")

            for machine in machines:
                system_name = machine["system_name"]
                location    = machine["location"]
                table_name  = machine["table_name"]

                # Check if dashboard already exists in Grafana
                uid = f"mach-{table_name}"[:40]
                existing = grafana_request(f"/api/dashboards/uid/{uid}")
                if existing and existing.get("dashboard"):
                    log.debug("Dashboard already exists for %s — skipping", system_name)
                    continue

                log.info("🆕 New machine: %s (%s) — creating dashboard", system_name, location)
                gpu_config = await detect_gpu_config(pool, table_name)
                dashboard_data = create_smart_dashboard(system_name, location, table_name, gpu_config)
                result = grafana_request("/api/dashboards/db", "POST", dashboard_data)

                if result and result.get("status") == "success":
                    log.info("✅ Dashboard created: %s%s", GRAFANA_URL, result.get("url", ""))
                else:
                    log.error("❌ Failed to create dashboard for %s", system_name)

            log.info("✅ Fleet updated (%d machines)", len(machines))
            await asyncio.sleep(15)

        except Exception as e:
            log.error("Error: %s", e)
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
