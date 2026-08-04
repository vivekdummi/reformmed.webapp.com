"""
REFORMMED Monitor API — Receives metrics from agents
Improvements:
  - SQL injection protection via table_name whitelist validation
  - /machines endpoint to list registered machines
  - /machines/{table_name}/status endpoint for individual machine status
  - Proper startup/shutdown lifespan handler (replaces deprecated @app.on_event)
"""
import re
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import asyncpg
from fastapi import FastAPI, HTTPException, Header, Request

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("api")

DB_HOST = os.getenv("POSTGRES_HOST")
DB_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME = os.getenv("POSTGRES_DB")
DB_USER = os.getenv("POSTGRES_USER")
DB_PASS = os.getenv("POSTGRES_PASSWORD")
API_SECRET = os.getenv("API_SECRET")

# ── table name safety ────────────────────────────────────────────────────────
# Table names are built from user-supplied system_name + location.
# We only allow lowercase letters, digits, and underscores, max 60 chars.
_TABLE_RE = re.compile(r"^[a-z0-9_]{1,60}$")

def _safe_table_name(system_name: str, location: str) -> str:
    """Build and validate a table name from user input. Raises 400 on bad input."""
    def _slug(s: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", s.lower().strip()).strip("_")

    table_name = f"machine_{_slug(system_name)}_{_slug(location)}"
    if not _TABLE_RE.match(table_name):
        raise HTTPException(400, f"Invalid system_name/location produces unsafe table name: {table_name!r}")
    return table_name

def _assert_known_table(table_name: str, known: set[str]):
    """Reject table names not in the registry whitelist (prevents 2nd-order injection)."""
    if not _TABLE_RE.match(table_name):
        raise HTTPException(400, "Invalid table_name format")
    if table_name not in known:
        raise HTTPException(404, f"Unknown machine table: {table_name!r}")

# ── pool + registry whitelist ────────────────────────────────────────────────
pool: asyncpg.Pool | None = None
registered_tables: set[str] = set()   # in-memory whitelist populated at startup & registration

async def _load_registered_tables(conn):
    """Populate whitelist from DB (called at startup and after each registration)."""
    rows = await conn.fetch("SELECT table_name FROM machine_registry")
    for r in rows:
        registered_tables.add(r["table_name"])

@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS,
        min_size=5, max_size=20,
    )
    # Ensure registry table exists and pre-load known tables
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS machine_registry (
                id SERIAL PRIMARY KEY,
                system_name TEXT,
                location TEXT,
                table_name TEXT UNIQUE,
                os_type TEXT,
                hostname TEXT,
                public_ip TEXT,
                registered_at TIMESTAMPTZ DEFAULT NOW(),
                last_seen TIMESTAMPTZ,
                status TEXT DEFAULT 'offline'
            )
        """)
        await _load_registered_tables(conn)
    log.info(f"✅ Connected to {DB_HOST} as {DB_USER} — {len(registered_tables)} machines loaded")
    yield
    await pool.close()

app = FastAPI(title="REFORMMED Monitor API", lifespan=lifespan)

# ── auth helper ──────────────────────────────────────────────────────────────
def _check_auth(x_api_key: str):
    if x_api_key != API_SECRET:
        raise HTTPException(401, "Invalid API key")

# ── endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/machines")
async def list_machines(x_api_key: str = Header(...)):
    """Return all registered machines with their current status."""
    _check_auth(x_api_key)
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT system_name, location, table_name, os_type, hostname,
                   public_ip, registered_at, last_seen, status
            FROM machine_registry
            ORDER BY system_name, location
        """)
    return [dict(r) for r in rows]


@app.get("/machines/{table_name}/status")
async def machine_status(table_name: str, x_api_key: str = Header(...)):
    """Return the latest metrics snapshot for a specific machine."""
    _check_auth(x_api_key)
    _assert_known_table(table_name, registered_tables)

    async with pool.acquire() as conn:
        reg = await conn.fetchrow(
            "SELECT * FROM machine_registry WHERE table_name = $1", table_name
        )
        if not reg:
            raise HTTPException(404, "Machine not found")

        latest = await conn.fetchrow(
            f"SELECT * FROM {table_name} ORDER BY ts DESC LIMIT 1"  # safe: validated above
        )

    result = dict(reg)
    if latest:
        result["latest_metrics"] = dict(latest)
    return result


@app.post("/register")
async def register(request: Request, x_api_key: str = Header(...)):
    _check_auth(x_api_key)

    data = await request.json()
    system_name = data.get("system_name")
    location = data.get("location")

    if not system_name or not location:
        raise HTTPException(400, "system_name and location required")

    table_name = _safe_table_name(system_name, location)

    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO machine_registry
                (system_name, location, table_name, os_type, hostname, public_ip, last_seen, status)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), 'online')
            ON CONFLICT (table_name) DO UPDATE
            SET last_seen=NOW(), os_type=$4, hostname=$5, public_ip=$6
        """, system_name, location, table_name,
            data.get("os_type"), data.get("hostname"), data.get("public_ip"))

        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id SERIAL PRIMARY KEY,
                ts TIMESTAMPTZ DEFAULT NOW(),
                cpu_percent FLOAT,
                cpu_per_core JSONB,
                cpu_freq_mhz FLOAT,
                cpu_temp FLOAT,
                ram_total_gb FLOAT,
                ram_used_gb FLOAT,
                ram_percent FLOAT,
                swap_total_gb FLOAT,
                swap_used_gb FLOAT,
                swap_percent FLOAT,
                gpu_info JSONB,
                disk_partitions JSONB,
                disk_io JSONB,
                net_bytes_sent BIGINT,
                net_bytes_recv BIGINT,
                net_packets_sent BIGINT,
                net_packets_recv BIGINT,
                public_ip TEXT,
                top_processes JSONB,
                uptime_seconds FLOAT,
                boot_time TIMESTAMPTZ,
                os_version TEXT,
                hostname TEXT,
                status TEXT
            )
        """)
        await conn.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{table_name}_ts ON {table_name}(ts DESC)"
        )
        await _load_registered_tables(conn)

    log.info(f"✅ Registered: {system_name} ({location}) → {table_name}")
    return {"table_name": table_name}


@app.post("/metrics")
async def metrics(request: Request, x_api_key: str = Header(...)):
    _check_auth(x_api_key)

    data = await request.json()
    table_name = data.get("table_name")

    if not table_name:
        raise HTTPException(400, "table_name required")

    # Validate against whitelist — prevents SQL injection via table_name
    _assert_known_table(table_name, registered_tables)

    cpu_per_core    = json.dumps(data.get("cpu_per_core"))    if data.get("cpu_per_core")    else None
    gpu_info        = json.dumps(data.get("gpu_info"))        if data.get("gpu_info")        else None
    disk_partitions = json.dumps(data.get("disk_partitions")) if data.get("disk_partitions") else None
    disk_io         = json.dumps(data.get("disk_io"))         if data.get("disk_io")         else None
    top_processes   = json.dumps(data.get("top_processes"))   if data.get("top_processes")   else None

    boot_time_str = data.get("boot_time")
    boot_time = datetime.fromisoformat(boot_time_str) if boot_time_str else None

    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE machine_registry
            SET last_seen=NOW(), public_ip=$2, hostname=$3
            WHERE table_name=$1
        """, table_name, data.get("public_ip"), data.get("hostname"))

        await conn.execute(f"""
            INSERT INTO {table_name} (
                cpu_percent, cpu_per_core, cpu_freq_mhz, cpu_temp,
                ram_total_gb, ram_used_gb, ram_percent,
                swap_total_gb, swap_used_gb, swap_percent,
                gpu_info, disk_partitions, disk_io,
                net_bytes_sent, net_bytes_recv, net_packets_sent, net_packets_recv,
                public_ip, top_processes, uptime_seconds, boot_time, os_version, hostname, status
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                $11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24
            )
        """,
        data.get("cpu_percent"), cpu_per_core, data.get("cpu_freq_mhz"), data.get("cpu_temp"),
        data.get("ram_total_gb"), data.get("ram_used_gb"), data.get("ram_percent"),
        data.get("swap_total_gb"), data.get("swap_used_gb"), data.get("swap_percent"),
        gpu_info, disk_partitions, disk_io,
        data.get("net_bytes_sent"), data.get("net_bytes_recv"),
        data.get("net_packets_sent"), data.get("net_packets_recv"),
        data.get("public_ip"), top_processes, data.get("uptime_seconds"),
        boot_time, data.get("os_version"), data.get("hostname"), data.get("status"))

    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("API_HOST", "0.0.0.0"), port=int(os.getenv("API_PORT", "8000")))