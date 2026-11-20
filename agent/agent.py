#!/usr/bin/env python3
import os, sys, time, psutil, requests, json, platform, socket, logging, subprocess
import pwd, re, shutil
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load .env file
load_dotenv('/opt/reformmed-agent/.env')

logging.basicConfig(level=logging.INFO, format="%(asctime)s [AGENT] %(message)s")
log = logging.getLogger("agent")

# Read config from environment
API_URL = os.getenv("REFORMMED_API_URL", "http://localhost:8000")
API_KEY = os.getenv("REFORMMED_API_SECRET", "")
SYSTEM_NAME = os.getenv("REFORMMED_SYSTEM_NAME", "unknown")
LOCATION = os.getenv("REFORMMED_LOCATION", "unknown")
INTERVAL = int(os.getenv("REFORMMED_INTERVAL", "15"))

# GPU detection
GPU_TYPE = None
HAS_NVIDIA = False
HAS_INTEL = False

try:
    import pynvml
    pynvml.nvmlInit()
    GPU_TYPE = "NVIDIA"
    HAS_NVIDIA = True
    log.info(f"✅ NVIDIA GPU detected ({pynvml.nvmlDeviceGetCount()} device(s))")
except:
    pass

try:
    result = os.popen("lspci | grep -i vga").read().lower()
    if "intel" in result:
        GPU_TYPE = "Intel" if not GPU_TYPE else f"{GPU_TYPE} Intel"
        HAS_INTEL = True
        log.info(f"✅ Intel GPU detected: {result.strip()}")
except:
    pass

# ── PM2 detection ──────────────────────────────────────────────────────────
# A machine can run several PM2 daemons — one per user who started PM2
# (e.g. root's /root/.pm2 AND adminqa's /home/adminqa/.pm2). `pm2 jlist`
# only talks to the daemon of whoever runs it, so we find every running
# daemon and query each one as its own user. Run the agent as root to see
# every user's daemon; as a normal user it only sees its own.
#
# Daemons are found two ways, since the "PM2 vX: God Daemon (<home>)"
# process title can be truncated or missing (short argv, old PM2):
#   1. <home>/pm2.pid files under /root and /home/* whose pid is alive
#   2. any process whose command line mentions "God Daemon"
# Only daemons that are already running are queried, so the agent never
# spawns a new (empty) PM2 daemon the way a bare `pm2 jlist` does.
_PM2_DAEMON_RE = re.compile(r"God Daemon \((.+?)\)")
_PM2_DAEMON_CACHE_SECS = 60
# `pm2 jlist` starts a node process per daemon — don't do that on every send
# when REFORMMED_INTERVAL is short; reuse the last list for this long.
PM2_REFRESH_SECS = int(os.getenv("REFORMMED_PM2_REFRESH_SECS", "10"))
_pm2_daemon_cache = {"ts": 0.0, "daemons": []}
_pm2_result_cache = {"ts": 0.0, "procs": []}
_pm2_warned = set()
_AGENT_USER = pwd.getpwuid(os.geteuid()).pw_name
_IS_ROOT = os.geteuid() == 0


def _user_of_uid(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def _daemon_info(proc, home, user=None):
    try:
        node_dir = os.path.dirname(proc.exe())
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        node_dir = None
    if not user:
        try:
            user = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            user = None
    return {"user": user or _AGENT_USER, "home": os.path.realpath(home),
            "node_dir": node_dir, "pid": proc.pid}


def _find_pm2_daemons(force=False):
    """[{user, home, node_dir, pid}] for every running PM2 daemon (cached 60s)."""
    now = time.time()
    if not force and now - _pm2_daemon_cache["ts"] < _PM2_DAEMON_CACHE_SECS:
        return _pm2_daemon_cache["daemons"]
    found = {}

    # 1. pid files — works whatever the daemon's process title looks like.
    homes = ["/root/.pm2"]
    try:
        homes += [os.path.join("/home", d, ".pm2") for d in os.listdir("/home")]
    except OSError:
        pass
    for home in homes:
        pid_file = os.path.join(home, "pm2.pid")
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            proc = psutil.Process(pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                continue
            info = _daemon_info(proc, home, _user_of_uid(os.stat(pid_file).st_uid))
            found.setdefault(info["home"], info)
        except (OSError, ValueError, psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 2. process titles — catches a PM2_HOME outside /root and /home.
    known_pids = {d["pid"] for d in found.values()}
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if p.pid in known_pids:
                continue
            cmd = " ".join(p.info['cmdline'] or []) or (p.info['name'] or "")
            if "God Daemon" not in cmd:
                continue
            m = _PM2_DAEMON_RE.search(cmd)
            home = m.group(1) if m else None
            if not home:
                try:
                    home = p.environ().get("PM2_HOME")
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    home = None
            if not home:
                try:
                    home = os.path.join(pwd.getpwnam(p.username()).pw_dir, ".pm2")
                except (KeyError, psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            info = _daemon_info(p, home)
            found.setdefault(info["home"], info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    _pm2_daemon_cache.update(ts=now, daemons=list(found.values()))
    return _pm2_daemon_cache["daemons"]


def _pm2_binary(node_dir):
    """The pm2 CLI that belongs to the daemon's node install, else whatever is on PATH."""
    candidates = []
    if node_dir:
        candidates.append(os.path.join(node_dir, "pm2"))
    candidates += [shutil.which("pm2"), "/usr/local/bin/pm2", "/usr/bin/pm2"]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def _pm2_jlist(daemon):
    """Raw `pm2 jlist` list for one daemon, run as that daemon's user."""
    user, home, node_dir = daemon["user"], daemon["home"], daemon["node_dir"]
    pm2 = _pm2_binary(node_dir)
    if not pm2:
        if home not in _pm2_warned:
            _pm2_warned.add(home)
            log.warning(f"PM2 daemon for {user} ({home}) found but no pm2 CLI to query it")
        return []

    # pm2 is a `#!/usr/bin/env node` script — node must be on PATH.
    path = os.pathsep.join(x for x in (node_dir, os.path.dirname(pm2),
                                       os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")) if x)
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        pw = None
    env = dict(os.environ, PM2_HOME=home, PATH=path,
               HOME=pw.pw_dir if pw else os.path.dirname(home))

    kwargs = {}
    if user != _AGENT_USER:
        if not (_IS_ROOT and pw):
            if home not in _pm2_warned:
                _pm2_warned.add(home)
                log.warning(f"PM2 daemon for {user} ({home}) is running but this agent runs as "
                            f"{_AGENT_USER} — run the agent as root to report it")
            return []
        # Drop to the owner directly (no runuser, so no PAM session lines in
        # the journal on every send) — nothing in their ~/.pm2 ends up root-owned.
        env["USER"] = env["LOGNAME"] = user
        kwargs = {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": []}

    try:
        result = subprocess.run([pm2, "jlist"], capture_output=True, text=True,
                                timeout=10, env=env, **kwargs)
    except Exception as e:
        log.debug(f"pm2 jlist failed for {user}: {e}")
        return []
    out = result.stdout or ""
    # pm2 sometimes prints notices (e.g. "In-memory PM2 is out-of-date") before the JSON.
    start = out.find("[")
    if result.returncode != 0 or start == -1:
        if home not in _pm2_warned:
            _pm2_warned.add(home)
            log.warning(f"pm2 jlist for {user} ({home}) failed, exit {result.returncode}: "
                        f"{(result.stderr or out).strip()[:300]}")
        return []
    try:
        data = json.loads(out[start:])
        return data if isinstance(data, list) else []
    except ValueError:
        log.debug(f"pm2 jlist for {user}: unparseable output")
        return []


_startup_daemons = _find_pm2_daemons(force=True)
HAS_PM2 = bool(_startup_daemons) or shutil.which("pm2") is not None
if _startup_daemons:
    log.info("✅ PM2 daemons: " + ", ".join(f"{d['user']} ({d['home']})" for d in _startup_daemons))

log.info("=======================================================")
log.info("  REFORMMED Monitor Agent")
log.info(f"  System   : {SYSTEM_NAME}")
log.info(f"  Location : {LOCATION}")
log.info(f"  Server   : {API_URL}")
log.info(f"  GPU      : {GPU_TYPE or 'None'}")
log.info(f"  PM2      : {', '.join(d['user'] for d in _startup_daemons) or ('installed, no daemon running' if HAS_PM2 else 'No')}")
log.info(f"  Run as   : {_AGENT_USER}")
log.info("=======================================================")

# Public IP is cached — refreshed every N seconds instead of on every single send
_public_ip_cache = {"ip": "unknown", "ts": 0}
PUBLIC_IP_REFRESH_SECS = 600

# Process objects persist across loop iterations so psutil.cpu_percent() has a
# real baseline to diff against (a fresh Process object always reports 0.0 on
# its first call).
_proc_cache = {}

def get_public_ip():
    """Cached — refreshed at most once every PUBLIC_IP_REFRESH_SECS, not on every send."""
    now = time.time()
    if now - _public_ip_cache["ts"] > PUBLIC_IP_REFRESH_SECS or _public_ip_cache["ip"] == "unknown":
        try:
            _public_ip_cache["ip"] = requests.get("https://api.ipify.org", timeout=3).text
            _public_ip_cache["ts"] = now
        except Exception:
            pass  # keep last known value on failure
    return _public_ip_cache["ip"]

def get_pm2_processes():
    """
    Every process managed by every PM2 daemon on this machine — e.g. the
    camera analytics workers — so a dead worker shows up in the dashboard
    the same way an offline machine does. Each entry carries pm2_user (the
    daemon it belongs to), since ids repeat across daemons.
    Uses `pm2 jlist` (JSON) rather than parsing the `pm2 list` table.
    """
    now = time.time()
    if now - _pm2_result_cache["ts"] < PM2_REFRESH_SECS:
        return _pm2_result_cache["procs"]
    out = []
    for daemon in _find_pm2_daemons():
        try:
            procs = _pm2_jlist(daemon)
        except Exception as e:
            log.debug(f"PM2 process list error for {daemon['user']}: {e}")
            continue
        for p in procs:
            env = p.get("pm2_env", {}) or {}
            monit = p.get("monit", {}) or {}
            pm_uptime_ms = env.get("pm_uptime")
            uptime_secs = None
            if pm_uptime_ms and env.get("status") == "online":
                uptime_secs = round((time.time() * 1000 - pm_uptime_ms) / 1000, 1)
            out.append({
                "name":         p.get("name"),
                "pm_id":        p.get("pm_id"),
                "pid":          p.get("pid"),
                "pm2_user":     daemon["user"],
                "status":       env.get("status"),           # online / stopped / errored / ...
                "restarts":     env.get("restart_time", 0),
                "cpu_percent":  monit.get("cpu", 0),
                "mem_mb":       round((monit.get("memory") or 0) / 1024**2, 1),
                "uptime_secs":  uptime_secs,
                "exec_mode":    env.get("exec_mode"),
                "instances":    env.get("instances"),
            })
    _pm2_result_cache.update(ts=now, procs=out)
    return out

def get_intel_gpu_stats():
    """Get Intel GPU stats using intel_gpu_top"""
    try:
        result = subprocess.run(
            ['timeout', '2', 'intel_gpu_top', '-l', '1', '-J'],
            capture_output=True,
            text=True,
            timeout=3
        )

        # timeout command returns 124 when it kills the process after 2 seconds
        if result.returncode in [0, 124] and result.stdout:
            output = result.stdout.strip()

            # Find the last complete JSON object
            last_brace = output.rfind('}')
            if last_brace == -1:
                return None

            # Find matching opening brace
            brace_count = 0
            start_pos = last_brace
            for i in range(last_brace, -1, -1):
                if output[i] == '}':
                    brace_count += 1
                elif output[i] == '{':
                    brace_count -= 1
                    if brace_count == 0:
                        start_pos = i
                        break

            last_json = output[start_pos:last_brace+1]
            sample = json.loads(last_json)

            engines = sample.get('engines', {})
            total_usage = sum([
                engines.get('Render/3D', {}).get('busy', 0),
                engines.get('Compute', {}).get('busy', 0),
                engines.get('Video', {}).get('busy', 0)
            ])

            return {
                'freq_actual': round(sample.get('frequency', {}).get('actual', 0), 2),
                'freq_requested': round(sample.get('frequency', {}).get('requested', 0), 2),
                'power_gpu': round(sample.get('power', {}).get('GPU', 0), 2),
                'power_package': round(sample.get('power', {}).get('Package', 0), 2),
                'usage_total': round(total_usage, 2),
                'render_3d': round(engines.get('Render/3D', {}).get('busy', 0), 2),
                'compute': round(engines.get('Compute', {}).get('busy', 0), 2),
                'video': round(engines.get('Video', {}).get('busy', 0), 2),
                'rc6_idle': round(sample.get('rc6', {}).get('value', 0), 2)
            }
    except Exception as e:
        log.debug(f"Intel GPU stats error: {e}")

    return None

def get_gpu_info():
    gpus = []

    # NVIDIA GPUs
    if HAS_NVIDIA:
        try:
            import pynvml
            for i in range(pynvml.nvmlDeviceGetCount()):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                gpus.append({
                    "name": pynvml.nvmlDeviceGetName(h),
                    "type": "nvidia",
                    "index": i,
                    "temp_c": pynvml.nvmlDeviceGetTemperature(h, 0),
                    "gpu_percent": pynvml.nvmlDeviceGetUtilizationRates(h).gpu,
                    "mem_percent": pynvml.nvmlDeviceGetUtilizationRates(h).memory,
                    "mem_used_mb": pynvml.nvmlDeviceGetMemoryInfo(h).used // 1024**2,
                    "mem_total_mb": pynvml.nvmlDeviceGetMemoryInfo(h).total // 1024**2
                })
        except Exception as e:
            log.debug(f"NVIDIA GPU error: {e}")

    # Intel GPU
    if HAS_INTEL:
        try:
            result = os.popen("lspci | grep -i vga | grep -i intel").read().strip()
            gpu_name = result.split(": ")[1] if ": " in result else result

            # Get Intel GPU stats
            intel_stats = get_intel_gpu_stats()

            if intel_stats:
                gpus.append({
                    "name": gpu_name,
                    "type": "intel",
                    "index": len(gpus),
                    "temp_c": 0,
                    "gpu_percent": intel_stats['usage_total'],
                    "mem_percent": 0,
                    "mem_used_mb": 0,
                    "mem_total_mb": 0,
                    "freq_actual_mhz": intel_stats['freq_actual'],
                    "freq_requested_mhz": intel_stats['freq_requested'],
                    "power_gpu_w": intel_stats['power_gpu'],
                    "power_package_w": intel_stats['power_package'],
                    "render_3d_percent": intel_stats['render_3d'],
                    "compute_percent": intel_stats['compute'],
                    "video_percent": intel_stats['video'],
                    "rc6_idle_percent": intel_stats['rc6_idle']
                })
            else:
                gpus.append({
                    "name": gpu_name,
                    "type": "intel",
                    "index": len(gpus),
                    "temp_c": 0,
                    "gpu_percent": 0,
                    "mem_percent": 0,
                    "mem_used_mb": 0,
                    "mem_total_mb": 0
                })
        except Exception as e:
            log.debug(f"Intel GPU error: {e}")

    return gpus

def get_top_processes(limit=20):
    """
    psutil's per-process cpu_percent() needs a prior call on the SAME Process
    object to compute a delta — a freshly created Process always returns 0.0
    on its first call. We keep Process objects alive across loop iterations
    (module-level _proc_cache) so cpu_percent() has a real baseline each time.
    """
    procs = []
    seen_pids = set()

    for p in psutil.process_iter(['pid']):
        pid = p.pid
        seen_pids.add(pid)
        cached = _proc_cache.get(pid)
        if cached is None:
            try:
                cached = psutil.Process(pid)
                cached.cpu_percent(interval=None)  # prime baseline; discard the 0.0
                _proc_cache[pid] = cached
                continue  # no meaningful delta yet on a brand-new process this cycle
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        try:
            procs.append({
                "pid": pid,
                "name": cached.name(),
                "cpu_percent": round(cached.cpu_percent(interval=None), 2),
                "mem_percent": round(cached.memory_percent(), 2),
                "status": cached.status(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            _proc_cache.pop(pid, None)

    # Drop cached entries for processes that have exited
    for pid in list(_proc_cache.keys()):
        if pid not in seen_pids:
            _proc_cache.pop(pid, None)

    procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return procs[:limit]


def collect_metrics():
    cpu_temp = None
    try:
        temps = psutil.sensors_temperatures()
        if "coretemp" in temps:
            cpu_temp = max([t.current for t in temps["coretemp"]])
    except:
        pass

    disk_partitions = []
    for p in psutil.disk_partitions():
        if not p.fstype:
            continue
        try:
            du = psutil.disk_usage(p.mountpoint)
        except (PermissionError, OSError):
            continue
        disk_partitions.append({
            "device": p.device,
            "mountpoint": p.mountpoint,
            "fstype": p.fstype,
            "total_gb": round(du.total / 1024**3, 2),
            "used_gb": round(du.used / 1024**3, 2),
            "free_gb": round(du.free / 1024**3, 2),
            "percent": du.percent
        })

    dio = psutil.disk_io_counters()
    nio = psutil.net_io_counters()

    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "cpu_per_core": psutil.cpu_percent(interval=0.1, percpu=True),
        "cpu_freq_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else 0,
        "cpu_temp": cpu_temp,
        "ram_total_gb": round(psutil.virtual_memory().total / 1024**3, 2),
        "ram_used_gb": round(psutil.virtual_memory().used / 1024**3, 2),
        "ram_percent": psutil.virtual_memory().percent,
        "swap_total_gb": round(psutil.swap_memory().total / 1024**3, 2),
        "swap_used_gb": round(psutil.swap_memory().used / 1024**3, 2),
        "swap_percent": psutil.swap_memory().percent,
        "gpu_info": get_gpu_info(),
        "disk_partitions": disk_partitions,
        "disk_io": {
            "read_mb": round(dio.read_bytes / 1024**2, 2) if dio else 0,
            "write_mb": round(dio.write_bytes / 1024**2, 2) if dio else 0,
            "read_count": dio.read_count if dio else 0,
            "write_count": dio.write_count if dio else 0
        },
        "net_bytes_sent": nio.bytes_sent,
        "net_bytes_recv": nio.bytes_recv,
        "net_packets_sent": nio.packets_sent,
        "net_packets_recv": nio.packets_recv,
        "top_processes": get_top_processes(20),
        "pm2_processes": get_pm2_processes(),
        "uptime_seconds": round(time.time() - psutil.boot_time(), 2),
        "boot_time": datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat(),
        "public_ip": get_public_ip(),
        "os_version": platform.platform(),
        "hostname": socket.gethostname(),
        "status": "online"
    }

def register():
    for attempt in range(1, 61):
        try:
            resp = requests.post(
                f"{API_URL}/register",
                json={
                    "system_name": SYSTEM_NAME,
                    "location": LOCATION,
                    "os_type": "linux",
                    "hostname": socket.gethostname(),
                    "public_ip": get_public_ip()
                },
                headers={"X-API-Key": API_KEY},
                timeout=5
            )
            if resp.status_code == 200:
                table_name = resp.json()["table_name"]
                log.info(f"✅ Registered as: {table_name}")
                return table_name
            log.error(f"Register failed: {resp.status_code} {resp.text}")
        except Exception as e:
            log.error(f"Register attempt {attempt}/60: {e}")
        time.sleep(5)
    sys.exit(1)

def main():
    table_name = register()
    count = 0

    while True:
        try:
            data = collect_metrics()
            data["table_name"] = table_name

            resp = requests.post(
                f"{API_URL}/metrics",
                json=data,
                headers={"X-API-Key": API_KEY},
                timeout=5
            )

            if resp.status_code == 200:
                count += 1
                gpu_count = len(data['gpu_info'])
                gpu_usage = data['gpu_info'][0]['gpu_percent'] if gpu_count > 0 else 0
                pm2_count = len(data['pm2_processes'])
                pm2_down  = sum(1 for p in data['pm2_processes'] if p['status'] != 'online')
                pm2_users = sorted({p['pm2_user'] for p in data['pm2_processes']})
                pm2_txt   = (f" | PM2: {pm2_count}({pm2_down} down) [{', '.join(pm2_users)}]"
                             if pm2_count else "")
                log.info(f"📊 {count} sent | CPU: {data['cpu_percent']}% | RAM: {data['ram_percent']}% | GPU: {gpu_usage}% ({gpu_count}) | Temp: {data['cpu_temp']}°C{pm2_txt}")
            else:
                log.error(f"Send failed: {resp.status_code}")
        except Exception as e:
            log.error(f"Send error: {e}")

        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
