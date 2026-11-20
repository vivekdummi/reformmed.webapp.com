"""PM2 process parsing (blueprints.servers.parse_pm2) — raw `pm2 jlist` and flat shapes."""
import json
import time

from blueprints.servers import parse_pm2, pm2_summary


def test_raw_pm2_jlist_shape():
    started_ms = (time.time() - 3600) * 1000
    raw = [{
        "name": "api", "pm_id": 0, "pid": 123,
        "monit": {"cpu": 12.5, "memory": 150 * 1024 * 1024},
        "pm2_env": {"status": "online", "restart_time": 3, "pm_uptime": started_ms,
                    "exec_mode": "cluster_mode", "instances": 4},
    }]
    [p] = parse_pm2(json.dumps(raw))
    assert p["name"] == "api" and p["id"] == 0 and p["status"] == "online"
    assert p["cpu"] == 12.5
    assert p["memory_mb"] == 150.0
    assert p["restarts"] == 3
    assert 3590 <= p["uptime_secs"] <= 3610
    assert p["mode"] == "cluster" and p["instances"] == 4


def test_flat_shape_with_memory_in_mb():
    [p] = parse_pm2([{"name": "worker", "status": "online", "cpu": 1,
                      "memory": 80, "restarts": 0, "uptime": 120}])
    assert p["memory_mb"] == 80 and p["uptime_secs"] == 120


def test_stopped_app_has_no_uptime_and_sorts_first():
    procs = parse_pm2([
        {"name": "b", "status": "online", "uptime": 10},
        {"name": "a", "status": "stopped", "uptime": 10},
    ])
    assert [p["name"] for p in procs] == ["a", "b"]
    assert procs[0]["uptime_secs"] is None
    assert pm2_summary(procs) == {"online": 1, "total": 2}


def test_garbage_and_missing_input():
    assert parse_pm2(None) == []
    assert parse_pm2("not json") == []
    assert parse_pm2([1, "x", None]) == []
    assert pm2_summary([]) is None
    assert len(parse_pm2({"processes": [{"name": "x", "status": "errored"}]})) == 1


def test_reformmed_agent_shape_with_two_daemons():
    # What /opt/reformmed-agent/agent.py sends: one entry per app, tagged
    # with the daemon (user) it came from. ids clash across daemons.
    procs = parse_pm2([
        {"name": "jammu_cam2_pharmacy", "pm_id": 2, "pm2_user": "root", "status": "online",
         "restarts": 370, "cpu_percent": 0, "mem_mb": 1843.2, "uptime_secs": 5280.0,
         "exec_mode": "fork_mode", "instances": 1},
        {"name": "agarwal_axelera", "pm_id": 0, "pm2_user": "adminqa", "status": "online",
         "restarts": 495, "cpu_percent": 3.5, "mem_mb": 2560.0, "uptime_secs": 75600.0},
    ])
    by_user = {p["user"]: p for p in procs}
    assert set(by_user) == {"root", "adminqa"}
    assert by_user["adminqa"]["memory_mb"] == 2560.0
    assert by_user["adminqa"]["cpu"] == 3.5
    assert by_user["root"]["restarts"] == 370
    assert by_user["root"]["mode"] == "fork"
