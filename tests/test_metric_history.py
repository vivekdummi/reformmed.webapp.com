"""
Analytics card trends (blueprints.servers._metric_history): readings bucketed
to avg/min/max (level metrics) or per-second rates from counter deltas (net,
disk I/O); empty buckets stay null; CSV export; route validation.
"""
from contextlib import contextmanager

from blueprints import servers
from conftest import login, make_user

NOW = 360_000.0  # divisible by the 1h bucket (30s)


def _fake_db(monkeypatch, rows, captured=None):
    results = [{"now": NOW}, rows]

    class Cur:
        def execute(self, query, params=None):
            if captured is not None:
                captured.append((query, params))
            self.cur = results.pop(0)

        def fetchone(self):
            return self.cur

        def fetchall(self):
            return self.cur

    @contextmanager
    def fake_db():
        class Conn:
            def cursor(self):
                return Cur()
        yield Conn()

    monkeypatch.setattr(servers, "get_db", fake_db)


BUCKET = 3600 // servers.TREND_POINTS  # 30s for 1h
FIRST = int((NOW - 3600) // BUCKET)


def test_level_buckets_and_stats(monkeypatch):
    _fake_db(monkeypatch, [
        {"b": FIRST + 1, "a": 50.0, "lo": 48.0, "hi": 52.0, "n": 2},
        {"b": FIRST + 3, "a": 70.0, "lo": 66.0, "hi": 81.5, "n": 2},
    ])
    d = servers._metric_history("machine_test", "temp", hours=1)
    assert d["bucket_secs"] == BUCKET
    pts = d["points"]
    assert len(pts) == servers.TREND_POINTS + 1
    assert pts[0]["avg"] is None and pts[2]["avg"] is None  # gaps stay empty
    assert pts[1] == {"t": (FIRST + 1) * BUCKET, "avg": 50.0, "min": 48.0, "max": 52.0}
    assert d["min"] == {"value": 48.0, "t": (FIRST + 1) * BUCKET}
    assert d["max"] == {"value": 81.5, "t": (FIRST + 3) * BUCKET}
    assert d["avg"] == 60.0
    assert (d["first"], d["last"]) == (50.0, 70.0)
    assert d["samples"] == 4


def test_level_no_readings(monkeypatch):
    _fake_db(monkeypatch, [])
    d = servers._metric_history("machine_test", "cpu", hours=168)
    assert d["samples"] == 0 and d["min"] is None and d["max"] is None and d["avg"] is None
    assert all(p["avg"] is None for p in d["points"])
    assert len(d["points"]) <= servers.TREND_POINTS + 1


def test_disk_and_core_pass_their_parameter(monkeypatch):
    q = []
    _fake_db(monkeypatch, [], q)
    servers._metric_history("machine_test", "disk", hours=1, mount="/data")
    assert "/data" in q[-1][1]
    q.clear()
    _fake_db(monkeypatch, [], q)
    servers._metric_history("machine_test", "core", hours=1, core=3)
    assert 3 in q[-1][1]


def test_rate_net(monkeypatch):
    # 2 samples: avg rates 2048 / 1024 bytes/s, max 4096 / 2048; 30 KB / 15 KB moved
    _fake_db(monkeypatch, [
        {"b": FIRST + 2, "aa": 2048.0, "am": 4096.0, "ba": 1024.0, "bm": 2048.0,
         "ta": 30720.0, "tb": 15360.0, "n": 2},
    ])
    d = servers._metric_history("machine_test", "net", hours=1)
    p = d["points"][2]
    assert (p["a"], p["a_max"], p["b"], p["b_max"]) == (2.0, 4.0, 1.0, 2.0)  # KB/s
    assert d["a_peak"] == {"value": 4.0, "t": (FIRST + 2) * BUCKET}
    assert d["a_avg"] == 2.0 and d["b_avg"] == 1.0
    assert d["a_total"] == 30720.0 and d["b_total"] == 15360.0       # bytes
    assert d["points"][0]["a"] is None


def test_csv_skips_empty_buckets(monkeypatch):
    _fake_db(monkeypatch, [{"b": FIRST + 1, "a": 50.0, "lo": 48.0, "hi": 52.0, "n": 2}])
    d = servers._metric_history("machine_test", "cpu", hours=1)
    resp = servers._metric_csv(d, "machine_test")
    lines = resp.get_data(as_text=True).strip().splitlines()
    assert lines[0] == "time_utc,cpu_avg,cpu_min,cpu_max"
    assert len(lines) == 2 and lines[1].endswith(",50.0,48.0,52.0")
    assert "attachment" in resp.headers["Content-Disposition"]


def test_route_requires_server_access(client):
    make_user(2, "viewer")
    login(client, "viewer")
    assert client.get("/servers/machine_other/metric-history?metric=cpu").status_code == 403


def test_route_rejects_bad_table_name(client):
    make_user(1, "boss", role="admin")
    login(client, "boss")
    assert client.get("/servers/not_a_machine/metric-history?metric=cpu").status_code == 404


def test_route_rejects_unknown_metric_and_bad_range(client):
    make_user(1, "boss", role="admin")
    login(client, "boss")
    assert client.get("/servers/machine_x/metric-history?metric=evil").status_code == 400
    assert client.get("/servers/machine_x/metric-history?metric=cpu&start=nope&end=nope").status_code == 400
    r = client.get("/servers/machine_x/metric-history?metric=cpu"
                   "&start=2026-01-02T00:00:00Z&end=2026-01-01T00:00:00Z")
    assert r.status_code == 400
