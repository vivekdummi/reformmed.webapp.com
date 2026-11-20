"""
Online/offline timeline built from gaps in a machine's metric rows
(blueprints.servers._uptime_timeline). The DB is faked: each query returns
the canned result for its position in the function.
"""
from contextlib import contextmanager

import pytest

from blueprints import servers
from conftest import login, make_user

NOW = 1_000_000.0
HOUR = 3600


class _FakeCursor:
    def __init__(self, results):
        self._results = list(results)
        self._current = None

    def execute(self, *_a, **_k):
        self._current = self._results.pop(0)

    def fetchone(self):
        return self._current

    def fetchall(self):
        return self._current


def _run(monkeypatch, first, last, before, gaps, hours=1):
    results = [
        {"now": NOW},
        {"first": first, "last": last},
        {"ts": before} if before is not None else None,
        [{"s": s, "e": e} for s, e in gaps],
    ]

    @contextmanager
    def fake_db():
        class Conn:
            def cursor(self):
                return _FakeCursor(results)
        yield Conn()

    monkeypatch.setattr(servers, "get_db", fake_db)
    monkeypatch.setattr(servers, "OFFLINE_AFTER_SECS", 60)
    return servers._uptime_timeline("machine_test", hours)


def _states(d):
    return [(s["state"], s["start"], s["end"]) for s in d["segments"]]


def test_always_online(monkeypatch):
    start = NOW - HOUR
    d = _run(monkeypatch, first=start + 5, last=NOW - 5, before=start - 5, gaps=[])
    assert _states(d) == [("online", start, NOW)]
    assert d["uptime_pct"] == 100.0
    assert d["outages"] == 0


def test_gap_in_middle_is_an_outage(monkeypatch):
    start = NOW - HOUR
    d = _run(monkeypatch, first=start + 5, last=NOW - 5, before=start - 5,
             gaps=[(start + 600, start + 1200)])
    assert _states(d) == [
        ("online", start, start + 600),
        ("offline", start + 600, start + 1200),
        ("online", start + 1200, NOW),
    ]
    assert d["outages"] == 1
    assert d["offline_secs"] == 600
    assert d["longest_outage_secs"] == 600


def test_silent_since_last_report_is_offline_now(monkeypatch):
    start = NOW - HOUR
    d = _run(monkeypatch, first=start + 5, last=NOW - 300, before=start - 5, gaps=[])
    assert _states(d)[-1] == ("offline", NOW - 300, NOW)


def test_no_older_data_is_nodata_not_offline(monkeypatch):
    start = NOW - HOUR
    d = _run(monkeypatch, first=start + 1800, last=NOW - 5, before=None, gaps=[])
    assert _states(d) == [("nodata", start, start + 1800), ("online", start + 1800, NOW)]
    assert d["uptime_pct"] == 100.0  # no-data time doesn't count against uptime


def test_window_opens_mid_outage(monkeypatch):
    start = NOW - HOUR
    d = _run(monkeypatch, first=start + 900, last=NOW - 5, before=start - 3000, gaps=[])
    assert _states(d)[0] == ("offline", start, start + 900)


def test_no_rows_in_window(monkeypatch):
    start = NOW - HOUR
    assert _states(_run(monkeypatch, None, None, before=start - 10, gaps=[])) == [("offline", start, NOW)]
    d = _run(monkeypatch, None, None, before=None, gaps=[])
    assert _states(d) == [("nodata", start, NOW)]
    assert d["uptime_pct"] is None


def test_uptime_route_rejects_bad_table_name(client):
    make_user(1, "boss", role="admin")
    login(client, "boss")
    assert client.get("/servers/not_a_machine/uptime").status_code == 404


def test_uptime_route_requires_server_access(client):
    make_user(2, "viewer")
    login(client, "viewer")  # not granted this server
    assert client.get("/servers/machine_other/uptime").status_code == 403
