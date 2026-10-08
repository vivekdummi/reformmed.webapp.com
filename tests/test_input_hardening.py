"""Input validation, injection and information-leak fixes."""
import contextlib
import pathlib
import re

import pytest

from conftest import login, make_user
from security import RateLimiter, safe_next_url

ROOT = pathlib.Path(__file__).parents[1]


# ── security.py helpers ─────────────────────────────────────────────────────

@pytest.mark.parametrize("target,expected", [
    ("/servers/x", "/servers/x"),
    ("https://evil.example", "/home"),
    ("//evil.example", "/home"),
    ("/\\evil.example", "/home"),
    ("javascript:alert(1)", "/home"),
    ("", "/home"),
    (None, "/home"),
])
def test_safe_next_url(target, expected):
    assert safe_next_url(target, "/home") == expected


def test_rate_limiter():
    rl = RateLimiter(3, 60)
    for _ in range(3):
        assert not rl.blocked("k")
        rl.hit("k")
    assert rl.blocked("k")
    rl.reset("k")
    assert not rl.blocked("k")


# ── email header / HTML injection ───────────────────────────────────────────

def test_clean_header_strips_newlines():
    from alert_sender import clean_header
    out = clean_header("Disk full\r\nBcc: attacker@evil.example")
    assert "\r" not in out and "\n" not in out
    assert len(clean_header("x" * 1000)) == 200


def test_offline_alert_email_escapes_agent_data():
    from offline_checker import _render_alert
    evil = "<a href='https://evil.example'>Re-login</a>"
    subject, plain, html = _render_alert("disk", evil, "lab", [("Mount", "<script>x</script>")])
    assert "<a href='https://evil.example'>" not in html
    assert "<script>" not in html
    assert "&lt;a href=" in html


def test_grafana_sql_literal_escaped():
    import sys
    sys.path.insert(0, str(ROOT / "server"))
    from dashboard_manager import _sql_lit
    assert _sql_lit("x' OR '1'='1") == "x'' OR ''1''=''1"


# ── servers blueprint ───────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["machine_x;drop table t", "pg_shadow", "machine_X", "a" * 5])
def test_server_routes_reject_bad_table_names(client, name):
    make_user(100, "admin1", role="admin")
    login(client, "admin1")
    assert client.get(f"/servers/{name}/history?start=2026-01-01&end=2026-01-02").status_code == 404


@pytest.mark.parametrize("start,end", [
    ("1970-01-01T00:00", "2100-01-01T00:00"),   # too long a span
    ("not-a-date", "2026-01-02T00:00"),
    ("2026-01-02T00:00", "2026-01-01T00:00"),   # reversed
])
def test_history_range_validated_before_query(client, start, end):
    make_user(101, "admin2", role="admin")
    login(client, "admin2")
    r = client.get(f"/servers/machine_box_lab/history?start={start}&end={end}")
    assert r.status_code == 400


def test_chart_data_not_rendered_with_safe_filter():
    tpl = (ROOT / "templates" / "server_detail.html").read_text(encoding="utf-8")
    assert not re.search(r"chart_\w+\s*\|\s*safe", tpl)
    assert not (ROOT / "templates" / "bac-server_detail.html").exists()


def test_tojson_neutralises_script_breakout(app):
    from flask import render_template_string
    with app.test_request_context():
        out = render_template_string("{{ v | tojson }}", v=["</script><script>alert(1)</script>"])
    assert "</script>" not in out


# ── reports ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("body", [
    {"table_names": [["nested"]], "metrics": ["cpu"]},
    {"table_names": ["bad name;"], "metrics": ["cpu"]},
    {"table_names": [f"machine_{i}" for i in range(51)], "metrics": ["cpu"]},
    {"table_names": ["machine_a"], "mode": "range", "start": "garbage", "end": "2026-01-01T00:00"},
    {"table_names": ["machine_a"], "mode": "range",
     "start": "2020-01-01T00:00", "end": "2026-01-01T00:00"},
])
def test_report_requests_validated(client, body):
    make_user(102, "admin3", role="admin")
    login(client, "admin3")
    from blueprints import reports
    body.setdefault("metrics", [next(iter(reports.METRIC_FORMATTERS))])
    r = client.post("/reports/generate", json=body)
    assert r.status_code == 400, r.get_json()


# ── ARIA chat rate limit / error leak ───────────────────────────────────────

def test_chat_rate_limited(client):
    make_user(103, "user1")
    login(client, "user1")
    from blueprints import api
    for _ in range(20):
        api._chat_limiter.hit("chat|103")
    r = client.post("/api/agent/chat", json={"message": "hi"})
    assert r.status_code == 429


# ── DB monitor: no internal error details for non-admins ────────────────────

class _FakeCursor:
    def __init__(self, row): self.row = row
    def execute(self, *a, **k): pass
    def fetchone(self): return self.row
    def fetchall(self): return []


class _FakeConn:
    def __init__(self, row): self.row = row
    def cursor(self): return _FakeCursor(self.row)


WATCH = {"id": 1, "monitoring": True, "host": "10.0.3.7", "port": 5432, "dbname": "d",
         "username": "u", "password": "p", "conn_name": "c", "schema_name": "public",
         "table_name": "t", "alerts_enabled": False, "alert_emails": ""}


_EXT_ERROR = ('connection to server at "10.0.3.7", port 5432 failed: '
              'password authentication failed for user "u"')


def test_dbmonitor_check_stores_connection_error(monkeypatch):
    """The background check records the external-DB failure on the watch."""
    from blueprints import dbmonitor
    monkeypatch.setattr(dbmonitor, "get_db", lambda: contextlib.nullcontext(_FakeConn(WATCH)))

    def boom(row):
        raise RuntimeError(_EXT_ERROR)
    monkeypatch.setattr(dbmonitor, "_ext_conn", boom)
    stored = {}
    monkeypatch.setattr(dbmonitor, "_store_check", lambda wid, result: stored.update({wid: result}))
    dbmonitor.check_watch(1)
    assert stored == {1: {"error": _EXT_ERROR}}


def _status_as(client, monkeypatch, uid, username, role, **perms):
    from blueprints import dbmonitor
    row = dict(WATCH, last_check={"error": _EXT_ERROR}, last_checked_at=None)
    monkeypatch.setattr(dbmonitor, "get_db", lambda: contextlib.nullcontext(_FakeConn(row)))
    make_user(uid, username, role=role, **perms)
    login(client, username)
    return client.get("/dbmonitor/watch/1/status").get_json()


def test_dbmonitor_status_hides_errors_from_viewers(client, monkeypatch):
    data = _status_as(client, monkeypatch, 104, "viewer", "user", can_view_dbmon=True)
    assert "10.0.3.7" not in data["error"]


def test_dbmonitor_status_shows_errors_to_admin(client, monkeypatch):
    data = _status_as(client, monkeypatch, 105, "admin4", "admin")
    assert "10.0.3.7" in data["error"]


def test_dbmonitor_requires_permission(client):
    make_user(106, "nodb", can_view_dbmon=False)
    login(client, "nodb")
    assert client.get("/dbmonitor/watch/1/status").status_code == 403


# ── settings / users are admin-only ─────────────────────────────────────────

@pytest.mark.parametrize("method,url", [
    ("get", "/users/"), ("post", "/users/create"), ("post", "/users/1/delete"),
    ("get", "/settings/"), ("post", "/settings/save"), ("get", "/api/settings"),
])
def test_admin_routes_forbidden_for_users(client, method, url):
    make_user(107, "plain")
    login(client, "plain")
    assert getattr(client, method)(url).status_code == 403
