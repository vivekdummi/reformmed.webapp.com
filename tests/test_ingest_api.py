"""Agent ingest API (server/main.py): auth and request-size limits.
The DB pool is never opened — every request here is rejected before it."""
import pathlib
import sys

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "server"))
import main  # noqa: E402

client = TestClient(main.app)  # no `with` → lifespan (DB connect) not run
KEY = {"X-Api-Key": "test-api-secret"}


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setattr(main, "API_SECRET", "test-api-secret")


@pytest.mark.parametrize("path", ["/register", "/metrics"])
def test_wrong_key_rejected(path):
    r = client.post(path, json={}, headers={"X-Api-Key": "nope"})
    assert r.status_code == 401


def test_no_secret_configured_fails_closed(monkeypatch):
    monkeypatch.setattr(main, "API_SECRET", "")
    assert client.post("/metrics", json={}, headers={"X-Api-Key": ""}).status_code == 401


@pytest.mark.parametrize("path", ["/register", "/metrics"])
def test_oversized_body_rejected(path):
    big = b'{"x":"' + b"a" * (main.MAX_BODY_BYTES + 10) + b'"}'
    r = client.post(path, content=big, headers={**KEY, "Content-Type": "application/json"})
    assert r.status_code == 413


@pytest.mark.parametrize("payload", [b"not json", b"[1,2,3]"])
def test_non_object_body_rejected(payload):
    r = client.post("/metrics", content=payload, headers={**KEY, "Content-Type": "application/json"})
    assert r.status_code == 400


def test_bad_table_name_rejected():
    r = client.post("/metrics", json={"table_name": "x; DROP TABLE y"}, headers=KEY)
    assert r.status_code in (400, 403, 404)


def test_docs_disabled():
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(p).status_code == 404
