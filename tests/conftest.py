"""
Test fixtures. No Postgres needed: table setup is stubbed out and users live
in an in-memory dict, so these tests exercise the Flask app's auth/security
behaviour end to end without a database.
"""
import os
import sys

# Must be set before app.py runs load_dotenv() (which never overrides
# variables that already exist), so the real .env is never used by tests.
os.environ["FLASK_SECRET"] = "test-secret-" + "x" * 40
os.environ["SESSION_COOKIE_SECURE"] = "0"
os.environ["GOOGLE_CLIENT_ID"] = ""
os.environ["GEMINI_API_KEY"] = ""
os.environ["API_SECRET"] = "test-api-secret"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pyotp
import pytest
from werkzeug.security import generate_password_hash

import models
from models import User

_USERS = {}


def make_user(uid, username, password="correct-horse-1", role="user",
              is_active=True, totp_secret=None, **perms):
    row = {
        "id": uid, "username": username, "email": f"{username}@example.com",
        "password_hash": generate_password_hash(password), "role": role,
        "is_active": is_active,
        "can_view_dvr": perms.get("can_view_dvr", False),
        "can_view_dbmon": perms.get("can_view_dbmon", False),
        "can_view_alerts": perms.get("can_view_alerts", True),
        "can_view_servers": perms.get("can_view_servers", True),
        "totp_secret": totp_secret, "totp_enabled": bool(totp_secret),
        "totp_required": False, "avatar_ver": 0,
    }
    _USERS[uid] = row
    return row


def _find(field, value):
    for r in _USERS.values():
        if r[field] == value:
            return User(dict(r))
    return None


def _update(user_id, **kwargs):
    if kwargs.get("password"):
        kwargs["password_hash"] = generate_password_hash(kwargs.pop("password"))
    _USERS[user_id].update({k: v for k, v in kwargs.items() if k in _USERS[user_id]})


@pytest.fixture
def app(monkeypatch):
    import app as app_module
    import blueprints.dbmonitor
    import blueprints.dvr

    monkeypatch.setattr(app_module, "init_db", lambda: None)
    monkeypatch.setattr(blueprints.dbmonitor, "init_dbmonitor_tables", lambda: None)
    monkeypatch.setattr(blueprints.dvr, "init_dvr_tables", lambda: None)

    monkeypatch.setattr(User, "get_by_id", staticmethod(lambda uid: _USERS.get(int(uid)) and User(dict(_USERS[int(uid)]))))
    monkeypatch.setattr(User, "get_by_username", staticmethod(lambda n: _find("username", n)))
    monkeypatch.setattr(User, "get_by_email", staticmethod(lambda e: _find("email", e)))
    monkeypatch.setattr(User, "touch_login", staticmethod(lambda uid: None))
    monkeypatch.setattr(User, "update", staticmethod(_update))
    monkeypatch.setattr(models.User, "allowed_servers",
                        lambda self: None if self.is_admin else set())

    _USERS.clear()
    application = app_module.create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield application
    _USERS.clear()


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username, password="correct-horse-1"):
    return client.post("/login", data={"username": username, "password": password})


def totp_now(secret):
    return pyotp.TOTP(secret).now()
