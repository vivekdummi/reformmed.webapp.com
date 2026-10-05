"""Authentication / session security of the Flask webapp."""
import pyotp

from conftest import _USERS, login, make_user, totp_now

# Any login_required URL that never touches the DB: _check_access rejects the
# malformed table name with 404 when logged in; anonymous users get 302.
PROBE = "/servers/not-a-table!"


def _is_logged_in(client):
    r = client.get(PROBE)
    assert r.status_code in (302, 404)
    return r.status_code == 404


def test_login_success_and_logout(client):
    make_user(1, "alice")
    r = login(client, "alice")
    assert r.status_code == 302
    assert _is_logged_in(client)
    client.post("/logout")
    assert not _is_logged_in(client)


def test_login_wrong_password(client):
    make_user(2, "bob")
    r = login(client, "bob", "wrong")
    assert r.status_code == 200
    assert not _is_logged_in(client)


def test_login_rate_limited_after_10_failures(client):
    make_user(3, "carol")
    for _ in range(10):
        login(client, "carol", "wrong")
    r = login(client, "carol")  # correct password, but locked out
    assert r.status_code == 429
    assert not _is_logged_in(client)


def test_inactive_user_cannot_log_in(client):
    make_user(4, "dave", is_active=False)
    login(client, "dave")
    assert not _is_logged_in(client)


def test_deactivated_user_session_is_rejected(client):
    make_user(5, "erin")
    login(client, "erin")
    assert _is_logged_in(client)
    _USERS[5]["is_active"] = False          # admin deactivates the account
    assert not _is_logged_in(client)


def test_password_change_invalidates_other_sessions(app):
    make_user(6, "frank")
    attacker, victim = app.test_client(), app.test_client()
    login(attacker, "frank")
    login(victim, "frank")
    assert _is_logged_in(attacker)
    # victim resets password elsewhere (forgot-password / admin reset)
    from models import User
    User.update(6, password="brand-new-password")
    assert not _is_logged_in(attacker)
    assert not _is_logged_in(victim)


def test_own_password_change_keeps_current_session(client):
    make_user(7, "gina")
    login(client, "gina")
    r = client.post("/profile", data={"password": "another-password-9",
                                      "current_password": "correct-horse-1"})
    assert r.status_code == 302
    assert _is_logged_in(client)


def test_legacy_integer_session_id_rejected(app):
    make_user(8, "hank")
    c = app.test_client()
    with c.session_transaction() as s:
        s["_user_id"] = "8"          # pre-fix session format, no fingerprint
        s["_fresh"] = True
    assert not _is_logged_in(c)


def test_forged_fingerprint_rejected(app):
    make_user(9, "ivy")
    c = app.test_client()
    with c.session_transaction() as s:
        s["_user_id"] = "9:0000000000000000"
        s["_fresh"] = True
    assert not _is_logged_in(c)


def test_2fa_required_and_code_cannot_be_replayed(app):
    secret = pyotp.random_base32()
    make_user(10, "jack", totp_secret=secret)

    c1 = app.test_client()
    r = login(c1, "jack")
    assert r.status_code == 302 and "/login/verify-2fa" in r.headers["Location"]
    assert not _is_logged_in(c1)          # password alone isn't enough
    code = totp_now(secret)
    r = c1.post("/login/verify-2fa", data={"code": code})
    assert r.status_code == 302
    assert _is_logged_in(c1)

    # Same code, different browser (e.g. phished/shoulder-surfed) → refused
    c2 = app.test_client()
    login(c2, "jack")
    r = c2.post("/login/verify-2fa", data={"code": code})
    assert r.status_code == 200
    assert not _is_logged_in(c2)


def test_2fa_wrong_code(app):
    secret = pyotp.random_base32()
    make_user(11, "kate", totp_secret=secret)
    c = app.test_client()
    login(c, "kate")
    c.post("/login/verify-2fa", data={"code": "000000" if totp_now(secret) != "000000" else "111111"})
    assert not _is_logged_in(c)


def test_open_redirect_blocked_on_login(client):
    make_user(12, "liam")
    r = client.post("/login?next=https://evil.example/x",
                    data={"username": "liam", "password": "correct-horse-1"})
    assert r.status_code == 302
    assert "evil.example" not in r.headers["Location"]


def test_logout_requires_post(client):
    make_user(13, "mia")
    login(client, "mia")
    assert client.get("/logout").status_code == 405
    assert _is_logged_in(client)


def test_csrf_enforced_when_enabled(app):
    app.config["WTF_CSRF_ENABLED"] = True
    make_user(14, "noah")
    c = app.test_client()
    r = c.post("/login", data={"username": "noah", "password": "correct-horse-1"})
    assert r.status_code in (302, 400)
    assert not _is_logged_in(c)


def test_security_headers(client):
    r = client.get("/login")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Referrer-Policy" in r.headers


def test_session_cookie_flags(client):
    make_user(15, "olga")
    r = login(client, "olga")
    cookies = r.headers.getlist("Set-Cookie")
    assert any(c.startswith("session=") and "HttpOnly" in c for c in cookies)
    assert any(c.startswith("remember_token=") and "HttpOnly" in c for c in cookies)


def test_debug_mode_off_by_default():
    import ast, pathlib
    src = (pathlib.Path(__file__).parents[1] / "app.py").read_text(encoding="utf-8")
    assert 'os.getenv("FLASK_DEBUG", "0") == "1"' in src
    ast.parse(src)
