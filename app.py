"""
Reformmed INFRA Monitor — Flask Web Dashboard
"""
import hmac
import os
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()  # no-op in Docker (env already set by compose); fills gaps when run directly

from flask import Flask, redirect, request, url_for
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from db import init_db
from models import User
from oauth import init_oauth

login_manager = LoginManager()
csrf = CSRFProtect()

# Endpoints reachable even when 2FA setup is being force-enforced below —
# otherwise a user with totp_required could never reach the page that lets
# them set it up (or log out) in the first place.
_TOTP_SETUP_EXEMPT_ENDPOINTS = {
    "auth.login", "auth.logout", "auth.google_login", "auth.google_callback",
    "auth.verify_2fa", "auth.profile", "auth.totp_setup", "auth.totp_confirm",
    "static",
}


def create_app():
    app = Flask(__name__)
    secret = os.getenv("FLASK_SECRET", "")
    if not secret or secret in ("change-me-in-production", "change-this-to-a-random-long-string"):
        # A guessable secret lets anyone forge a logged-in session cookie.
        raise RuntimeError("FLASK_SECRET must be set to a long random value "
                           "(python -c \"import secrets; print(secrets.token_hex(32))\")")
    app.secret_key = secret
    # Behind the TLS-terminating reverse proxy: trust one hop of X-Forwarded-*
    # so request.remote_addr / scheme are the real client's.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    cookie_secure = os.getenv("SESSION_COOKIE_SECURE", "1") == "1"
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cookie_secure,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_SECURE=cookie_secure,
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        WTF_CSRF_TIME_LIMIT=None,  # token lives as long as the session
    )
    csrf.init_app(app)
    # 7-day auto-logout: covers both the "remember me" cookie (survives
    # browser close) and the regular session cookie, so either way a login
    # stops working exactly 7 days after it started.
    app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
    init_oauth(app)

    # ── Init DB ──────────────────────────────────────────────────────────────
    init_db()
    from blueprints.dbmonitor import init_dbmonitor_tables
    init_dbmonitor_tables()
    from blueprints.dvr import init_dvr_tables
    init_dvr_tables()

    # ── Flask-Login ──────────────────────────────────────────────────────────
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id):
        # user_id is "<id>:<password fingerprint>" (see User.get_id). Reject
        # sessions from before a password change, and any session of a
        # deactivated account — Flask-Login itself doesn't check is_active
        # for already-logged-in users.
        uid, _, fingerprint = str(user_id).partition(":")
        if not uid.isdigit() or not fingerprint:
            return None
        user = User.get_by_id(int(uid))
        if not user or not user.is_active:
            return None
        if not hmac.compare_digest(fingerprint, user.session_fingerprint()):
            return None
        return user

    # An admin can mark a user as totp_required — this catches every request
    # from that user until they've actually completed 2FA setup, and bounces
    # them to the setup page instead of letting them use the rest of the app.
    @app.before_request
    def _enforce_totp_required():
        if not current_user.is_authenticated:
            return
        if not getattr(current_user, "totp_required", False):
            return
        if current_user.totp_enabled:
            return
        if request.endpoint in _TOTP_SETUP_EXEMPT_ENDPOINTS:
            return
        return redirect(url_for("auth.profile"))

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def _csrf_error(e):
        if request.is_json or request.accept_mimetypes.best == "application/json":
            from flask import jsonify
            return jsonify({"ok": False, "error": "Session expired — reload the page and try again."}), 400
        from flask import flash
        flash("Your session expired — please try again.", "warning")
        return redirect(request.referrer if request.referrer and request.referrer.startswith(request.host_url) else url_for("home.index"))

    # ── Blueprints ───────────────────────────────────────────────────────────
    from blueprints.auth     import auth_bp
    from blueprints.home     import home_bp
    from blueprints.servers  import servers_bp
    from blueprints.users    import users_bp
    from blueprints.alerts   import alerts_bp
    from blueprints.api      import api_bp
    from blueprints.dvr      import dvr_bp
    from blueprints.dbmonitor import dbmonitor_bp
    from blueprints.settings import settings_bp
    from blueprints.review    import review_bp
    from blueprints.reports  import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(home_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dvr_bp)
    app.register_blueprint(dbmonitor_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(review_bp)
    app.register_blueprint(reports_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host=os.getenv("WEBAPP_HOST", "0.0.0.0"),
        port=int(os.getenv("WEBAPP_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )