"""
REFORMMED Monitor — Flask Web Dashboard
"""
import os
from flask import Flask
from flask_login import LoginManager
from db import init_db, get_db
from models import User

login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET", "change-me-in-production")

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

    @login_manager.user_loader
    def load_user(user_id):
        return User.get_by_id(int(user_id))

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

    app.register_blueprint(auth_bp)
    app.register_blueprint(home_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dvr_bp)
    app.register_blueprint(dbmonitor_bp)
    app.register_blueprint(settings_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host=os.getenv("WEBAPP_HOST", "0.0.0.0"),
        port=int(os.getenv("WEBAPP_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )
