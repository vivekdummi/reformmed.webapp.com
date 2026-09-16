"""
Google OAuth client (Authlib) — shared instance, registered once in app.py's
create_app() via init_oauth(app), then used by blueprints/auth.py's
/auth/google and /auth/google/callback routes.
"""
import os
from authlib.integrations.flask_client import OAuth

oauth = OAuth()


def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )