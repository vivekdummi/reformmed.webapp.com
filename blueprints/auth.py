import base64
import io
import os

import pyotp
import qrcode
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models import User
from oauth import oauth

auth_bp = Blueprint("auth", __name__)


def _start_2fa_challenge(user, next_url=None):
    """Common to password login and Google login: instead of logging the
    user in immediately, park them pending a correct 6-digit code."""
    session["pending_2fa_user_id"] = user.id
    session["pending_2fa_next"] = next_url or url_for("home.index")
    return redirect(url_for("auth.verify_2fa"))


def _complete_login(user):
    session.permanent = True  # applies PERMANENT_SESSION_LIFETIME (7 days)
    login_user(user, remember=True)  # applies REMEMBER_COOKIE_DURATION (7 days)
    User.touch_login(user.id)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home.index"))
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password   = request.form.get("password", "")
        user = User.get_by_username(identifier)
        if not user:
            user = User.get_by_email(identifier)
        if user and user.check_password(password) and user.is_active:
            if user.totp_enabled:
                return _start_2fa_challenge(user, request.args.get("next"))
            _complete_login(user)
            return redirect(request.args.get("next") or url_for("home.index"))
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html", google_sso_enabled=bool(os.getenv("GOOGLE_CLIENT_ID")))


@auth_bp.route("/auth/google")
def google_login():
    if current_user.is_authenticated:
        return redirect(url_for("home.index"))
    redirect_uri = url_for("auth.google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route("/auth/google/callback")
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
    except Exception as e:
        flash(f"Google sign-in failed: {e}", "danger")
        return redirect(url_for("auth.login"))

    userinfo = token.get("userinfo") or {}
    email = (userinfo.get("email") or "").strip()
    email_verified = userinfo.get("email_verified", False)

    if not email or not email_verified:
        flash("Google sign-in failed — no verified email returned.", "danger")
        return redirect(url_for("auth.login"))

    # No auto-provisioning: an admin has to have already created the account
    # with this exact email. Anyone whose Google account isn't already a
    # REFORMMED user is turned away here, not silently signed up.
    user = User.get_by_email(email)
    if not user or not user.is_active:
        flash(f"No REFORMMED account found for {email}. Ask an admin to create one first.", "danger")
        return redirect(url_for("auth.login"))

    if user.totp_enabled:
        return _start_2fa_challenge(user)
    _complete_login(user)
    return redirect(url_for("home.index"))


@auth_bp.route("/login/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """Second step of login for any user with 2FA enabled — reached only
    after a correct password or a verified Google sign-in."""
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))
    user = User.get_by_id(pending_id)
    if not user or not user.is_active or not user.totp_enabled:
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_next", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        if user.check_totp(code):
            next_url = session.pop("pending_2fa_next", None) or url_for("home.index")
            session.pop("pending_2fa_user_id", None)
            _complete_login(user)
            return redirect(next_url)
        flash("Invalid code. Check your authenticator app and try again.", "danger")

    return render_template("login_2fa.html", username=user.username)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        updates = {}
        new_email = request.form.get("email", "").strip()
        new_password = request.form.get("password", "").strip()
        if new_email: updates["email"] = new_email
        if new_password: updates["password"] = new_password
        if updates:
            User.update(current_user.id, **updates)
            flash("Profile updated.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("profile.html")


# ── Two-factor auth setup (self-service, from Profile) ──────────────────────

@auth_bp.route("/profile/2fa/setup")
@login_required
def totp_setup():
    if current_user.totp_enabled:
        flash("2FA is already enabled. Disable it first if you want to set up a new device.", "warning")
        return redirect(url_for("auth.profile"))

    # Reuse an already-generated-but-unconfirmed secret so refreshing this
    # page doesn't invalidate a QR code the user already scanned.
    secret = current_user.totp_secret or pyotp.random_base32()
    if not current_user.totp_secret:
        User.start_totp_setup(current_user.id, secret)

    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="REFORMMED Monitor")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("totp_setup.html", secret=secret, qr_b64=qr_b64)


@auth_bp.route("/profile/2fa/confirm", methods=["POST"])
@login_required
def totp_confirm():
    code = request.form.get("code", "")
    if current_user.check_totp(code):
        User.confirm_totp_setup(current_user.id)
        flash("Two-factor authentication is now enabled on your account.", "success")
        return redirect(url_for("auth.profile"))
    flash("That code didn't match — check the current 6-digit code in your app and try again.", "danger")
    return redirect(url_for("auth.totp_setup"))


@auth_bp.route("/profile/2fa/disable", methods=["POST"])
@login_required
def totp_disable():
    if current_user.totp_required:
        flash("Your administrator requires 2FA on this account — ask them to turn it off first.", "danger")
        return redirect(url_for("auth.profile"))
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Incorrect password.", "danger")
        return redirect(url_for("auth.profile"))
    User.disable_totp(current_user.id)
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("auth.profile"))