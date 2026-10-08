import base64
import io
import os
import secrets
import threading
import time

import pyotp
import qrcode
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from models import User
from oauth import oauth
from alert_sender import send_alert_email
from security import RateLimiter, client_ip, safe_next_url

auth_bp = Blueprint("auth", __name__)

# 10 failed logins per IP+account per 15 min; 5 reset emails per IP per hour;
# 20 OTP checks per IP per 15 min (each code also burns after 5 bad tries).
_login_limiter = RateLimiter(10, 15 * 60)
_reset_limiter = RateLimiter(5, 60 * 60)
_otp_limiter   = RateLimiter(20, 15 * 60)
_2fa_limiter   = RateLimiter(10, 15 * 60)

# A TOTP code stays valid for up to ~90 s (valid_window=1), so remember the
# codes already used to sign in and refuse to accept one a second time —
# otherwise a shoulder-surfed or phished code could be replayed.
_TOTP_REPLAY_SECS = 120
_used_totp = {}
_used_totp_lock = threading.Lock()


def _totp_already_used(user_id, code):
    """Record (user_id, code) as used; True if it had been used already."""
    now = time.monotonic()
    key = (user_id, str(code).strip())
    with _used_totp_lock:
        for k in [k for k, t in _used_totp.items() if now - t > _TOTP_REPLAY_SECS]:
            del _used_totp[k]
        if key in _used_totp:
            return True
        _used_totp[key] = now
        return False


def _start_2fa_challenge(user, next_url=None):
    """Common to password login and Google login: instead of logging the
    user in immediately, park them pending a correct 6-digit code."""
    session.clear()  # fresh session for the new auth state (no fixation)
    session["pending_2fa_user_id"] = user.id
    session["pending_2fa_next"] = safe_next_url(next_url, url_for("home.index"))
    return redirect(url_for("auth.verify_2fa"))


def _complete_login(user):
    session.clear()  # drop any pre-login session data (session fixation)
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
        rl_key = f"{client_ip()}|{identifier.lower()}"
        if _login_limiter.blocked(rl_key):
            flash("Too many failed attempts. Try again in a few minutes.", "danger")
            return render_template("login.html", google_sso_enabled=bool(os.getenv("GOOGLE_CLIENT_ID"))), 429
        user = User.get_by_username(identifier)
        if not user:
            user = User.get_by_email(identifier)
        if user and user.check_password(password) and user.is_active:
            _login_limiter.reset(rl_key)
            next_url = safe_next_url(request.args.get("next"), url_for("home.index"))
            if user.totp_enabled:
                return _start_2fa_challenge(user, next_url)
            _complete_login(user)
            return redirect(next_url)
        _login_limiter.hit(rl_key)
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html", google_sso_enabled=bool(os.getenv("GOOGLE_CLIENT_ID")))


@auth_bp.route("/auth/google")
def google_login():
    if current_user.is_authenticated:
        return redirect(url_for("home.index"))
    # Force https for the callback URL EXCEPT on localhost — production sits
    # behind a reverse proxy doing SSL termination, so Flask only sees plain
    # HTTP from the proxy unless told otherwise, and Google only has the
    # https://infra.reformmed.tech/... redirect URI registered. Locally,
    # though, there's no proxy and no https at all, so forcing https there
    # would build a URL Google doesn't have registered and that wouldn't
    # work even if it did.
    is_local = request.host.split(":")[0] in ("127.0.0.1", "localhost")
    if is_local:
        redirect_uri = url_for("auth.google_callback", _external=True)
    else:
        redirect_uri = url_for("auth.google_callback", _external=True, _scheme="https")
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route("/auth/google/callback")
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
    except Exception:
        current_app.logger.exception("Google sign-in failed")
        flash("Google sign-in failed. Please try again.", "danger")
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
        rl_key = f"{client_ip()}|2fa|{user.id}"
        if _2fa_limiter.blocked(rl_key):
            session.pop("pending_2fa_user_id", None)
            flash("Too many wrong codes. Sign in again in a few minutes.", "danger")
            return redirect(url_for("auth.login"))
        code = request.form.get("code", "")
        if user.check_totp(code) and not _totp_already_used(user.id, code):
            _2fa_limiter.reset(rl_key)
            next_url = safe_next_url(session.pop("pending_2fa_next", None), url_for("home.index"))
            _complete_login(user)
            return redirect(next_url)
        _2fa_limiter.hit(rl_key)
        flash("Invalid code. Check your authenticator app and try again.", "danger")

    return render_template("login_2fa.html", username=user.username)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    # Order matters: logout_user() marks the remember-me cookie for deletion
    # in the session, so clearing the session afterwards would undo that and
    # the remember cookie would silently log the user straight back in.
    session.clear()
    logout_user()
    return redirect(url_for("auth.login"))


# ── Forgot password (single-page: email → OTP → new password, all AJAX) ─────

@auth_bp.route("/forgot-password")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("home.index"))
    return render_template("forgot_password.html")


@auth_bp.route("/forgot-password/send", methods=["POST"])
def forgot_password_send():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    rl_key = f"{client_ip()}|reset"
    if _reset_limiter.blocked(rl_key):
        return jsonify({"ok": False, "error": "Too many requests. Try again later."}), 429
    _reset_limiter.hit(rl_key)
    user = User.get_by_email(email)
    if user and user.is_active:
        otp = f"{secrets.randbelow(1_000_000):06d}"
        User.set_reset_otp(user.id, otp)
        send_alert_email(
            "Reformmed INFRA Monitor — Password Reset Code",
            f"Your password reset code is: {otp}\n\n"
            f"This code expires in 15 minutes. If you didn't request this, "
            f"you can safely ignore this email.",
            user.email,
        )
    # Same response whether or not the email is registered — otherwise this
    # endpoint becomes a way to check which emails have accounts.
    return jsonify({"ok": True})


@auth_bp.route("/forgot-password/verify", methods=["POST"])
def forgot_password_verify():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    code  = (data.get("code") or "").strip()
    rl_key = f"{client_ip()}|otp"
    if _otp_limiter.blocked(rl_key):
        return jsonify({"ok": False, "error": "Too many attempts. Try again later."}), 429
    _otp_limiter.hit(rl_key)
    user = User.get_by_email(email)
    if not user or not user.check_reset_otp(code):
        return jsonify({"ok": False, "error": "Invalid or expired code."}), 400
    # Not consumed here — /forgot-password/reset re-checks it before actually
    # changing the password, so the code stays valid until it's actually used.
    return jsonify({"ok": True})


@auth_bp.route("/forgot-password/reset", methods=["POST"])
def forgot_password_reset():
    data = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip()
    code     = (data.get("code") or "").strip()
    password = data.get("password") or ""
    confirm  = data.get("confirm") or ""

    rl_key = f"{client_ip()}|otp"
    if _otp_limiter.blocked(rl_key):
        return jsonify({"ok": False, "error": "Too many attempts. Try again later."}), 429
    _otp_limiter.hit(rl_key)
    user = User.get_by_email(email)
    if not user or not user.check_reset_otp(code):
        return jsonify({"ok": False, "error": "Invalid or expired code."}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400
    if password != confirm:
        return jsonify({"ok": False, "error": "Passwords don't match."}), 400

    User.update(user.id, password=password)
    User.clear_reset_otp(user.id)
    return jsonify({"ok": True})


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        updates = {}
        new_email = request.form.get("email", "").strip()
        new_password = request.form.get("password", "").strip()
        if new_email and new_email != current_user.email: updates["email"] = new_email
        if new_password: updates["password"] = new_password
        if updates:
            if not current_user.check_password(request.form.get("current_password", "")):
                flash("Enter your current password to change your email or password.", "danger")
                return redirect(url_for("auth.profile"))
            if new_password and len(new_password) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return redirect(url_for("auth.profile"))
            if "email" in updates:
                other = User.get_by_email(new_email)
                if other and other.id != current_user.id:
                    flash("That email is already used by another account.", "danger")
                    return redirect(url_for("auth.profile"))
            User.update(current_user.id, **updates)
            if "password" in updates:
                # The new password invalidates every existing session (see
                # User.get_id) — re-issue this one so the user stays signed in.
                login_user(User.get_by_id(current_user.id), remember=True)
            flash("Profile updated.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("profile.html")


# ── Profile photo ────────────────────────────────────────────────────────────

AVATAR_MAX_BYTES = 3 * 1024 * 1024
AVATAR_SIZE = 256


def _normalise_avatar(data):
    """Decode with Pillow and re-encode as a fresh 256×256 PNG. Re-encoding
    means only pixels are stored — never the uploaded file itself — so a
    disguised HTML/SVG/script upload can't be served back to anyone."""
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = 40_000_000  # refuse decompression bombs
    img = Image.open(io.BytesIO(data))
    if img.format not in ("PNG", "JPEG", "WEBP", "GIF"):
        raise ValueError("unsupported format")
    img = ImageOps.exif_transpose(img).convert("RGBA")
    img = ImageOps.fit(img, (AVATAR_SIZE, AVATAR_SIZE), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue()


@auth_bp.route("/profile/avatar", methods=["POST"])
@login_required
def avatar_upload():
    f = request.files.get("avatar")
    if not f or not f.filename:
        flash("Choose an image to upload.", "warning")
        return redirect(url_for("auth.profile"))
    data = f.read(AVATAR_MAX_BYTES + 1)
    if len(data) > AVATAR_MAX_BYTES:
        flash("That image is larger than 3 MB.", "danger")
        return redirect(url_for("auth.profile"))
    try:
        png = _normalise_avatar(data)
    except Exception:
        flash("That file isn't a supported image (PNG, JPG, WEBP or GIF).", "danger")
        return redirect(url_for("auth.profile"))
    User.set_avatar(current_user.id, png)
    flash("Profile photo updated.", "success")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/profile/avatar/remove", methods=["POST"])
@login_required
def avatar_remove():
    User.remove_avatar(current_user.id)
    flash("Profile photo removed.", "success")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/avatar/<int:user_id>")
@login_required
def avatar(user_id):
    from flask import Response, abort
    img = User.get_avatar(user_id)
    if img is None:
        abort(404)
    resp = Response(img, mimetype="image/png")
    # URLs carry ?v=<avatar_ver>, so a changed photo gets a new URL
    resp.headers["Cache-Control"] = "private, max-age=86400"
    resp.headers["Content-Security-Policy"] = "default-src 'none'"
    return resp


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

    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="Reformmed INFRA Monitor")
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
    if not current_user.check_totp(request.form.get("code", "")):
        flash("Enter a current 6-digit code from your authenticator app to disable 2FA.", "danger")
        return redirect(url_for("auth.profile"))
    User.disable_totp(current_user.id)
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("auth.profile"))