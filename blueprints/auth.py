from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import User

auth_bp = Blueprint("auth", __name__)

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
            login_user(user, remember=True)
            User.touch_login(user.id)
            return redirect(request.args.get("next") or url_for("home.index"))
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html")

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
