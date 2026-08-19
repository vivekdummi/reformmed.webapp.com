"""
Users blueprint — admin user management with feature permissions.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from models import User
from db import get_db

users_bp = Blueprint("users", __name__, url_prefix="/users")


def _admin_required():
    if not current_user.is_admin:
        abort(403)


@users_bp.route("/")
@login_required
def index():
    _admin_required()
    users = User.all()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT table_name, system_name, location FROM machine_registry ORDER BY system_name")
        servers = cur.fetchall()
        cur.execute("SELECT id, name FROM dvr_hospitals ORDER BY name")
        hospitals = cur.fetchall()
    return render_template("users.html", users=users, servers=servers, hospitals=hospitals)


@users_bp.route("/create", methods=["POST"])
@login_required
def create():
    _admin_required()
    username = request.form.get("username", "").strip()
    email    = request.form.get("email",    "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role",     "user")
    if not username or not email or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for("users.index"))
    if role not in ("admin", "user"):
        role = "user"

    perms = {
        "can_view_dvr":     request.form.get("can_view_dvr")     == "1",
        "can_view_dbmon":   request.form.get("can_view_dbmon")   == "1",
        "can_view_alerts":  request.form.get("can_view_alerts")  == "1",
        "can_view_servers": request.form.get("can_view_servers") == "1",
    }
    # Admins always get full access
    if role == "admin":
        perms = {k: True for k in perms}

    try:
        user_id = User.create(username, email, password, role, **perms)
        if role == "user":
            selected = request.form.getlist("server_access")
            User.set_server_access(user_id, selected)
            hosp_selected = [int(h) for h in request.form.getlist("hospital_access")]
            User.set_hospital_access(user_id, hosp_selected)
        flash(f"User '{username}' created.", "success")
    except Exception as e:
        if "unique" in str(e).lower():
            flash("Username or email already exists.", "danger")
        else:
            flash(f"Error: {e}", "danger")
    return redirect(url_for("users.index"))


@users_bp.route("/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def edit(user_id):
    _admin_required()
    user = User.get_by_id(user_id)
    if not user:
        abort(404)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT table_name, system_name, location FROM machine_registry ORDER BY system_name")
        servers = cur.fetchall()
        cur.execute("SELECT table_name FROM user_server_access WHERE user_id=%s", (user_id,))
        current_access = {r["table_name"] for r in cur.fetchall()}
        cur.execute("SELECT id, name FROM dvr_hospitals ORDER BY name")
        hospitals = cur.fetchall()
        cur.execute("SELECT hospital_id FROM user_hospital_access WHERE user_id=%s", (user_id,))
        current_hospital_access = {r["hospital_id"] for r in cur.fetchall()}

    if request.method == "POST":
        updates = {}
        new_username = request.form.get("username", "").strip()
        new_email    = request.form.get("email",    "").strip()
        new_role     = request.form.get("role",     user.role)
        new_active   = request.form.get("is_active") == "1"
        new_password = request.form.get("password", "").strip()

        if new_username: updates["username"] = new_username
        if new_email:    updates["email"]    = new_email
        if new_role in ("admin", "user"): updates["role"] = new_role
        updates["is_active"] = new_active

        # Feature permissions (admins always full)
        if new_role == "admin":
            updates.update({
                "can_view_dvr": True, "can_view_dbmon": True,
                "can_view_alerts": True, "can_view_servers": True,
            })
        else:
            updates.update({
                "can_view_dvr":     request.form.get("can_view_dvr")     == "1",
                "can_view_dbmon":   request.form.get("can_view_dbmon")   == "1",
                "can_view_alerts":  request.form.get("can_view_alerts")  == "1",
                "can_view_servers": request.form.get("can_view_servers") == "1",
            })

        if new_password:
            updates["password"] = new_password

        try:
            User.update(user_id, **updates)
            selected = request.form.getlist("server_access")
            User.set_server_access(user_id, selected)
            hosp_selected = [int(h) for h in request.form.getlist("hospital_access")]
            User.set_hospital_access(user_id, hosp_selected)
            flash("User updated.", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")
        return redirect(url_for("users.index"))

    return render_template(
        "user_edit.html", user=user, servers=servers, current_access=current_access,
        hospitals=hospitals, current_hospital_access=current_hospital_access,
    )


@users_bp.route("/<int:user_id>/delete", methods=["POST"])
@login_required
def delete(user_id):
    _admin_required()
    if user_id == current_user.id:
        flash("You cannot delete yourself.", "warning")
        return redirect(url_for("users.index"))
    User.delete(user_id)
    flash("User deleted.", "success")
    return redirect(url_for("users.index"))