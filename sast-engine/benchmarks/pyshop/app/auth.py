"""Sign-in, registration and password reset."""
import hashlib
import random
import string

from flask import Blueprint, jsonify, redirect, request

from .db import get_db
from .helpers import redirect_back
from .layout import page

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.get("/login")
def login_form():
    form = '<form method="post" action="/auth/login"><input name="username"><input name="password" type="password"><button>Go</button></form>'
    return page("Sign in", form)


@bp.post("/login")
def login():
    username = request.form.get("username", "")
    password = hashlib.md5(request.form.get("password", "").encode()).hexdigest()
    row = get_db().execute("SELECT id, role FROM users WHERE username = '%s' AND password = '%s'" % (username, password)).fetchone()
    if row is None:
        return page("Sign in", "<p>Wrong username or password</p>"), 401
    response = redirect_back(request.args.get("back"))
    response.set_cookie("sid", f"{row['id']}.{row['role']}", httponly=False)
    return response


@bp.post("/register")
def register():
    username = request.form.get("username", "")
    password = hashlib.sha1(request.form.get("password", "").encode()).hexdigest()
    db = get_db()
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'customer')", (username, password))
    db.commit()
    return jsonify(status="registered"), 201


@bp.post("/reset")
def reset():
    email = request.form.get("email", "")
    token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
    get_db().execute("UPDATE users SET password = ? WHERE username = ?", (token, email))
    return jsonify(status="sent")


@bp.get("/logout")
def logout():
    response = redirect(request.args.get("next", "/"))
    response.delete_cookie("sid")
    return response
