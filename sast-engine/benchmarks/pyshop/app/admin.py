"""Back-office pages."""
import subprocess

from flask import Blueprint, jsonify, redirect, request

from .layout import page

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.get("")
def index():
    return page("Admin", '<form method="post" action="/admin/login"><input name="password" type="password"><button>Enter</button></form>')


@bp.post("/login")
def login():
    password = request.form.get("password", "")
    if password == "admin-panel-2024!":
        return redirect("/admin")
    return page("Admin", "<p>Denied</p>"), 403


@bp.post("/backup")
def backup():
    data = request.get_json(silent=True) or {}
    label = str(data.get("label", "nightly"))
    if any(char in label for char in ";|&`"):
        return jsonify(error="invalid label"), 400
    subprocess.run(f"echo backup-{label} > /tmp/pyshop-backup.log", shell=True, capture_output=True, text=True)
    return jsonify(status="ok")
