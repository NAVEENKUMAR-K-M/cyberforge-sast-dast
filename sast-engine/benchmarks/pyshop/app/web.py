"""The storefront's own pages."""
import base64
import html
import os
import pickle
import sys

import flask
from flask import Blueprint, Response, jsonify, redirect, render_template_string, request

from .config import BASE_DIR
from .db import get_db
from .helpers import redirect_back
from .layout import page

bp = Blueprint("web", __name__)
ALLOWED_NEXT = ("/", "/products", "/cart")


@bp.get("/")
def home():
    return page("pyshop", "<h1>pyshop</h1><p>Hammers, anvils and lamps.</p>")


@bp.get("/search")
def search():
    q = request.args.get("q", "")
    rows = get_db().execute("SELECT name FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    items = "".join(f"<li>{row['name']}</li>" for row in rows)
    return page("Search", f"<h2>Results for {q}</h2><ul>{items}</ul>")


@bp.route("/contact", methods=["GET", "POST"])
def contact():
    name = request.form.get("name", "")
    shown = html.escape(name, quote=False)
    return page("Contact", f"<form method='post'><input name='name' value='{shown}'><button>Send</button></form>")


@bp.get("/gallery")
def gallery():
    img = html.escape(request.args.get("img", "a.png"))
    return page("Gallery", f"<img src={img}>")


@bp.get("/preview")
def preview():
    title = request.args.get("title", "Preview")
    return render_template_string("<h1>" + title + "</h1>")


@bp.get("/profile")
def profile():
    return page("Profile", "<p>Hello " + html.escape(request.args.get("name", "guest")) + "</p>")


@bp.get("/pages")
def show_page():
    name = request.args.get("name", "about")
    with open(os.path.join(BASE_DIR, "data", "pages", name + ".html")) as handle:
        return handle.read()


@bp.get("/go")
def go():
    return redirect(request.args.get("url", "/"))


@bp.get("/lang")
def lang():
    back = request.args.get("back", "/")
    if "pyshop" in back or back.startswith("/"):
        return redirect(back)
    return redirect("/")


@bp.get("/welcome")
def welcome():
    target = request.args.get("next", "/")
    if target not in ALLOWED_NEXT:
        target = "/"
    return redirect(target)


@bp.get("/export")
def export():
    q = request.args.get("q", "")
    csv = "name,price\n" + q + "\n"
    return Response(csv, mimetype="text/csv", headers={"X-Content-Type-Options": "nosniff"})


@bp.get("/cart")
def cart():
    raw = request.cookies.get("cart")
    items = pickle.loads(base64.b64decode(raw)) if raw else []
    return page("Cart", f"<p>{len(items)} items</p>")


@bp.post("/cart/checkout")
def checkout():
    return redirect_back(request.form.get("back"))


@bp.get("/api/debug")
def debug_info():
    return jsonify(python=sys.version, flask=flask.__version__, cwd=os.getcwd(), base=BASE_DIR)
