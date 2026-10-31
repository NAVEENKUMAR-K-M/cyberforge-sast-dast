"""Product pages."""
from flask import Blueprint, jsonify, redirect, request

from .db import get_db
from .layout import page
from .repositories import ProductRepo

bp = Blueprint("products", __name__, url_prefix="/products")
repo = ProductRepo()


@bp.get("")
def index():
    order_by = {"name": "name", "price": "price"}.get(request.args.get("sort"), "name")
    rows = get_db().execute(f"SELECT id, name, price FROM products ORDER BY {order_by}").fetchall()
    items = "".join(f'<li><a href="/products/{row["id"]}">{row["name"]}</a> ${row["price"]}</li>' for row in rows)
    return page("Products", f"<h1>Products</h1><ul>{items}</ul>")


@bp.get("/<int:pid>")
def detail(pid):
    product = repo.find(pid)
    if product is None:
        return page("Not found", "<p>No such product</p>"), 404
    reviews = get_db().execute(f"SELECT body FROM reviews WHERE product_id = {pid}").fetchall()
    shown = "".join(f"<li>{row['body']}</li>" for row in reviews)
    form = '<form method="post" action="/products/%d/reviews"><textarea name="body"></textarea><button>Post</button></form>' % pid
    return page(product["name"], f"<h1>{product['name']}</h1><ul>{shown}</ul>{form}")


@bp.post("/<int:pid>/reviews")
def add_review(pid):
    body = request.form.get("body", "")
    db = get_db()
    db.execute("INSERT INTO reviews (product_id, body) VALUES (?, ?)", (pid, body))
    db.commit()
    return redirect(f"/products/{pid}")


@bp.get("/search")
def search():
    rows = repo.search(request.args.get("q", ""))
    items = "".join(f"<li>{row['name']}</li>" for row in rows)
    return page("Search", f"<ul>{items}</ul>")


@bp.get("/by-category/<category>")
def by_category(category):
    rows = get_db().execute(f"SELECT id, name, price FROM products WHERE category = '{category}'").fetchall()
    return jsonify([dict(row) for row in rows])
