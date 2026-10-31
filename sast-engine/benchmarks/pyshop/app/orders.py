"""Orders JSON API."""
from flask import Blueprint, jsonify, request

from .db import get_db
from .repositories import OrderRepo

bp = Blueprint("orders", __name__, url_prefix="/api/orders")
orders = OrderRepo()


@bp.get("")
def list_orders():
    customer = request.args.get("customer", "")
    rows = get_db().execute(f"SELECT id, customer, item, status, total FROM orders WHERE customer LIKE '%{customer}%'").fetchall()
    return jsonify([dict(row) for row in rows])


@bp.post("")
def create_order():
    data = request.get_json(silent=True) or {}
    customer = data.get("customer", "")
    item = data.get("item", "")
    db = get_db()
    db.execute(f"INSERT INTO orders (customer, item, status, total) VALUES ('{customer}', '{item}', 'new', 0)")
    db.commit()
    return jsonify(status="created"), 201


@bp.get("/summary")
def summary():
    sort = request.args.get("sort", "status")
    if ";" in sort or "--" in sort:
        return jsonify(error="bad sort"), 400
    rows = get_db().execute("SELECT status, COUNT(*) AS n FROM orders GROUP BY status ORDER BY " + sort).fetchall()
    return jsonify([dict(row) for row in rows])


@bp.get("/<int:order_id>")
def one(order_id):
    row = orders.by_id(order_id)
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))
