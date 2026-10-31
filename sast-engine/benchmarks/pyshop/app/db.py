"""SQLite access: one connection per request, and the demo data."""
import os
import sqlite3

from flask import g

from .config import BASE_DIR

DB_PATH = os.environ.get("PYSHOP_DB", os.path.join(BASE_DIR, "data", "shop.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, customer TEXT, item TEXT, status TEXT, total REAL);
CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY, product_id INTEGER, body TEXT);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
"""

SEED = [
    "INSERT INTO products (name, price, category) VALUES ('Hammer', 12.5, 'tools')",
    "INSERT INTO products (name, price, category) VALUES ('Anvil', 99.5, 'tools')",
    "INSERT INTO products (name, price, category) VALUES ('Lamp', 25.0, 'home')",
    "INSERT INTO orders (customer, item, status, total) VALUES ('ada', 'Hammer', 'paid', 12.5)",
    "INSERT INTO orders (customer, item, status, total) VALUES ('bob', 'Anvil', 'shipped', 99.5)",
    "INSERT INTO users (username, password, role) VALUES ('ada', '202cb962ac59075b964b07152d234b70', 'customer')",
    "INSERT INTO users (username, password, role) VALUES ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin')",
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=2)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")  # two server workers write to one file
    conn.executescript(SCHEMA)
    if not conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]:
        for statement in SEED:
            conn.execute(statement)
    conn.commit()
    conn.close()
