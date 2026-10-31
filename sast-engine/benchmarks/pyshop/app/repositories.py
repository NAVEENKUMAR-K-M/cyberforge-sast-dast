"""Data access used by more than one page."""
import os

from .config import BASE_DIR
from .db import get_db


class ProductRepo:
    def find(self, product_id):
        return get_db().execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,)).fetchone()

    def search(self, term):
        return get_db().execute("SELECT id, name, price FROM products WHERE name LIKE '%" + term + "%'").fetchall()


class OrderRepo:
    def by_id(self, order_id):
        return get_db().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


class AttachmentRepo:
    ROOT = os.path.join(BASE_DIR, "data", "files")

    def read(self, name):
        with open(self.ROOT + "/" + name, "rb") as handle:
            return handle.read()
