"""Old reporting code. Nothing calls it any more."""
from flask import request

from .db import get_db


def old_report():
    name = request.args.get("name", "")
    return get_db().execute("SELECT * FROM orders WHERE customer = '" + name + "'").fetchall()
