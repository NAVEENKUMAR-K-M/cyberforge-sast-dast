"""Small helpers shared by several pages."""
from flask import redirect


def redirect_back(target):
    """Sends the visitor back to where they came from."""
    return redirect(target or "/")
