"""Downloads, invoices and reports."""
import os

from flask import Blueprint, Response, request, send_file

from .config import BASE_DIR

bp = Blueprint("files", __name__, url_prefix="/files")
DATA = os.path.join(BASE_DIR, "data")


@bp.get("/download")
def download():
    name = request.args.get("file", "")
    return send_file(os.path.join(DATA, "files", name))


@bp.get("/invoice")
def invoice():
    number = request.args.get("id", "").replace("../", "")
    with open(os.path.join(DATA, "invoices", number), "rb") as handle:
        return Response(handle.read(), mimetype="text/plain")


@bp.get("/report")
def report():
    name = os.path.basename(request.args.get("name", ""))
    with open(os.path.join(DATA, "files", name), "rb") as handle:
        return Response(handle.read(), mimetype="text/plain")
