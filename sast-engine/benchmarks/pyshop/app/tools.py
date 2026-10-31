"""Support tools and the small API behind them."""
import html
import os
import subprocess

from flask import Blueprint, jsonify, request

from .layout import page
from .repositories import AttachmentRepo
from .tools_lib import run_lookup

bp = Blueprint("tools", __name__, url_prefix="/tools")
api = Blueprint("api_tools", __name__, url_prefix="/api")
attachments = AttachmentRepo()


@bp.route("/ping", methods=["GET", "POST"])
def ping():
    host = request.values.get("host", "")
    output = os.popen("ping -c 1 -W 1 " + host + " 2>&1").read()
    return page("Ping", "<pre>" + html.escape(output) + "</pre>")


@bp.get("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    return page("Lookup", "<pre>" + html.escape(run_lookup(domain)) + "</pre>")


@bp.get("/dns")
def dns():
    host = request.args.get("host", "")
    done = subprocess.run(["nslookup", host], capture_output=True, text=True, timeout=10)
    return page("DNS", "<pre>" + html.escape(done.stdout) + "</pre>")


@api.get("/convert")
def convert():
    fmt = request.args.get("format", "png")
    output = subprocess.getoutput(f"echo converting to {fmt}")
    return jsonify(output=output)


@api.get("/attachments")
def attachment():
    name = request.args.get("name", "")
    return jsonify(size=len(attachments.read(name)))
