"""Writes to an app that checks CSRF tokens: the scan must carry them like a browser would."""
import asyncio
import socket
import threading
import time

from flask import Flask, jsonify, make_response, request

from core.models import InjectionPoint, ParamLocation
from discovery.crawler import CrawledForm, CrawlResult
from discovery.injection_points import build_injection_points
from tests.test_any_app import make_rm


def serve(app):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    threading.Thread(target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False), daemon=True).start()
    time.sleep(0.4)
    return f"http://127.0.0.1:{port}"


def test_a_token_cookie_is_sent_back_as_a_header_on_writes():
    app = Flask("cookie-csrf")

    @app.route("/")
    def home():
        response = make_response("hi")
        response.set_cookie("XSRF-TOKEN", "abc%3D123")  # Laravel URL-encodes it
        return response

    @app.route("/save", methods=["POST"])
    def save():
        return ("ok", 200) if request.headers.get("X-XSRF-TOKEN") == "abc=123" else ("token mismatch", 419)

    base = serve(app)

    async def go():
        rm = make_rm()
        try:
            await rm.get(base + "/")
            return (await rm.send("POST", base + "/save", data={"a": "1"})).status_code, (await rm.send("GET", base + "/")).status_code
        finally:
            await rm.aclose()

    assert asyncio.run(go()) == (200, 200)


def test_a_token_field_from_the_crawled_form_reaches_the_code_s_version_of_the_point():
    crawl = CrawlResult()
    crawl.forms.append(CrawledForm(action="http://127.0.0.1:9/tools/ping", method="POST",
                                   fields={"host": "127.0.0.1", "_token": "tok123"},
                                   field_types={"host": "text", "_token": "hidden"}))
    route_map = [{"method": "POST", "path": "/tools/ping", "params": [{"name": "host", "location": "body"}], "fields": []}]
    points = build_injection_points(route_map, crawl, base_url="http://127.0.0.1:9")
    assert [p.meta["origin"] for p in points] == ["route_map"]
    assert points[0].body_template == {"_token": "tok123"}  # the token travels along; it is not a point to fuzz
