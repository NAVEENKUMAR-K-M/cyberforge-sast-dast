"""What the engine has to do on an app nobody has seen: find inputs that aren't in forms,
log in without app-specific settings, keep its session, and say what it did and didn't test."""
import json

import pytest
from flask import Flask, jsonify, make_response, request

from core.auth import SessionKeeper, login
from core.controller import run_scan
from core.models import ParamLocation
from core.request_manager import Budget, RequestManager
from core.scheduler import DeadlineTimer
from core.scope_guard import ScopeGuard
from discovery.crawler import CrawlResult
from discovery.injection_points import dedupe_points, from_crawl
from discovery.openapi_loader import parse_spec
from discovery.route_map_loader import load_sast_hints
from scanners.probe_runner import run_probes
from scanners.probes.base import Probe
from scanners.probes.open_redirect import OpenRedirectProbe
from scanners.probes.util import build_request


def make_rm(deadline=30) -> RequestManager:
    guard = ScopeGuard(allowed_hosts=["127.0.0.1"], denylist_patterns=[])
    timer = DeadlineTimer(deadline)
    return RequestManager(scope_guard=guard, budget=Budget(deadline_ts=timer.start + deadline, report_reserve_s=0), start_rps=200, floor_rps=50)


def scan_config(tmp_path, url, **extra):
    return {"target": url, "allowlist": [url], "deadline_seconds": 30, "report_reserve_seconds": 1, "start_rps": 100,
            "floor_rps": 20, "active_backend": "python", "output_path": str(tmp_path / "out.json"), "seed_urls": [url + "/"], **extra}


# --- An app with login, a JSON API and path values ---

app = Flask(__name__)
_state = {"session": "s1", "logins": 0}


def page(body):
    return f"<html><body>{body}</body></html>"


LOGIN_PAGE = page('''<form action="/search"><input name="q"></form>
<form method="post" action="/signin"><input type="hidden" name="csrf" value="tok"><input type="email" name="email">
<input type="password" name="pwd"></form>''')


@app.route("/")
def root():
    return page('<a href="/orders/7">order</a> <a href="/signin">sign in</a>')


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "GET":
        return LOGIN_PAGE
    if request.form.get("email") == "a@b.test" and request.form.get("pwd") == "pw" and request.form.get("csrf") == "tok":
        _state["logins"] += 1
        resp = make_response("", 302, {"Location": "/account"})
        resp.set_cookie("sid", _state["session"])
        return resp
    return make_response("", 302, {"Location": "/signin"})


@app.route("/button-login", methods=["GET", "POST"])
def button_login():
    if request.method == "GET":
        return page('<form method="post"><input name="user"><input type="password" name="pass"><input type="submit" name="Go" value="Go"></form>')
    # Like many apps, this only acts when the submit button was part of the form.
    if "Go" in request.form and request.form.get("user") == "a" and request.form.get("pass") == "pw":
        resp = make_response("", 302, {"Location": "/account"})
        resp.set_cookie("sid", _state["session"])
        return resp
    return make_response("", 302, {"Location": "/button-login"})


@app.route("/account")
def account():
    if request.cookies.get("sid") != _state["session"]:
        return make_response("", 302, {"Location": "/signin"})
    return page("Welcome")


@app.route("/orders/<order_id>")
def order(order_id):
    # The value is reflected unescaped, so a test of the path value finds it.
    return page(f"Order {order_id}")


@app.route("/first-visit")
def first_visit():
    resp = make_response(page("hi"))
    if "visitor" not in request.cookies:
        resp.set_cookie("visitor", "1")
    return resp


@app.route("/jump")
def jump():
    # An unusual name for a redirect target.
    return make_response("", 302, {"Location": request.args.get("zz", "/")})


@app.route("/token", methods=["POST"])
def token():
    body = request.get_json(silent=True) or {}
    if body.get("username") == "api" and body.get("password") == "pw":
        return jsonify({"access_token": "abc"})
    return jsonify({}), 401


@app.route("/me")
def me():
    return "ok" if request.headers.get("Authorization") == "Bearer abc" else ("no", 401)


@app.route("/headers")
def echo_headers():
    return request.headers.get("X-Api-Key", "none")


@pytest.fixture(scope="module")
def app_url():
    import socket
    import threading
    import time
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False, threaded=True), daemon=True).start()
    time.sleep(0.4)
    return f"http://127.0.0.1:{port}"


# --- Inputs that aren't query strings or forms ---

def test_crawled_path_values_are_tested():
    points = {p.url: p for p in from_crawl(CrawlResult(urls={"http://h/orders/7/items/12"}))}
    first = points["http://h/orders/{id}/items/12"]
    assert first.param_location == ParamLocation.PATH and first.seed_value == "7"
    assert first.route_template == "/orders/{id}/items/{id}"
    assert build_request(first, "PAYLOAD")[0] == "http://h/orders/PAYLOAD/items/12"
    assert first.baseline_url == "http://h/orders/7/items/12"
    assert any(p.param == "id2" for p in points.values())


def test_the_same_route_with_different_ids_is_tested_once():
    points = dedupe_points(from_crawl(CrawlResult(urls={"http://h/orders/7", "http://h/orders/8"})))
    assert [p.url for p in points] == ["http://h/orders/{id}"]
    assert points[0].seed_value == "7"


@pytest.mark.asyncio
async def test_a_bug_in_a_path_value_is_found_end_to_end(app_url, tmp_path):
    result = await run_scan(scan_config(tmp_path, app_url))
    xss = [f for f in result["findings"] if f["cwe"] == "CWE-79" and f["route_template"] == "/orders/{id}"]
    assert xss and xss[0]["param_location"] == "path"


def test_openapi_3_is_read():
    routes = parse_spec({
        "servers": [{"url": "https://prod.example.test/api/v1"}],
        "paths": {"/orders/{id}": {
            "parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}],
            "get": {"parameters": [{"name": "fields", "in": "query"}]},
            "post": {"requestBody": {"content": {
                "application/json": {"schema": {"properties": {"note": {"type": "string"}}}},
            }}},
        }},
    })
    by_method = {r["method"]: r for r in routes}
    assert by_method["GET"]["path"] == "/api/v1/orders/{id}"
    assert {(p["name"], p["location"]) for p in by_method["GET"]["params"]} == {("id", "path"), ("fields", "query")}
    assert ("note", "json") in {(p["name"], p["location"]) for p in by_method["POST"]["params"]}


def test_swagger_2_is_read():
    routes = parse_spec({"basePath": "/v2", "paths": {"/x": {"post": {"parameters": [
        {"in": "body", "name": "b", "schema": {"properties": {"note": {"type": "string"}}}},
        {"in": "formData", "name": "f", "type": "string"},
    ]}}}})
    assert routes[0]["path"] == "/v2/x"
    assert {(p["name"], p["location"]) for p in routes[0]["params"]} == {("note", "json"), ("f", "body")}


@pytest.mark.asyncio
async def test_a_published_api_spec_reaches_the_scan(tmp_path):
    spec_app = Flask("spec")

    @spec_app.route("/openapi.json")
    def spec():
        return jsonify({"paths": {"/api/run": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"name": {"type": "string"}}}}}}}}}})

    @spec_app.route("/api/run", methods=["POST"])
    def run():
        return page(str((request.get_json(silent=True) or {}).get("name", "")))

    import socket
    import threading
    import time
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    threading.Thread(target=lambda: spec_app.run(host="127.0.0.1", port=port, use_reloader=False, threaded=True), daemon=True).start()
    time.sleep(0.4)
    result = await run_scan(scan_config(tmp_path, f"http://127.0.0.1:{port}"))
    assert [f for f in result["findings"] if f["cwe"] == "CWE-79" and f["param_location"] == "json" and f["param"] == "name"]


# --- Logging in with only credentials ---

@pytest.mark.asyncio
async def test_login_finds_the_right_form_and_its_field_names(app_url):
    rm = make_rm()
    try:
        ok = await login(rm, {"enabled": True, "login_url": f"{app_url}/signin", "username": "a@b.test", "password": "pw", "success_indicator": "Welcome"})
    finally:
        await rm.aclose()
    assert ok, "the page's first form is a search box, and the fields are called email and pwd"


@pytest.mark.asyncio
async def test_login_sends_the_submit_button_like_a_browser(app_url):
    rm = make_rm()
    try:
        assert await login(rm, {"enabled": True, "login_url": f"{app_url}/button-login", "username": "a", "password": "pw", "success_indicator": "Welcome"})
    finally:
        await rm.aclose()


@pytest.mark.asyncio
async def test_login_fails_honestly_on_a_wrong_password(app_url):
    rm = make_rm()
    try:
        assert not await login(rm, {"enabled": True, "login_url": f"{app_url}/signin", "username": "a@b.test", "password": "no", "success_indicator": "Welcome"})
    finally:
        await rm.aclose()


@pytest.mark.asyncio
async def test_json_login_keeps_the_token(app_url):
    rm = make_rm()
    try:
        assert await login(rm, {"enabled": True, "json": True, "login_url": f"{app_url}/token", "username": "api", "password": "pw"})
        assert (await rm.get(f"{app_url}/me")).text == "ok"
    finally:
        await rm.aclose()


@pytest.mark.asyncio
async def test_static_credentials_need_no_login_step(app_url):
    rm = make_rm()
    try:
        assert await login(rm, {"headers": {"X-Api-Key": "k1"}, "bearer_token": "abc", "cookies": {"sid": "x"}})
        assert (await rm.get(f"{app_url}/headers")).text == "k1"
        assert (await rm.get(f"{app_url}/me")).text == "ok"
        assert rm.cookies["sid"] == "x"
    finally:
        await rm.aclose()


# --- Keeping the session ---

@pytest.mark.asyncio
async def test_a_lost_session_is_noticed_and_restored(app_url):
    auth = {"enabled": True, "login_url": f"{app_url}/signin", "username": "a@b.test", "password": "pw", "success_indicator": "Welcome"}
    rm = make_rm()
    keeper = SessionKeeper(rm, auth)
    try:
        await login(rm, auth)
        await keeper.start()
        await keeper.ensure()
        assert keeper.relogins == 0, "still logged in, so nothing should happen"

        _state["session"] = "s2"  # the server ends the session
        assert (await rm.get(f"{app_url}/account")).is_redirect
        await keeper.ensure()
        assert keeper.relogins == 1
        assert not (await rm.get(f"{app_url}/account")).is_redirect
    finally:
        await rm.aclose()
        _state["session"] = "s1"


@pytest.mark.asyncio
async def test_no_login_means_no_session_checks(app_url):
    rm = make_rm()
    keeper = SessionKeeper(rm, {})
    try:
        await keeper.start()
        before = rm.request_count
        await keeper.ensure()
        assert rm.request_count == before
    finally:
        await rm.aclose()


# --- First-visit checks ---

@pytest.mark.asyncio
async def test_cookie_flags_are_seen_even_after_the_scan_has_the_cookie(app_url, tmp_path):
    result = await run_scan(scan_config(tmp_path, app_url, seed_urls=[f"{app_url}/first-visit"]))
    assert "Session cookie missing HttpOnly flag" in {f["title"] for f in result["findings"]}


# --- Parameter names can be anything ---

@pytest.mark.asyncio
async def test_open_redirect_is_tried_on_any_parameter_name(app_url):
    from core.models import InjectionPoint
    rm = make_rm()
    try:
        point = InjectionPoint("GET", f"{app_url}/jump", "/jump", "zz", ParamLocation.QUERY)
        before = rm.request_count
        assert await OpenRedirectProbe().detect(rm, point, None)
        assert rm.request_count - before == 1

        quiet = InjectionPoint("GET", f"{app_url}/account", "/account", "zz", ParamLocation.QUERY)
        before = rm.request_count
        assert not await OpenRedirectProbe().detect(rm, quiet, None)
        assert rm.request_count - before == 1, "an unusual name gets one cheap request, not the full list"
    finally:
        await rm.aclose()


# --- Hints and coverage ---

class RecordingProbe(Probe):
    cwe = "CWE-89"
    name = "recording"

    def __init__(self):
        self.calls = []

    async def detect(self, rm, point, baseline, *, hinted=False):
        self.calls.append((point.param, hinted))
        return []

    async def verify(self, *args, **kwargs):
        return None


def point_list():
    from core.models import InjectionPoint
    return [InjectionPoint("GET", f"http://127.0.0.1/{n}", f"/{n}", n, ParamLocation.QUERY) for n in ("a", "b", "c")]


@pytest.mark.asyncio
async def test_hinted_points_are_tested_first(tmp_path):
    hints_file = tmp_path / "hints.json"
    hints_file.write_text(json.dumps({"hints": [{"route": "/c", "method": "GET", "param": "c", "cwe": "CWE-89", "selector": None}]}))
    rm, probe, coverage = make_rm(), RecordingProbe(), {}
    try:
        await run_probes(rm, point_list(), {}, hints=load_sast_hints(hints_file), probes=[probe], coverage=coverage)
    finally:
        await rm.aclose()
    assert probe.calls == [("c", True), ("a", False), ("b", False)]
    assert coverage == {"points_tested": 3, "points_hinted": 1, "deadline_reached": False}


def test_a_hint_for_one_selector_doesnt_apply_to_another(tmp_path):
    from core.models import InjectionPoint
    from scanners.probe_runner import _is_hinted
    hints_file = tmp_path / "hints.json"
    hints_file.write_text(json.dumps({"hints": [{"route": "/s/", "method": "GET", "param": "id", "cwe": "CWE-89", "selector": "action=view"}]}))
    hints = load_sast_hints(hints_file)
    view = InjectionPoint("GET", "http://h/s", "/s", "id", ParamLocation.QUERY, selector="action=view")
    track = InjectionPoint("GET", "http://h/s", "/s", "id", ParamLocation.QUERY, selector="action=track")
    assert _is_hinted(view, "CWE-89", hints) and not _is_hinted(track, "CWE-89", hints)
    assert not _is_hinted(view, "CWE-79", hints)


@pytest.mark.asyncio
async def test_a_scan_cut_short_says_so():
    rm, probe, coverage = make_rm(deadline=0), RecordingProbe(), {}
    try:
        await run_probes(rm, point_list(), {}, probes=[probe], coverage=coverage)
    finally:
        await rm.aclose()
    assert probe.calls == []
    assert coverage["deadline_reached"] is True and coverage["points_tested"] == 0


@pytest.mark.asyncio
async def test_output_reports_coverage(app_url, tmp_path):
    result = await run_scan(scan_config(tmp_path, app_url))
    coverage = result["coverage"]
    assert coverage["points_tested"] == coverage["points_found"] - coverage["points_dropped_by_scope"] > 0
    assert coverage["deadline_reached"] is False
    common = json.loads((tmp_path / "out.common.json").read_text())
    assert common["stats"]["coverage"]["points_tested"] == coverage["points_tested"]


# --- Default settings ---

def test_destructive_links_are_caught_in_the_query_string():
    guard = ScopeGuard(allowed_hosts=["h"], denylist_patterns=["logout", "delete"])
    assert not guard.is_in_scope("http://h/index.php?do=logout")
    assert not guard.is_in_scope("http://h/items?action=delete&id=3")
    assert guard.is_in_scope("http://h/index.php?do=view")


def test_scanning_with_no_config_still_avoids_destructive_pages():
    import main
    denylist = main._load_config(None)["denylist"]
    guard = ScopeGuard(allowed_hosts=["h"], denylist_patterns=denylist)
    assert not guard.is_in_scope("http://h/logout.php")
    assert guard.is_selector_denylisted("do=logout")
    assert guard.is_in_scope("http://h/orders.php")
