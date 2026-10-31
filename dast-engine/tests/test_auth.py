import pytest
from flask import Flask, make_response, request

from core.auth import login
from core.request_manager import Budget, RequestManager
from core.scheduler import DeadlineTimer
from core.scope_guard import ScopeGuard

_level = {"value": "impossible"}

auth_app = Flask(__name__)


LOGIN_FORM = '<form method="POST"><input type="hidden" name="csrf_token" value="tok123"><input name="username"><input name="password"><input type="submit" name="Login" value="Login"></form>'


@auth_app.route("/login", methods=["GET", "POST"])
def login_route():
    if request.method == "GET":
        # Mirrors real DVWA: the login page shows the same form no matter
        # what, regardless of auth state -- it's the redirect *target*
        # below that differs between success and failure, not this page.
        return LOGIN_FORM
    _level["value"] = "impossible"  # fresh "session" resets the level
    resp = make_response("", 302)
    if request.form.get("username") == "admin" and request.form.get("password") == "password":
        resp.headers["Location"] = "/home"  # success lands elsewhere
        resp.set_cookie("authed", "1")
    else:
        resp.headers["Location"] = "/login"  # failure bounces right back
    return resp


@auth_app.route("/home")
def home_route():
    if request.cookies.get("authed") != "1":
        return make_response("", 302, {"Location": "/login"})
    return "Welcome admin"


@auth_app.route("/settings", methods=["GET", "POST"])
def settings_route():
    if request.method == "GET":
        return '<form method="POST"><input type="hidden" name="csrf_token" value="tok456"></form>'
    _level["value"] = request.form.get("level", "impossible")
    resp = make_response("settings updated")
    resp.set_cookie("level", _level["value"])
    return resp


@auth_app.route("/level")
def level_route():
    return _level["value"]


def make_rm(base_url: str) -> RequestManager:
    guard = ScopeGuard(allowed_hosts=["127.0.0.1"], denylist_patterns=[])
    timer = DeadlineTimer(30)
    budget = Budget(deadline_ts=timer.start + 30, report_reserve_s=1)
    return RequestManager(scope_guard=guard, budget=budget, start_rps=50, floor_rps=10)


@pytest.fixture
def auth_fixture_url():
    import socket
    import threading
    import time

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    t = threading.Thread(target=lambda: auth_app.run(host="127.0.0.1", port=port, use_reloader=False), daemon=True)
    t.start()
    time.sleep(0.4)
    yield f"http://127.0.0.1:{port}"


@pytest.mark.asyncio
async def test_login_succeeds_and_runs_post_login_action(auth_fixture_url):
    rm = make_rm(auth_fixture_url)
    try:
        cfg = {
            "enabled": True,
            "login_url": f"{auth_fixture_url}/login",
            "username": "admin",
            "password": "password",
            "extra_fields": {"Login": "Login"},
            "success_indicator": "Welcome",
            "post_login": [
                {"url": f"{auth_fixture_url}/settings", "fields": {"level": "low"}},
            ],
        }
        ok = await login(rm, cfg)
        assert ok is True

        resp = await rm.get(f"{auth_fixture_url}/level")
        assert resp.text == "low", "post_login action must run after a successful login"
        assert rm.cookies.get("level") == "low", "the post_login action's own Set-Cookie must be merged into rm.cookies"
    finally:
        await rm.aclose()


@pytest.mark.asyncio
async def test_empty_redirect_body_does_not_false_positive(auth_fixture_url):
    """Regression test: a login POST that redirects with an empty body
    must not be mistaken for success just because the (empty) body lacks
    the failure indicator -- login() must check a confirmatory page load,
    not the redirect response itself."""
    rm = make_rm(auth_fixture_url)
    try:
        cfg = {
            "enabled": True,
            "login_url": f"{auth_fixture_url}/login",
            "username": "admin",
            "password": "WRONG-password",
            # mirrors dvwa.yaml's real pattern: "Login" must be ABSENT for
            # success. The login form (shown again on failure) contains
            # the literal text "Login" (the submit button's value).
            "success_indicator": "!Login",
        }
        ok = await login(rm, cfg)
        assert ok is False, "a failed login must not be reported as success"
    finally:
        await rm.aclose()


@pytest.mark.asyncio
async def test_post_login_action_skipped_on_failed_login(auth_fixture_url):
    rm = make_rm(auth_fixture_url)
    try:
        cfg = {
            "enabled": True,
            "login_url": f"{auth_fixture_url}/login",
            "username": "admin",
            "password": "wrong",
            "success_indicator": "this-string-never-appears",
            "post_login": [
                {"url": f"{auth_fixture_url}/settings", "fields": {"level": "low"}},
            ],
        }
        ok = await login(rm, cfg)
        assert ok is False

        resp = await rm.get(f"{auth_fixture_url}/level")
        assert resp.text == "impossible", "post_login action must not run when login fails"
    finally:
        await rm.aclose()
