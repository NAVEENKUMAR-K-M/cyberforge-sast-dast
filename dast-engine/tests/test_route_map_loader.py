"""FR-4: route_map.json as the SAST engine actually writes it (sast-engine's
routes.json: `methods` list, locations beyond query/body/path/header/cookie,
`required_params`) -- not just the loose format in the module docstring.
"""
import json

from core.models import ParamLocation
from discovery.injection_points import from_route_map
from discovery.route_map_loader import load_route_map
from scanners.probes.util import build_request


def write(tmp_path, routes: list[dict]):
    path = tmp_path / "route_map.json"
    path.write_text(json.dumps({"routes": routes}), encoding="utf-8")
    return path


# --- methods: list, not singular ------------------------------------------

def test_methods_list_is_read_not_just_singular_method(tmp_path):
    """Regression test: the loader used to look for a singular `method` key;
    SAST's routes.json has `methods` (a list), so every route silently
    defaulted to GET."""
    path = write(tmp_path, [{"path": "/login.php", "methods": ["POST"], "params": []}])
    routes = load_route_map(path)
    assert len(routes) == 1
    assert routes[0]["method"] == "POST"


def test_a_route_with_several_methods_is_tested_under_each_one(tmp_path):
    path = write(tmp_path, [{"path": "/api/orders.php", "methods": ["GET", "POST"], "params": [{"name": "id", "location": "query"}]}])
    routes = load_route_map(path)
    assert {r["method"] for r in routes} == {"GET", "POST"}
    assert all(r["path"] == "/api/orders.php" for r in routes)


def test_still_accepts_a_loose_singular_method_for_hand_written_maps(tmp_path):
    path = write(tmp_path, [{"path": "/x", "method": "put", "params": []}])
    assert load_route_map(path)[0]["method"] == "PUT"


def test_method_defaults_to_get_when_neither_key_is_present(tmp_path):
    path = write(tmp_path, [{"path": "/x", "params": []}])
    assert load_route_map(path)[0]["method"] == "GET"


# --- param locations beyond DAST's core set --------------------------------

def test_any_location_is_tested_in_each_method_natural_place(tmp_path):
    """SAST's `any` means $_REQUEST: either place works, so both are tried, but a GET
    has no body and repeating the query on a POST only spends budget on the same input."""
    path = write(tmp_path, [{"path": "/x", "methods": ["GET", "POST"], "params": [{"name": "q", "location": "any"}]}])
    routes = {r["method"]: r["params"] for r in load_route_map(path)}
    assert [p["location"] for p in routes["GET"]] == ["query"]
    assert [p["location"] for p in routes["POST"]] == ["body"]


def test_a_route_with_several_methods_tests_each_place_once(tmp_path):
    path = write(tmp_path, [{"path": "/x", "methods": ["GET", "POST"], "params": [
        {"name": "a", "location": "query"}, {"name": "b", "location": "body"}, {"name": "c", "location": "cookie"},
    ]}])
    routes = {r["method"]: {p["name"] for p in r["params"]} for r in load_route_map(path)}
    assert routes == {"GET": {"a", "c"}, "POST": {"b"}}


def test_a_required_field_stays_in_its_own_place(tmp_path):
    """Regression test: locations used to be dropped, so a POST reading `save` from its
    body and `id` from its URL got both in the URL, and its check never passed."""
    path = write(tmp_path, [{
        "path": "/x", "methods": ["POST"],
        "params": [{"name": "id", "location": "query"}, {"name": "note", "location": "body"}],
        "required_params": [{"name": "save", "location": "body", "value": "yes"}, {"name": "mode", "location": "query", "value": "a"}],
    }])
    points = {p.param: p for p in from_route_map(load_route_map(path), "http://h/")}
    url, kwargs = build_request(points["id"], "PAYLOAD")
    assert kwargs["params"] == {"id": "PAYLOAD", "mode": "a"} and kwargs["data"] == {"save": "yes"}
    url, kwargs = build_request(points["note"], "PAYLOAD")
    assert kwargs["data"] == {"note": "PAYLOAD", "save": "yes"} and kwargs["params"] == {"mode": "a"}


def test_form_fields_are_sent_with_their_real_defaults(tmp_path):
    """A browser sends every field of a form, and a submit button's value may be what the
    code checks for. A made-up value isn't safe: pages can reject two exclusive fields both set."""
    path = write(tmp_path, [{
        "path": "/search.php", "methods": ["POST"], "params": [{"name": "item", "location": "body"}, {"name": "term", "location": "body"}],
        "form_fields": [{"method": "POST", "action": "", "fields": [
            {"name": "item", "type": "text"}, {"name": "term", "type": "text"}, {"name": "go", "type": "submit", "value": "Search"},
            {"name": "upload", "type": "file"},
        ]}],
    }])
    point = next(p for p in from_route_map(load_route_map(path)) if p.param == "item")
    assert point.body_template == {"term": "", "go": "Search"}


def test_a_form_for_another_page_or_method_is_ignored(tmp_path):
    path = write(tmp_path, [{
        "path": "/a.php", "methods": ["POST"], "params": [{"name": "x", "location": "body"}],
        "form_fields": [
            {"method": "POST", "action": "/other.php", "fields": [{"name": "other", "type": "text"}]},
            {"method": "GET", "action": "", "fields": [{"name": "search", "type": "text"}]},
        ],
    }])
    assert from_route_map(load_route_map(path))[0].body_template is None


def test_path_values_become_testable_placeholders(tmp_path):
    path = write(tmp_path, [{"path": "/a/{x}/b/{y?}", "methods": ["GET"], "params": [
        {"name": "x", "location": "path"}, {"name": "q", "location": "query"},
    ]}])
    points = {p.param: p for p in from_route_map(load_route_map(path), "http://h/")}
    assert points["x"].url == "http://h/a/{x}/b/1"
    assert points["x"].baseline_url == "http://h/a/1/b/1"
    assert build_request(points["x"], "PAYLOAD")[0] == "http://h/a/PAYLOAD/b/1"
    assert points["q"].url == "http://h/a/1/b/1"


def test_file_and_session_locations_are_skipped_not_mistested_as_query(tmp_path):
    """Regression test: these used to fall into the generic except-clause
    and silently get fuzzed as a query param, which is actively wrong -- a
    file upload has no text value, and a session key isn't attacker-
    supplied in the request at all."""
    path = write(tmp_path, [{
        "path": "/upload.php", "methods": ["POST"],
        "params": [
            {"name": "avatar", "location": "file"},
            {"name": "user_id", "location": "session"},
            {"name": "caption", "location": "body"},
        ],
    }])
    routes = load_route_map(path)
    names = {p["name"] for p in routes[0]["params"]}
    assert names == {"caption"}


def test_direct_locations_pass_through_unchanged(tmp_path):
    path = write(tmp_path, [{
        "path": "/x", "methods": ["GET"],
        "params": [{"name": "a", "location": "json"}, {"name": "b", "location": "header"}, {"name": "c", "location": "cookie"}],
    }])
    locations = {p["name"]: p["location"] for p in load_route_map(path)[0]["params"]}
    assert locations == {"a": "json", "b": "header", "c": "cookie"}


def test_string_only_params_still_work(tmp_path):
    path = write(tmp_path, [{"path": "/x", "methods": ["GET"], "params": ["q"]}])
    assert load_route_map(path)[0]["params"] == [{"name": "q", "location": "query", "type": None}]


# --- required_params: the DVWA "Submit button" class of bug, for route-map points too ---

def test_required_params_become_a_shared_body_template(tmp_path):
    """Regression test: route-map-sourced InjectionPoints never carried
    sibling required fields at all, so a route gated behind
    isset($_POST['username']) (sast-engine's real /login.php route) would
    never actually reach the vulnerable code when only `password` was
    being fuzzed -- same bug class already fixed for crawled GET forms."""
    path = write(tmp_path, [{
        "path": "/login.php", "methods": ["POST"],
        "params": [{"name": "username", "location": "body"}, {"name": "password", "location": "body"}],
        "required_params": [{"name": "username", "location": "body"}],
    }])
    routes = load_route_map(path)
    points = from_route_map(routes)

    password_point = next(p for p in points if p.param == "password")
    assert password_point.body_template == {"username": "1"}

    # the required param's own point must not require itself
    username_point = next(p for p in points if p.param == "username")
    assert username_point.body_template is None


def test_required_param_with_an_exact_value_sends_that_value(tmp_path):
    """docs/finding-format.md: "A value means the code compares against
    that exact value" -- e.g. a hidden Submit=Submit field."""
    path = write(tmp_path, [{
        "path": "/vulnerabilities/sqli/", "methods": ["GET"],
        "params": [{"name": "id", "location": "query"}],
        "required_params": [{"name": "Submit", "location": "query", "value": "Submit"}],
    }])
    points = from_route_map(load_route_map(path))
    assert points[0].body_template == {"Submit": "Submit"}


def test_no_required_params_means_no_body_template(tmp_path):
    path = write(tmp_path, [{"path": "/x", "methods": ["GET"], "params": [{"name": "q", "location": "query"}]}])
    assert from_route_map(load_route_map(path))[0].body_template is None


# --- url resolution: a bare path is not a request-able URL ----------------

def test_without_base_url_the_bare_path_passes_through(tmp_path):
    path = write(tmp_path, [{"path": "/account/orders.php", "methods": ["GET"], "params": [{"name": "sort", "location": "query"}]}])
    point = from_route_map(load_route_map(path))[0]
    assert point.url == "/account/orders.php"


def test_with_base_url_the_path_becomes_a_concrete_request_url(tmp_path):
    """Regression test: a route-map point's bare path (route_template)
    used to be sent as-is for `url` too. Scanning with --route-map crashed
    on the very first baseline request with
    "Refusing out-of-scope request: /account/orders.php" -- the scope
    guard has no host to check a bare path against. route_template must
    still be the bare path; only `url` gets resolved."""
    path = write(tmp_path, [{"path": "/account/orders.php", "methods": ["GET"], "params": [{"name": "sort", "location": "query"}]}])
    point = from_route_map(load_route_map(path), base_url="http://127.0.0.1:8088")[0]
    assert point.url == "http://127.0.0.1:8088/account/orders.php"
    assert point.route_template == "/account/orders.php"


def test_build_injection_points_threads_base_url_through(tmp_path):
    path = write(tmp_path, [{"path": "/x", "methods": ["GET"], "params": [{"name": "q", "location": "query"}]}])
    from discovery.injection_points import build_injection_points

    points = build_injection_points(load_route_map(path), crawl_result=None, base_url="http://localhost:8080")
    assert points[0].url == "http://localhost:8080/x"


# --- end to end against the real sast-engine output, if it's been built ---

def test_against_real_sast_engine_routes_json_if_present():
    """Not a hard dependency on sast-engine being checked out and scanned,
    but when it has been (sast-engine/out/shop/routes.json from a real run)
    this exercises the loader against actual SAST output, not a hand-built
    fixture."""
    from pathlib import Path

    real = Path(__file__).resolve().parents[2] / "sast-engine" / "out" / "shop" / "routes.json"
    if not real.exists():
        import pytest

        pytest.skip("sast-engine/out/shop/routes.json not present; run sast-engine's CLI first")

    routes = load_route_map(real)
    login_routes = [r for r in routes if r["path"] == "/login.php"]
    assert login_routes and all(r["method"] == "POST" for r in login_routes)

    points = from_route_map(routes, base_url="http://127.0.0.1:8088")
    orders_id = next(p for p in points if p.route_template == "/api/orders.php" and p.param == "id")
    assert orders_id.param_location == ParamLocation.QUERY
    assert orders_id.url == "http://127.0.0.1:8088/api/orders.php"
