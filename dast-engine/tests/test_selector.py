"""A selector ("action=view") picks which code runs on a shared path. Without
it a request never reaches that code, so a route map's selector has to survive
from routes.json to the request and on to the finding."""
import hashlib
import json

import pytest

from core.controller import run_scan
from core.models import Confidence, Evidence, Finding, ParamLocation, Severity
from discovery.injection_points import from_route_map
from discovery.route_map_loader import load_route_map
from scanners.probes.util import build_request


def write_map(tmp_path, *routes):
    path = tmp_path / "route_map.json"
    path.write_text(json.dumps({"routes": list(routes)}), encoding="utf-8")
    return path


def route(selector, params=None):
    return {"path": "/shop.php", "methods": ["GET"], "selector": selector, "params": params or [{"name": "id", "location": "query"}]}


def scan_config(tmp_path, url, route_map, denylist=()):
    return {
        "target": url, "allowlist": [url], "route_map_path": str(route_map),
        "deadline_seconds": 30, "report_reserve_seconds": 2, "start_rps": 50, "floor_rps": 10,
        "active_backend": "python", "seed_urls": [], "output_path": str(tmp_path / "out.json"),
        "denylist": list(denylist),
    }


def test_loader_keeps_the_selector(tmp_path):
    assert load_route_map(write_map(tmp_path, route("action=view")))[0]["selector"] == "action=view"


def test_query_point_sends_the_selector_with_the_payload(tmp_path):
    points = from_route_map(load_route_map(write_map(tmp_path, route("action=view"))), "http://localhost/")
    assert points[0].selector == "action=view" and points[0].route_template == "/shop.php"
    _, kwargs = build_request(points[0], "PAYLOAD")
    assert kwargs["params"] == {"action": "view", "id": "PAYLOAD"}


def test_body_point_keeps_the_selector_in_the_query_string(tmp_path):
    routes = load_route_map(write_map(tmp_path, route("action=save", [{"name": "note", "location": "body"}])))
    url, kwargs = build_request(from_route_map(routes, "http://localhost/")[0], "PAYLOAD")
    assert url == "http://localhost/shop.php?action=save"
    assert kwargs["data"] == {"note": "PAYLOAD"}


def test_selector_value_is_url_encoded(tmp_path):
    points = from_route_map(load_route_map(write_map(tmp_path, route("page=a b.php"))), "http://localhost/")
    assert points[0].url == "http://localhost/shop.php?page=a+b.php"


def test_two_selectors_on_one_path_are_different_points_and_findings(tmp_path):
    routes = load_route_map(write_map(tmp_path, route("action=view"), route("action=track")))
    a, b = from_route_map(routes, "http://localhost/")
    assert a.key() != b.key()

    def finding(selector):
        return Finding(cwe="CWE-89", title="SQL Injection", severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                       method="GET", url="http://localhost/shop.php", route_template="/shop.php", param="id",
                       param_location=ParamLocation.QUERY.value, evidence=Evidence(), selector=selector)

    assert finding("action=view").finding_id != finding("action=track").finding_id


def test_ids_without_a_selector_dont_change():
    found = Finding(cwe="CWE-89", title="SQL Injection", severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    method="GET", url="http://localhost/x", route_template="/x", param="id", param_location="query")
    assert found.finding_id == hashlib.sha1(b"CWE-89|GET|/x|id|query").hexdigest()


@pytest.mark.asyncio
async def test_a_bug_behind_a_selector_is_found_and_attributed(vuln_app_url, tmp_path):
    route_map = write_map(tmp_path, {
        "path": "/dispatch", "methods": ["GET"], "selector": "action=view", "params": [{"name": "id", "location": "query"}],
    }, {
        "path": "/dispatch", "methods": ["GET"], "selector": None, "params": [{"name": "id", "location": "query"}],
    })
    result = await run_scan(scan_config(tmp_path, vuln_app_url, route_map))
    sqli = [f for f in result["findings"] if f["cwe"] == "CWE-89"]
    assert [f["selector"] for f in sqli] == ["action=view"]


@pytest.mark.asyncio
async def test_two_bugs_behind_different_selectors_both_survive_dedupe(vuln_app_url, tmp_path):
    route_map = write_map(tmp_path, *[{
        "path": "/dispatch", "methods": ["GET"], "selector": s, "params": [{"name": "id", "location": "query"}],
    } for s in ("action=view", "action=track")])
    result = await run_scan(scan_config(tmp_path, vuln_app_url, route_map))
    assert {f["selector"] for f in result["findings"] if f["cwe"] == "CWE-89"} == {"action=view", "action=track"}


@pytest.mark.asyncio
async def test_a_denylisted_selector_is_never_requested(vuln_app_url, tmp_path):
    route_map = write_map(tmp_path, {
        "path": "/dispatch", "methods": ["GET"], "selector": "action=view", "params": [{"name": "id", "location": "query"}],
    })
    result = await run_scan(scan_config(tmp_path, vuln_app_url, route_map, denylist=["action=view"]))
    assert result["injection_point_count"] == 0
    assert not [f for f in result["findings"] if f["cwe"] == "CWE-89"]
