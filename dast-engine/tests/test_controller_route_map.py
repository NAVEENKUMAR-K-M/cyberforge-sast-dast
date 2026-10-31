"""FR-4 end to end: run_scan() with a route_map.json, including a
denylisted route -- the shape SAST's routes.json actually produces (it
legitimately lists every route the code has, logout.php included)."""
import json

import pytest

from core.controller import run_scan


def write_route_map(tmp_path, *routes) -> str:
    path = tmp_path / "route_map.json"
    path.write_text(json.dumps({"routes": list(routes)}), encoding="utf-8")
    return str(path)


@pytest.mark.asyncio
async def test_a_route_map_point_is_resolved_and_actually_scanned(fixture_app_url, tmp_path):
    route_map = write_route_map(tmp_path, {
        "path": "/insecure", "methods": ["GET"], "params": [],
    })
    config = {
        "target": fixture_app_url,
        "allowlist": [fixture_app_url],
        "route_map_path": route_map,
        "deadline_seconds": 20, "report_reserve_seconds": 2,
        "start_rps": 50, "floor_rps": 10,
        "active_backend": "none",
        "seed_urls": [],
        "output_path": str(tmp_path / "out.json"),
        "denylist": ["logout", "setup", "reset", "delete"],
    }
    result = await run_scan(config)
    assert result["injection_point_count"] >= 0  # didn't crash
    cwes = {f["cwe"] for f in result["findings"]}
    assert "CWE-1021" in cwes  # the route-map point's own passive-adjacent header check still ran


@pytest.mark.asyncio
async def test_a_denylisted_route_map_point_is_dropped_not_crashed(fixture_app_url, tmp_path):
    """Regression test: a route-map point for a denylisted path (SAST's
    routes.json legitimately lists logout.php as a real route) used to
    crash the whole scan on its very first baseline request with
    ScopeViolation, since RequestManager.send() raises rather than skips
    an out-of-scope request."""
    route_map = write_route_map(
        tmp_path,
        {"path": "/logout.php", "methods": ["GET"], "params": [{"name": "redirect", "location": "query"}]},
        {"path": "/insecure", "methods": ["GET"], "params": []},
    )
    config = {
        "target": fixture_app_url,
        "allowlist": [fixture_app_url],
        "route_map_path": route_map,
        "deadline_seconds": 20, "report_reserve_seconds": 2,
        "start_rps": 50, "floor_rps": 10,
        "active_backend": "none",
        "seed_urls": [],
        "output_path": str(tmp_path / "out.json"),
        "denylist": ["logout", "setup", "reset", "delete"],
    }
    result = await run_scan(config)  # must not raise ScopeViolation
    assert all("logout" not in f["url"] for f in result["findings"])
