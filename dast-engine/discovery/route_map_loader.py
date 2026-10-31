"""Loads an optional route_map.json produced by the SAST side (FR-4/FR-5).

Written for the SAST engine's actual routes.json shape (sast-engine/docs/
finding-format.md), which this loader now reads directly:
{
  "routes": [
    {"methods": ["GET", "POST"], "path": "/api/orders.php", "params": [
        {"name": "id", "location": "query"}
     ], "required_params": [{"name": "Submit", "location": "body", "value": "Submit"}]}
  ]
}
A looser shape (singular "method") is still accepted for anything else that
produces a route map by hand.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("dast.route_map_loader")

# SAST locations with a direct DAST ParamLocation equivalent (same spelling).
_DIRECT_LOCATIONS = {"query", "body", "json", "path", "header", "cookie"}
# Not a single fuzzable request param in our sense: a file upload has no text
# value to inject, and a session key isn't attacker-supplied in the request
# at all. Skipped loudly (logged), never silently mistested as "query".
_SKIP_LOCATIONS = {"file", "session"}


def _methods_of(r: dict) -> list[str]:
    """One row per method, so a POST-only route is never silently tested as
    GET: SAST's routes.json lists `methods` (a list); a single `method`
    string is accepted too for looser hand-written route maps."""
    methods = r.get("methods")
    if methods:
        return sorted({str(m).upper() for m in methods})
    return [(r.get("method") or "GET").upper()]


def _normalize_param(p: dict | str, route_path: str) -> list[dict]:
    if isinstance(p, str):
        return [{"name": p, "location": "query", "type": None}]
    name, loc, ptype = p.get("name"), p.get("location", "query"), p.get("type")
    if not name:
        return []
    if loc in _DIRECT_LOCATIONS:
        return [{"name": name, "location": loc, "type": ptype}]
    if loc == "any":
        # $_REQUEST: SAST can't tell if an attacker would use the query
        # string or the body, so test both rather than guess one and
        # silently miss the other.
        return [{"name": name, "location": "query", "type": ptype}, {"name": name, "location": "body", "type": ptype}]
    if loc in _SKIP_LOCATIONS:
        logger.info("route_map: skipping %s param %r on %s (not a fuzzable request value)", loc, name, route_path)
        return []
    # "unknown" or anything unrecognised: best effort, still worth trying.
    return [{"name": name, "location": "query", "type": ptype}]


def load_route_map(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        logger.warning("route_map.json not found at %s", path)
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.error("route_map.json is not valid JSON: %s", exc)
        return []

    routes = data.get("routes", data if isinstance(data, list) else [])
    normalized = []
    for r in routes:
        route_path = r.get("path") or r.get("route") or r.get("route_template")
        if not route_path:
            continue
        params = [n for p in r.get("params", []) for n in _normalize_param(p, route_path)]
        # Required params (e.g. DVWA's "Submit" button): without these the
        # request never reaches the vulnerable code at all. A `value` means
        # an exact match is checked; otherwise any truthy value will do.
        # Carried as a flat dict so every point on this route sends them
        # alongside whichever single param is actually being fuzzed -- the
        # same fix already applied to crawled GET forms (build_request()),
        # now applied to route-map-sourced points too.
        required = {
            p.get("name"): p.get("value") or "1"
            for p in r.get("required_params", [])
            if isinstance(p, dict) and p.get("name")
        }
        for method in _methods_of(r):
            normalized.append({"method": method, "path": route_path, "params": params, "required_params": required})
    return normalized


def load_sast_hints(path: str | Path | None) -> dict:
    """Optional per-route hints from SAST (e.g. a sink seen for a route+param).

    Shape: {"hints": [{"route": "/x/{id}", "method": "GET", "param": "id", "cwe": "CWE-89"}]}
    Used only to prioritise tier-2 probing — never to skip a test entirely.
    """
    if not path:
        return {}
    path = Path(path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.error("sast hints file is not valid JSON")
        return {}
    index: dict[tuple, list[str]] = {}
    for h in data.get("hints", []):
        key = (h.get("method", "GET").upper(), h.get("route"), h.get("param"))
        index.setdefault(key, []).append(h.get("cwe"))
    return index
