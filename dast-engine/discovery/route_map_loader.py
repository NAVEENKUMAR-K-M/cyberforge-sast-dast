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

from discovery.templates import normalize, path_index

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


def _normalize_param(p: dict | str, method: str, methods: list[str], route_path: str) -> list[dict]:
    """Where to test one parameter under one method. A body only goes with a
    method that has one, and a route with several methods tests each place once,
    so a scan doesn't spend its budget on the same input over and over."""
    if isinstance(p, str):
        p = {"name": p, "location": "query"}
    name, loc, ptype = p.get("name"), p.get("location", "query"), p.get("type")
    if not name:
        return []
    if loc in _SKIP_LOCATIONS:
        logger.info("route_map: skipping %s param %r on %s (not a fuzzable request value)", loc, name, route_path)
        return []
    if loc == "any":
        # $_REQUEST reads either place, so each method tests its natural one.
        return [{"name": name, "location": "query" if method == "GET" else "body", "type": ptype}]
    if loc not in _DIRECT_LOCATIONS:
        loc = "query"  # "unknown" or anything unrecognised: best effort, still worth trying.
    if len(methods) > 1:
        if loc == "query" and method != "GET":
            return []
        if loc in ("body", "json") and method == "GET":
            return []
        if loc in ("path", "header", "cookie") and method != methods[0]:
            return []
    return [{"name": name, "location": loc, "type": ptype}]


def _form_fields(route: dict, method: str, route_path: str) -> list[dict]:
    """Fields of the page's own forms that submit to this route, with their real
    defaults. Browsers send every field of a form, so a request should too. Made-up
    values won't do: some pages reject a request when two exclusive fields are both set."""
    fields = []
    for form in route.get("form_fields") or []:
        if not isinstance(form, dict) or form.get("method", "GET").upper() != method:
            continue
        action = (form.get("action") or "").split("?")[0]
        if action not in ("", "#") and not route_path.endswith(action.lstrip("./")):
            continue
        for field_info in form.get("fields", []):
            if field_info.get("name") and field_info.get("type") != "file":
                location = "body" if method != "GET" else "query"
                fields.append({"name": field_info["name"], "value": field_info.get("value", ""), "location": location})
    return fields


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
        methods = _methods_of(r)
        for method in methods:
            params = [n for p in r.get("params", []) for n in _normalize_param(p, method, methods, route_path)]
            # Required params (e.g. a "Submit" button): without these the request
            # never reaches the code at all. A `value` means the code checks for
            # that exact value; otherwise any truthy value will do.
            required = [
                {"name": p["name"], "value": p.get("value") or "1", "location": p.get("location")}
                for p in r.get("required_params", [])
                if isinstance(p, dict) and p.get("name")
            ]
            normalized.append({
                "method": method, "path": route_path, "params": params,
                # Required values go last, so they win over a form's default.
                "fields": _form_fields(r, method, route_path) + required,
                "selector": r.get("selector"),
            })
    return normalized


def hint_key(method: str, route: str, param: str | None, selector: str | None) -> tuple:
    """A trailing slash makes no difference (`/x/` from a crawl is `/x/` from SAST), and neither does what a
    placeholder is called (`/orders/{id}` from a crawl is `/orders/{order_id}` from SAST)."""
    return (method.upper(), normalize(route), param, selector)


def hint_keys(method: str, route: str, param: str | None, location: str | None, selector: str | None) -> list[tuple]:
    """Every way a hint for this point may have been written. A path parameter is also known by its position,
    since two tools rarely call the same placeholder the same thing."""
    keys = [hint_key(method, route, param, selector)]
    if location == "path" and param:
        index = path_index(route, param)
        if index is not None:
            keys.append(hint_key(method, route, f"#path{index}", selector))
    return keys


def load_sast_hints(path: str | Path | None) -> dict:
    """Optional per-route hints from SAST (e.g. a sink seen for a route+param).

    Shape: {"hints": [{"route": "/x/{id}", "method": "GET", "selector": null, "param": "id", "cwe": "CWE-89"}]}
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
        route = h.get("route") or ""
        # A hint on a name that is one of the route's placeholders is a path parameter; keep it by position too.
        location = "path" if h.get("param") and "{" + str(h.get("param")) in route else None
        for key in hint_keys(h.get("method", "GET"), route, h.get("param"), location, h.get("selector")):
            index.setdefault(key, []).append(h.get("cwe"))
    return index
