"""Parses an OpenAPI/Swagger spec fetched by the crawler into route entries
compatible with route_map_loader's normalized shape.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

logger = logging.getLogger("dast.openapi_loader")


async def load_from_url(rm, spec_url: str) -> list[dict]:
    resp = await rm.get(spec_url)
    if resp is None:
        return []
    try:
        return parse_spec(resp.json())
    except ValueError as exc:
        logger.warning("Failed to load OpenAPI spec %s: %s", spec_url, exc)
        return []


_IN_TO_LOCATION = {"query": "query", "path": "path", "header": "header", "cookie": "cookie", "formData": "body"}


def parse_spec(spec: dict) -> list[dict]:
    """Reads OpenAPI 3 and Swagger 2 into route entries, one per path and method."""
    routes: list[dict] = []
    servers = spec.get("servers") or []
    # The path prefix only: a spec's server host may not be the host being tested.
    base_path = (urlparse(servers[0].get("url", "")).path if servers else spec.get("basePath", "") or "").rstrip("/")

    for path, methods in (spec.get("paths") or {}).items():
        shared = methods.get("parameters", []) if isinstance(methods, dict) else []
        for method, op in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE") or not isinstance(op, dict):
                continue
            params = []
            for p in [*shared, *op.get("parameters", [])]:
                if p.get("in") == "body":
                    params.extend(_schema_params(p.get("schema", {}), "json"))
                elif p.get("name"):
                    params.append({
                        "name": p["name"],
                        "location": _IN_TO_LOCATION.get(p.get("in"), "query"),
                        "type": (p.get("schema") or {}).get("type") or p.get("type"),
                    })
            content = op.get("requestBody", {}).get("content", {})
            if "application/json" in content:
                params.extend(_schema_params(content["application/json"].get("schema", {}), "json"))
            if "application/x-www-form-urlencoded" in content:
                params.extend(_schema_params(content["application/x-www-form-urlencoded"].get("schema", {}), "body"))
            routes.append({"method": method.upper(), "path": base_path + path, "params": params})
    return routes


def _schema_params(schema: dict, location: str) -> list[dict]:
    return [{"name": name, "location": location, "type": prop.get("type")}
            for name, prop in (schema.get("properties") or {}).items() if isinstance(prop, dict)]
