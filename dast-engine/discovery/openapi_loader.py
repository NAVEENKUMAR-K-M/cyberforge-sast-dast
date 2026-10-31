"""Parses an OpenAPI/Swagger spec fetched by the crawler into route entries
compatible with route_map_loader's normalized shape.
"""
from __future__ import annotations

import logging
from urllib.parse import urljoin

import httpx

logger = logging.getLogger("dast.openapi_loader")


async def load_from_url(client: httpx.AsyncClient, spec_url: str) -> list[dict]:
    try:
        resp = await client.get(spec_url, timeout=10.0)
        resp.raise_for_status()
        spec = resp.json()
    except Exception as exc:
        logger.warning("Failed to load OpenAPI spec %s: %s", spec_url, exc)
        return []
    return parse_spec(spec, base_url=spec_url)


def parse_spec(spec: dict, base_url: str) -> list[dict]:
    routes: list[dict] = []
    base_path = ""
    servers = spec.get("servers")
    if servers:
        base_path = servers[0].get("url", "")

    for path, methods in (spec.get("paths") or {}).items():
        full_path = urljoin(base_path + "/", path.lstrip("/")) if base_path else path
        for method, op in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            params = []
            for p in op.get("parameters", []):
                params.append(
                    {
                        "name": p.get("name"),
                        "location": {"query": "query", "path": "path", "header": "header", "cookie": "cookie"}.get(
                            p.get("in"), "query"
                        ),
                        "type": (p.get("schema") or {}).get("type"),
                    }
                )
            body = op.get("requestBody", {})
            content = body.get("content", {})
            if "application/json" in content:
                schema = content["application/json"].get("schema", {})
                for prop_name, prop in (schema.get("properties") or {}).items():
                    params.append({"name": prop_name, "location": "json", "type": prop.get("type")})
            routes.append({"method": method.upper(), "path": path, "params": params})
    return routes
