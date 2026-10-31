"""Loads an optional route_map.json produced by the SAST side (FR-5).

Expected shape (kept loose — we accept several reasonable variants):
{
  "routes": [
    {"method": "GET", "path": "/api/orders/{id}", "params": [
        {"name": "id", "location": "path", "type": "integer"}
     ]}
  ]
}
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("dast.route_map_loader")


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
        method = (r.get("method") or "GET").upper()
        route_path = r.get("path") or r.get("route") or r.get("route_template")
        if not route_path:
            continue
        params = []
        for p in r.get("params", []):
            if isinstance(p, str):
                params.append({"name": p, "location": "query", "type": None})
            else:
                params.append(
                    {
                        "name": p.get("name"),
                        "location": p.get("location", "query"),
                        "type": p.get("type"),
                    }
                )
        normalized.append({"method": method, "path": route_path, "params": params})
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
