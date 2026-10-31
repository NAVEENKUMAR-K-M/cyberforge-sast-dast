"""Exports findings in the common format shared with the DAST engine (FR-3).

The format is defined in common/FORMAT.md and common/finding.schema.json. The
native findings.json / routes.json are unchanged; this adds findings.common.json.
"""
from __future__ import annotations

SCHEMA_VERSION = "1.0"
TOOL = "cyberforge-sast"


def to_common(result) -> dict:
    """result is a ScanResult; its findings and routes are already plain dicts."""
    routes_by_id = {route["id"]: route for route in result.routes}
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "sast",
        "tool": TOOL,
        "target": result.source_root,
        "stats": dict(result.stats),
        "findings": [_finding(f, routes_by_id) for f in result.findings],
    }


def _finding(f: dict, routes_by_id: dict) -> dict:
    # A finding's route refs carry no aliases; the full route does ("/shop/" for "/shop/index.php").
    routes = [
        {
            "path": ref["path"],
            "aliases": list(routes_by_id.get(ref["id"], {}).get("aliases", [])),
            "selector": ref["selector"],
            "methods": list(ref["methods"]),
        }
        for ref in f["routes"]
    ]
    return {
        "id": f"sast:{f['fingerprint']}",
        "source": "sast",
        "tool": TOOL,
        "cwe": f["cwe"],
        "cwe_family": f["cwe_family"],
        "title": f["title"],
        "severity": f["severity"],
        "confidence": f["confidence"],
        "status": f["status"],
        "scope": "endpoint" if routes else "code",
        "params": [dict(p) for p in f["source_params"]],
        "routes": routes,
        "code": {
            "file": f["file"],
            "line": f["line"],
            "snippet": f["snippet"],
            "function": f["function"],
            "sink": f["sink"],
            "trace": f["trace"],
            "conditions": f["conditions"],
            "stored_flow": f["stored_flow"],
            "suppression_reason": f["suppression_reason"],
            "engines": f["engines"],
        },
        "runtime": None,
    }
