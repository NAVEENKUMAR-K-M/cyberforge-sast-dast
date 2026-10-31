"""Exports DAST output in the common finding format shared with the SAST
engine (FR-3). The format is defined in common/FORMAT.md and
common/finding.schema.json; the native dast_results.json is unchanged.
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger("dast.common_export")

SCHEMA_VERSION = "1.0"
ENGINE_TOOL = "cyberforge-dast"
FAMILIES_PATH = Path(__file__).resolve().parents[2] / "common" / "cwe_families.json"

# Native tiers are confirmed/firm/tentative; the common format uses the same
# high/medium/low vocabulary as the SAST side. The native tier is kept in
# runtime.verification, so nothing is lost.
CONFIDENCE = {"confirmed": "high", "firm": "medium", "tentative": "low"}
# Native `tool` values -> common `tool`. Anything else (owasp-zap, nuclei) passes through.
TOOL_NAMES = {"dast-engine": ENGINE_TOOL}


@lru_cache(maxsize=1)
def _families() -> dict[int, int]:
    try:
        raw = json.loads(FAMILIES_PATH.read_text(encoding="utf-8"))["families"]
    except (OSError, ValueError, KeyError):
        # e.g. the Docker image only contains dast-engine/. Without the table a
        # CWE is its own family, so say so rather than degrade silently.
        logger.warning("CWE family table not found at %s; cwe_family will equal cwe", FAMILIES_PATH)
        return {}
    return {int(k): int(v) for k, v in raw.items()}


def cwe_family(cwe: str) -> str:
    number = int(re.fullmatch(r"CWE-(\d+)", cwe).group(1))
    return f"CWE-{_families().get(number, number)}"


def finding_to_common(f: dict) -> dict:
    """Converts one native finding dict (Finding.to_dict()) to the common shape."""
    scope = f.get("scope", "endpoint")
    param = f.get("param")
    params = [{"name": param, "location": f.get("param_location") or "unknown"}] if param else []
    # App-scope findings (missing header, cookie flag, ...) belong to no one route.
    routes = [] if scope == "app" else [
        {"path": f["route_template"], "aliases": [], "selector": f.get("selector"), "methods": [f["method"].upper()]}
    ]
    return {
        "id": f"dast:{f['finding_id']}",
        "source": "dast",
        "tool": TOOL_NAMES.get(f.get("tool", ""), f.get("tool") or ENGINE_TOOL),
        "cwe": f["cwe"],
        "cwe_family": cwe_family(f["cwe"]),
        "title": f["title"],
        "severity": f["severity"],
        "confidence": CONFIDENCE[f["confidence"]],
        "status": "open",
        "scope": scope,
        "params": params,
        "routes": routes,
        "code": None,
        "runtime": {
            "method": f["method"],
            "url": f["url"],
            "payload": f.get("payload", ""),
            "technique": f.get("technique", ""),
            "verification": f["confidence"],
            "evidence": dict(f.get("evidence") or {}),
        },
    }


def to_common(output: dict) -> dict:
    """Converts the dict from results.normalizer.build_output()."""
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "dast",
        "tool": ENGINE_TOOL,
        "target": output.get("target", ""),
        "stats": {
            key: output[key]
            for key in ("elapsed_seconds", "request_count", "injection_point_count", "p95_latency_seconds", "finding_count", "coverage")
            if key in output
        },
        "findings": [finding_to_common(f) for f in output.get("findings", [])],
    }


def common_path_for(native_path: str | Path) -> Path:
    """output/x.json -> output/x.common.json"""
    return Path(native_path).with_suffix(".common.json")


def write_common(output: dict, native_path: str | Path) -> Path:
    path = common_path_for(native_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_common(output), indent=2), encoding="utf-8")
    return path
