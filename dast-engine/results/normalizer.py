"""Normalizes and writes the final dast_results.json output."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from core.models import Finding
from results.dedupe import dedupe_findings, filter_exportable

logger = logging.getLogger("dast.normalizer")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(round(pct * (len(ordered) - 1)))))
    return ordered[idx]


def build_output(
    findings: list[Finding],
    *,
    target: str,
    started_at: float,
    finished_at: float,
    request_count: int,
    injection_point_count: int,
    latencies: list[float] | None = None,
) -> dict:
    deduped = dedupe_findings(findings)
    exportable = filter_exportable(deduped)
    exportable.sort(key=lambda f: (f.severity.value if hasattr(f.severity, "value") else f.severity, f.route_template))

    latencies = latencies or []
    return {
        "target": target,
        "scan_started_at": started_at,
        "scan_finished_at": finished_at,
        "elapsed_seconds": round(finished_at - started_at, 2),
        "request_count": request_count,
        "injection_point_count": injection_point_count,
        "p95_latency_seconds": round(_percentile(latencies, 0.95), 3),
        "finding_count": len(exportable),
        "findings": [f.to_dict() for f in exportable],
    }


def write_output(output: dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=False), encoding="utf-8")
    logger.info("Wrote %d findings to %s", output.get("finding_count", 0), path)
