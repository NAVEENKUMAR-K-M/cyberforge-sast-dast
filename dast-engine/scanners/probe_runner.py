"""Runs every CWE probe against every injection point, tier-1 always and
tier-2 only when hinted (see Probe.detect's docstring). This is the
"python" active_backend -- the default, custom-Python replacement for the
ZAP/Nuclei backends, giving exact per-point attribution without needing
an external scanner.
"""
from __future__ import annotations

import logging

from core.models import Baseline, Finding, InjectionPoint
from core.request_manager import RequestManager
from scanners.probes.base import Probe
from scanners.probes.cmdi import CmdiProbe
from scanners.probes.open_redirect import OpenRedirectProbe
from scanners.probes.path_traversal import PathTraversalProbe
from scanners.probes.sqli import SqliProbe
from scanners.probes.xss import XssProbe

logger = logging.getLogger("dast.probe_runner")


def default_probes() -> list[Probe]:
    return [SqliProbe(), XssProbe(), CmdiProbe(), PathTraversalProbe(), OpenRedirectProbe()]


def _is_hinted(point: InjectionPoint, cwe: str, hints: dict | None) -> bool:
    if not hints:
        return False
    key = (point.method.upper(), point.route_template, point.param)
    return cwe in hints.get(key, [])


async def run_probes(
    rm: RequestManager,
    points: list[InjectionPoint],
    baselines: dict[str, Baseline],
    hints: dict | None = None,
    probes: list[Probe] | None = None,
) -> list[Finding]:
    probes = probes or default_probes()
    findings: list[Finding] = []

    for i, point in enumerate(points):
        if rm.budget.expired():
            logger.info("Probe runner stopping: deadline reached (%d/%d points covered)", i, len(points))
            break
        baseline = baselines.get(point.key())
        for probe in probes:
            if rm.budget.expired():
                break
            hinted = _is_hinted(point, probe.cwe, hints)
            try:
                findings.extend(await probe.detect(rm, point, baseline, hinted=hinted))
            except Exception:
                logger.exception("Probe %s failed on %s %s param=%s", probe.name, point.method, point.url, point.param)

    return findings
