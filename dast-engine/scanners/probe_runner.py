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
from discovery.baseline import get_baseline
from discovery.route_map_loader import hint_key
from scanners.probes.base import Probe
from scanners.probes.cmdi import CmdiProbe
from scanners.probes.open_redirect import OpenRedirectProbe
from scanners.probes.path_traversal import PathTraversalProbe
from scanners.probes.sqli import SqliProbe
from scanners.probes.xss import XssProbe

logger = logging.getLogger("dast.probe_runner")


def default_probes() -> list[Probe]:
    return [SqliProbe(), XssProbe(), CmdiProbe(), PathTraversalProbe(), OpenRedirectProbe()]


def _hinted_cwes(point: InjectionPoint, hints: dict | None) -> list:
    if not hints:
        return []
    return hints.get(hint_key(point.method, point.route_template, point.param, point.selector), [])


def _is_hinted(point: InjectionPoint, cwe: str, hints: dict | None) -> bool:
    return cwe in _hinted_cwes(point, hints)


async def run_probes(
    rm: RequestManager,
    points: list[InjectionPoint],
    baselines: dict[str, Baseline] | None = None,
    hints: dict | None = None,
    probes: list[Probe] | None = None,
    coverage: dict | None = None,
    session=None,
) -> list[Finding]:
    probes = probes or default_probes()
    baselines = baselines if baselines is not None else {}
    findings: list[Finding] = []
    coverage = coverage if coverage is not None else {}
    coverage.update({"points_tested": 0, "points_hinted": 0, "deadline_reached": False})
    # Where the code points to a likely bug goes first, so a large app that runs out
    # of time loses the least promising points. The sort is stable, so order is otherwise kept.
    points = sorted(points, key=lambda p: not _hinted_cwes(p, hints))
    coverage["points_hinted"] = sum(1 for p in points if _hinted_cwes(p, hints))

    for i, point in enumerate(points):
        if rm.budget.expired():
            logger.info("Probe runner stopping: deadline reached (%d/%d points covered)", i, len(points))
            coverage["deadline_reached"] = True
            break
        if session is not None and i % session.check_every == 0:
            await session.ensure()
        # A point's baseline is fetched the first time it's probed, not all up front: on a large
        # route map, baselining every point would spend the whole budget before any probing.
        baseline = baselines.get(point.key())
        if baseline is None and point.key() not in baselines:
            baseline = await get_baseline(rm, point.method, point.baseline_url)
            baselines[point.key()] = baseline
        for probe in probes:
            if rm.budget.expired():
                break
            hinted = _is_hinted(point, probe.cwe, hints)
            try:
                found = await probe.detect(rm, point, baseline, hinted=hinted)
                for finding in found:
                    finding.selector = point.selector
                findings.extend(found)
            except Exception:
                logger.exception("Probe %s failed on %s %s param=%s", probe.name, point.method, point.url, point.param)
        coverage["points_tested"] += 1

    return findings
