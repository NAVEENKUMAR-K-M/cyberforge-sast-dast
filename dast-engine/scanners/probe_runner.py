"""Runs every CWE probe against every injection point, tier-1 always and
tier-2 only when hinted (see Probe.detect's docstring). This is the
"python" active_backend -- the default, custom-Python replacement for the
ZAP/Nuclei backends, giving exact per-point attribution without needing
an external scanner.
"""
from __future__ import annotations

import asyncio
import logging
import time

from core.models import Baseline, Finding, InjectionPoint
from core.request_manager import RequestManager
from discovery.baseline import get_baseline
from discovery.route_map_loader import hint_keys
from scanners.probes.base import Probe
from scanners.probes.util import build_request
from scanners.probes.cmdi import CmdiProbe
from scanners.probes.open_redirect import OpenRedirectProbe
from scanners.probes.path_traversal import PathTraversalProbe
from scanners.probes.sqli import SqliProbe
from scanners.probes.xss import XssProbe

logger = logging.getLogger("dast.probe_runner")

# Seconds one point may take: at least this, or this many times its normal response time if that is more.
POINT_BUDGET_MIN_S = 20.0
POINT_BUDGET_SLOWDOWN = 6.0
# An endpoint whose normal answer takes longer than this is probed alone.
HEAVY_ENDPOINT_S = 1.0
# Rough cost in requests of each probe on a point where nothing is found, to run the cheap ones first.
# Parameter types a framework enforces, from an OpenAPI schema or SAST's route map.
TYPED_KINDS = {"integer", "number", "boolean", "uuid", "enum", "validated"}
PROBE_COST = {"open_redirect": 1, "path_traversal": 2, "cmdi": 3, "xss": 4, "sqli": 5}


def default_probes() -> list[Probe]:
    return [SqliProbe(), XssProbe(), CmdiProbe(), PathTraversalProbe(), OpenRedirectProbe()]


def _hinted_cwes(point: InjectionPoint, hints: dict | None) -> list:
    if not hints:
        return []
    location = point.param_location.value if hasattr(point.param_location, "value") else str(point.param_location)
    found = []
    for key in hint_keys(point.method, point.route_template, point.param, location, point.selector):
        found.extend(hints.get(key, []))
    return found


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
    concurrency: int = 1,
    skip_methods: set | frozenset = frozenset(),
) -> list[Finding]:
    """Runs every probe on every point, in the order that loses least if time runs out.

    The work is a list of (point, probe) pairs. Pairs the code points to come first. The rest follow cheapest
    probe first across all points, so the deadline costs the dearest, least likely tests and not whole
    points. `concurrency` pairs run at once and the rate limiter is shared. Slow endpoints are kept out of that
    pool and probed one at a time afterwards, since a few of them at once can hold every worker of a small
    server. Findings come back in point order whatever order the pairs finish in."""
    probes = probes or default_probes()
    baselines = baselines if baselines is not None else {}
    coverage = coverage if coverage is not None else {}
    coverage.update({"points_tested": 0, "points_hinted": 0, "deadline_reached": False})
    coverage["points_hinted"] = sum(1 for p in points if _hinted_cwes(p, hints))

    order = sorted(
        ((pi, qi) for pi in range(len(points)) for qi in range(len(probes))),
        key=lambda pair: (not _is_hinted(points[pair[0]], probes[pair[1]].cwe, hints),
                          PROBE_COST.get(probes[pair[1]].name, 3), pair[0], pair[1]),
    )
    remaining = [len(probes)] * len(points)
    spent = [0.0] * len(points)
    found: dict[tuple[int, int], list[Finding]] = {}
    baseline_locks: dict[int, asyncio.Lock] = {}
    heavy: list[tuple[int, int]] = []
    heavy_points: set[int] = set()
    session_lock = asyncio.Lock()
    done = 0

    async def baseline_for(pi: int):
        point = points[pi]
        async with baseline_locks.setdefault(pi, asyncio.Lock()):
            if point.key() not in baselines:
                # What a normal request to this point looks like: the same shape the probes send (query, form or
                # JSON body, path placeholder filled in), with an ordinary value in the tested place.
                url, kwargs = build_request(point, point.seed_value or "1")
                baselines[point.key()] = await get_baseline(rm, point.method, url, **kwargs)
            return baselines[point.key()]

    def finish(pi: int) -> None:
        remaining[pi] -= 1
        if remaining[pi] == 0:
            coverage["points_tested"] += 1

    async def run_pair(pi: int, qi: int, baseline) -> None:
        point, probe = points[pi], probes[qi]
        # A point's time is capped: an endpoint that takes seconds to answer would otherwise spend the whole budget.
        budget = max(POINT_BUDGET_MIN_S, POINT_BUDGET_SLOWDOWN * (baseline.elapsed if baseline else 0.0))
        if spent[pi] > budget:
            coverage["pairs_time_capped"] = coverage.get("pairs_time_capped", 0) + 1
            finish(pi)
            return
        started = time.monotonic()
        try:
            results = await probe.detect(rm, point, baseline, hinted=_is_hinted(point, probe.cwe, hints))
            for finding in results:
                finding.selector = point.selector
            found[(pi, qi)] = results
        except Exception:
            logger.exception("Probe %s failed on %s %s param=%s", probe.name, point.method, point.url, point.param)
        finally:
            took = time.monotonic() - started
            spent[pi] += took
            seconds = coverage.setdefault("probe_seconds", {})
            seconds[probe.name] = round(seconds.get(probe.name, 0.0) + took, 2)
        finish(pi)

    async def take(queue: list, second_pass: bool) -> None:
        nonlocal done
        while queue:
            pi, qi = queue.pop(0)
            if rm.budget.expired():
                if not coverage["deadline_reached"]:
                    logger.info("Probe runner stopping: deadline reached (%d/%d points covered)", coverage["points_tested"], len(points))
                coverage["deadline_reached"] = True
                return
            if points[pi].method.upper() in skip_methods:
                # Even the baseline request would run the action: a DELETE of "item 1" deletes item 1.
                coverage["pairs_skipped_destructive"] = coverage.get("pairs_skipped_destructive", 0) + 1
                finish(pi)
                continue
            if points[pi].meta.get("type") in TYPED_KINDS:
                # The framework parses this value as a number, date or one of a few choices before the code sees it,
                # so text can't be injected through it. SAST's own analysis clears these the same way.
                coverage["pairs_skipped_typed"] = coverage.get("pairs_skipped_typed", 0) + 1
                finish(pi)
                continue
            done += 1
            if session is not None and done % max(1, session.check_every) == 0:
                async with session_lock:
                    await session.ensure()
            baseline = await baseline_for(pi)
            if not second_pass and (pi in heavy_points or (baseline is not None and baseline.elapsed > HEAVY_ENDPOINT_S)):
                heavy_points.add(pi)
                heavy.append((pi, qi))
                continue
            await run_pair(pi, qi, baseline)

    queue = list(order)
    await asyncio.gather(*(take(queue, False) for _ in range(max(1, concurrency))))
    heavy_queue = list(heavy)
    await take(heavy_queue, True)

    return [item for key in sorted(found) for item in found[key]]
