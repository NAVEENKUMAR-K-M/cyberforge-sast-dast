"""Reusable entry point for the correlation engine (bonus B-1): given a
code-only (SAST) finding's (cwe, method, route, param), re-check it live
and report whether it reproduces at runtime. This lets correlation upgrade
a Code-only finding to Confirmed without re-running the whole scan.

Usage from the correlation engine:
    from dast_engine.api import verify
    result = await verify("CWE-89", "GET", "/vulnerabilities/sqli/", "id",
                           target="http://localhost:8080", config=cfg)
"""
from __future__ import annotations

import logging

from core.request_manager import Budget, RequestManager
from core.scheduler import DeadlineTimer
from core.scope_guard import ScopeGuard
from scanners.probes.cmdi import CmdiProbe
from scanners.probes.open_redirect import OpenRedirectProbe
from scanners.probes.path_traversal import PathTraversalProbe
from scanners.probes.sqli import SqliProbe
from scanners.probes.xss import XssProbe

logger = logging.getLogger("dast.api")

_PROBE_BY_CWE = {
    "CWE-89": SqliProbe,
    "CWE-79": XssProbe,
    "CWE-78": CmdiProbe,
    "CWE-22": PathTraversalProbe,
    "CWE-601": OpenRedirectProbe,
}


async def verify(
    cwe: str,
    method: str,
    route: str,
    param: str,
    *,
    target: str,
    config: dict,
    param_location: str = "query",
) -> dict | None:
    """Re-test one specific (cwe, method, route, param) tuple live.

    Returns a finding dict (see results/schema.json) if it reproduces,
    otherwise None. Builds a fresh, logged-in RequestManager and calls the
    matching probe's verify() directly -- no full crawl/discovery needed,
    so this stays fast enough to call per hint.
    """
    probe_cls = _PROBE_BY_CWE.get(cwe)
    if probe_cls is None:
        logger.warning("verify(): no probe registered for %s", cwe)
        return None

    timer = DeadlineTimer(float(config.get("verify_deadline_seconds", 30)))
    scope_guard = ScopeGuard.from_config(config)
    url = target.rstrip("/") + route
    if not scope_guard.is_in_scope(url):
        logger.warning("verify(): %s is out of scope/denylisted", url)
        return None

    budget = Budget(deadline_ts=timer.start + timer.total_s, report_reserve_s=2.0)
    rm = RequestManager(scope_guard=scope_guard, budget=budget)
    try:
        from core.auth import login

        await login(rm, config.get("auth", {}))

        probe = probe_cls()
        finding = await probe.verify(rm, method, url, route, param, param_location)
    finally:
        await rm.aclose()

    return finding.to_dict() if finding else None
