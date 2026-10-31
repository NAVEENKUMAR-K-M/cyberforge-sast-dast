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

from core.models import ParamLocation
from core.request_manager import Budget, RequestManager
from core.scope_guard import ScopeGuard

logger = logging.getLogger("dast.api")

_CWE_BACKEND = {
    "CWE-89": "zap",
    "CWE-79": "zap",
    "CWE-78": "zap",
    "CWE-22": "zap",
    "CWE-601": "zap",
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
    otherwise None. Uses the ZAP backend's single-URL active scan rather
    than a full crawl+scan, so this stays fast enough to call per hint.
    """
    import time
    from core.scheduler import DeadlineTimer

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

        from scanners.zap_runner import ZapRunner

        runner = ZapRunner(
            zap_api_url=config.get("zap_api_url", "http://localhost:8090"),
            target=url,
            deadline_ts=timer.start + timer.total_s,
            denylist_patterns=config.get("denylist", []),
        )
        findings = await runner.run([url], cookies=rm.cookies)
    finally:
        await rm.aclose()

    for f in findings:
        if f.cwe == cwe and (not param or f.param == param):
            return f.to_dict()
    return None
