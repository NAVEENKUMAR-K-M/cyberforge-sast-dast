"""Reusable entry point for the correlation engine (bonus B-1): given a
code-only (SAST) finding's (cwe, method, route, param), re-check it live
and report whether it reproduces at runtime. This lets correlation upgrade
a Code-only finding to Confirmed without re-running the whole scan.

The folder is named dast-engine, which can't be a Python package name, and its
modules import each other as top-level names (core, scanners, ...). So there
are two ways in:

    # From another process, with JSON on stdout. Run with dast-engine as the
    # working directory. This keeps the two engines' imports apart.
    python main.py verify --target http://localhost:8080 --config dvwa.yaml \\
        --cwe CWE-89 --method GET --route /vulnerabilities/sqli/ --param id

    # In-process, with dast-engine on sys.path:
    from api import verify
    result = await verify("CWE-89", "GET", "/vulnerabilities/sqli/", "id",
                           target="http://localhost:8080", config=cfg)
"""
from __future__ import annotations

import logging
import re
import time
from urllib.parse import parse_qsl, urlencode

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
    selector: str | None = None,
    fields: dict | None = None,
    hint: str | None = None,
    attempts_out: list | None = None,
) -> dict | None:
    """Re-test one specific (cwe, method, route, param) tuple live.

    Returns a finding dict (see results/schema.json) if it reproduces,
    otherwise None. Builds a fresh, logged-in RequestManager and calls the
    matching probe's verify() directly -- no full crawl/discovery needed,
    so this stays fast enough to call per hint.

    `fields` are other values the request needs (a login form's password) and
    `hint` is a payload shape the probe tries first: {canary} for a redirect,
    {marker} for XSS, a traversal prefix for path traversal. If `attempts_out`
    is a list, every request the probe sends is appended to it (secrets masked).
    """
    probe_cls = _PROBE_BY_CWE.get(cwe)
    if probe_cls is None:
        logger.warning("verify(): no probe registered for %s", cwe)
        return None

    timer = DeadlineTimer(float(config.get("verify_deadline_seconds", 30)))
    scope_guard = ScopeGuard.from_config(config)
    url = target.rstrip("/") + route
    if not scope_guard.is_in_scope(url) or (selector and scope_guard.is_selector_denylisted(selector)):
        logger.warning("verify(): %s (selector %s) is out of scope/denylisted", url, selector)
        return None
    if selector:
        url = f"{url}?{urlencode(parse_qsl(selector, keep_blank_values=True))}"

    budget = Budget(deadline_ts=timer.start + timer.total_s, report_reserve_s=2.0)
    rm = RequestManager(scope_guard=scope_guard, budget=budget)
    try:
        from core.auth import login

        await login(rm, config.get("auth", {}))

        if attempts_out is not None:
            _record_requests(rm, attempts_out)
        probe = probe_cls()
        finding = await probe.verify(rm, method, url, route, param, param_location, fields=fields, hint=hint)
    finally:
        await rm.aclose()

    if finding is None:
        return None
    finding.selector = selector
    return finding.to_dict()


_SECRET_KEY = re.compile(r"pass|pwd|secret|token|auth|cookie|csrf", re.I)
MAX_RECORDED = 100


def _record_requests(rm: RequestManager, out: list) -> None:
    """Wraps rm.send so each request a re-test makes is kept: what was sent, and the status and size
    that came back. Called after login, so credentials never appear."""
    send = rm.send

    def masked(values):
        return {k: ("[masked]" if _SECRET_KEY.search(str(k)) else v) for k, v in (values or {}).items()}

    async def recording_send(method, url, **kwargs):
        started = time.monotonic()
        response = await send(method, url, **kwargs)
        if len(out) < MAX_RECORDED:
            out.append({
                "method": method, "url": url,
                "query": masked(kwargs.get("params")), "body": masked(kwargs.get("data") or kwargs.get("json")),
                "status": response.status_code if response is not None else None,
                "length": len(response.text) if response is not None else None,
                "excerpt": response.text[:160] if response is not None else None,
                "seconds": round(time.monotonic() - started, 2),
            })
        return response

    rm.send = recording_send
