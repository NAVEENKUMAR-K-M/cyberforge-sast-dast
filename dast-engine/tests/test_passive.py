import pytest

from core.request_manager import Budget, RequestManager
from core.scope_guard import ScopeGuard
from core.scheduler import DeadlineTimer
from scanners.passive import PassiveScanner


def make_rm(base_url: str) -> RequestManager:
    guard = ScopeGuard(allowed_hosts=["127.0.0.1"], denylist_patterns=[])
    timer = DeadlineTimer(30)
    budget = Budget(deadline_ts=timer.start + 30, report_reserve_s=1)
    return RequestManager(scope_guard=guard, budget=budget, start_rps=50, floor_rps=10)


@pytest.mark.asyncio
async def test_detects_missing_headers_and_cookie_flags(fixture_app_url):
    rm = make_rm(fixture_app_url)
    passive = PassiveScanner(rm, rm.scope_guard, fixture_app_url)
    try:
        url = f"{fixture_app_url}/insecure"
        resp = await rm.get(url)
        passive.inspect_response(url, resp)
        findings = passive.finalize()
    finally:
        await rm.aclose()

    cwes = {f.cwe for f in findings}
    assert "CWE-1021" in cwes  # missing CSP / X-Frame-Options
    assert "CWE-1004" in cwes  # missing HttpOnly
    assert "CWE-942" in cwes  # permissive CORS
    assert "CWE-200" in cwes  # server banner disclosure


@pytest.mark.asyncio
async def test_secure_route_is_not_flagged_as_decoy(fixture_app_url):
    rm = make_rm(fixture_app_url)
    passive = PassiveScanner(rm, rm.scope_guard, fixture_app_url)
    try:
        url = f"{fixture_app_url}/secure"
        resp = await rm.get(url)
        passive.inspect_response(url, resp)
        findings = passive.finalize()
    finally:
        await rm.aclose()

    affected = set()
    for f in findings:
        affected.update(f.evidence.extra.get("affected_urls", []))
    assert url not in affected, "secure route must not appear in any missing-header/cookie finding (false alarm)"


@pytest.mark.asyncio
async def test_detects_stack_trace_disclosure(fixture_app_url):
    rm = make_rm(fixture_app_url)
    passive = PassiveScanner(rm, rm.scope_guard, fixture_app_url)
    try:
        url = f"{fixture_app_url}/stack-trace"
        resp = await rm.get(url)
        passive.inspect_response(url, resp)
        findings = passive.finalize()
    finally:
        await rm.aclose()

    cwes = {f.cwe for f in findings}
    assert "CWE-209" in cwes
