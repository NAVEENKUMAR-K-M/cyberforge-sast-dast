import pytest

from core.request_manager import Budget, RequestManager
from core.scheduler import DeadlineTimer
from core.scope_guard import ScopeGuard


def make_rm(base_url: str) -> RequestManager:
    guard = ScopeGuard(allowed_hosts=["127.0.0.1"], denylist_patterns=[])
    timer = DeadlineTimer(30)
    budget = Budget(deadline_ts=timer.start + 30, report_reserve_s=1)
    return RequestManager(scope_guard=guard, budget=budget, start_rps=50, floor_rps=10)


@pytest.mark.asyncio
async def test_malformed_redirect_location_does_not_raise(fixture_app_url):
    """Regression test: httpx validates/builds the redirect request as
    soon as a response has a Location header, even with follow_redirects
    disabled at the client level -- a malformed Location (exactly what a
    fuzzed param reflected into a redirect can produce) must come back as
    a None response, not an uncaught exception that kills whatever probe
    triggered it."""
    rm = make_rm(fixture_app_url)
    try:
        # exactly the shape a path-traversal payload produces when it
        # lands in a redirect-target param (observed against live DVWA):
        # an absolute Windows-style path, which httpx's URL parser
        # rejects as a Location header value.
        resp = await rm.get(f"{fixture_app_url}/bad-redirect", params={"to": "C:\\windows\\win.ini"})
    finally:
        await rm.aclose()
    assert resp is None


@pytest.mark.asyncio
async def test_well_formed_redirect_still_works(fixture_app_url):
    rm = make_rm(fixture_app_url)
    try:
        resp = await rm.get(f"{fixture_app_url}/bad-redirect", params={"to": "/elsewhere"})
    finally:
        await rm.aclose()
    assert resp is not None
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/elsewhere"
