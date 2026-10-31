import pytest

from core.request_manager import Budget, RequestManager
from core.scope_guard import ScopeGuard
from core.scheduler import DeadlineTimer
from discovery.crawler import CrawledForm
from scanners.stored_marker import check_persistence, submit_markers


def make_rm(base_url: str) -> RequestManager:
    guard = ScopeGuard(allowed_hosts=["127.0.0.1"], denylist_patterns=[])
    timer = DeadlineTimer(30)
    budget = Budget(deadline_ts=timer.start + 30, report_reserve_s=1)
    return RequestManager(scope_guard=guard, budget=budget, start_rps=50, floor_rps=10)


@pytest.mark.asyncio
async def test_marker_persists_and_is_detected(fixture_app_url):
    rm = make_rm(fixture_app_url)
    try:
        form = CrawledForm(
            method="POST",
            action=f"{fixture_app_url}/comment",
            fields={"message": ""},
            field_types={"message": "text"},
        )
        submissions = await submit_markers(rm, [form])
        assert len(submissions) == 1

        findings = await check_persistence(rm, submissions, [f"{fixture_app_url}/comments"])
    finally:
        await rm.aclose()

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-79"
    assert findings[0].payload == submissions[0].marker


@pytest.mark.asyncio
async def test_no_finding_when_marker_never_echoed(fixture_app_url):
    rm = make_rm(fixture_app_url)
    try:
        form = CrawledForm(
            method="POST",
            action=f"{fixture_app_url}/comment",
            fields={"message": ""},
            field_types={"message": "text"},
        )
        submissions = await submit_markers(rm, [form])
        # Recheck a page that never echoes the marker -> no finding (false-alarm guard).
        findings = await check_persistence(rm, submissions, [f"{fixture_app_url}/secure"])
    finally:
        await rm.aclose()

    assert findings == []
