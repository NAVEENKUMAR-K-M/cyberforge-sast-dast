"""Top-level orchestrator: wires scope guard -> auth -> discovery -> passive
-> active backend -> normalize/write, respecting the overall time budget.
"""
from __future__ import annotations

import logging
import time
from urllib.parse import parse_qsl, urlencode, urljoin

from core.auth import SessionKeeper, login
from core.models import InjectionPoint
from core.request_manager import Budget, RequestManager
from core.scheduler import DeadlineTimer, allocate
from core.scope_guard import ScopeGuard
from discovery.crawler import crawl
from discovery.injection_points import build_injection_points
from discovery.openapi_loader import load_from_url
from discovery.route_map_loader import load_route_map, load_sast_hints
from results.normalizer import build_output, write_output
from scanners.passive import PassiveScanner
from scanners.probe_runner import run_probes
from scanners.stored_marker import check_persistence, submit_markers

logger = logging.getLogger("dast.controller")


async def run_scan(config: dict) -> dict:
    target = config["target"].rstrip("/")
    total_budget_s = float(config.get("deadline_seconds", 150))
    report_reserve_s = float(config.get("report_reserve_seconds", 15))
    timer = DeadlineTimer(total_budget_s)
    phases = allocate(total_budget_s, report_reserve_s)

    scope_guard = ScopeGuard.from_config(config)
    budget = Budget(deadline_ts=timer.start + total_budget_s, report_reserve_s=report_reserve_s)
    rm = RequestManager(
        scope_guard=scope_guard,
        budget=budget,
        start_rps=float(config.get("start_rps", 25)),
        floor_rps=float(config.get("floor_rps", 5)),
        verify_tls=bool(config.get("verify_tls", False)),
    )

    all_findings = []
    points: list[InjectionPoint] = []
    coverage: dict = {}
    session = SessionKeeper(rm, config.get("auth", {}))
    started_at = time.time()
    try:
        auth_ok = await login(rm, config.get("auth", {}))
        if not auth_ok:
            logger.warning("Auth did not appear to succeed; continuing unauthenticated")
        await session.start()

        # --- Discovery ---
        route_map = load_route_map(config["route_map_path"]) if config.get("route_map_path") else []
        seed_urls = [*(config.get("seed_urls") or [target]), *_route_map_pages(route_map, target, scope_guard)]
        crawl_result = await crawl(rm, scope_guard, seed_urls, max_pages=config.get("max_pages", 200))
        openapi_routes = []
        for spec_url in crawl_result.api_specs:
            openapi_routes.extend(await load_from_url(rm, spec_url))
        points = build_injection_points(route_map, crawl_result, openapi_routes, base_url=target)
        # Crawled points are already guaranteed in-scope (the crawler checks
        # before enqueueing a URL at all), but route-map-sourced ones never
        # go through that check -- a route map legitimately lists every
        # route the code has, denylisted ones included (logout.php,
        # setup.php, ...). Sending them anyway isn't just wasted effort:
        # RequestManager.send() *raises* ScopeViolation on an out-of-scope
        # URL rather than skipping it, which crashed the whole scan on the
        # first denylisted route-map point reached (confirmed in testing).
        before = len(points)
        points = [
            p for p in points
            if scope_guard.is_in_scope(p.url) and not (p.selector and scope_guard.is_selector_denylisted(p.selector))
        ]
        coverage.update({"points_found": before, "points_dropped_by_scope": before - len(points)})
        if before != len(points):
            logger.info("Dropped %d route-map point(s) outside scope/denylist", before - len(points))
        logger.info("Discovered %d injection points across %d URLs", len(points), len(crawl_result.urls))

        # --- Passive checks (reuse responses already fetched during crawl) ---
        passive = PassiveScanner(rm, scope_guard, target)
        for url in sorted(crawl_result.urls)[:200]:
            if timer.remaining() <= phases.active_s + report_reserve_s:
                break
            resp = await rm.get(url)
            passive.inspect_response(url, resp)
        first_visit_urls = [target, *sorted(crawl_result.urls)[:9]]
        await passive.check_first_visit_cookies(first_visit_urls)
        all_findings.extend(await passive.active_checks())
        all_findings.extend(passive.finalize())

        # --- Light stored-content check ---
        try:
            submissions = await submit_markers(rm, crawl_result.forms)
            get_urls = [u for u in crawl_result.urls if u not in {f.action for f in crawl_result.forms}]
            all_findings.extend(await check_persistence(rm, submissions, get_urls))
        except Exception:
            logger.exception("stored-marker check failed")

        # --- Active backend: custom Python probes (default), or ZAP/Nuclei ---
        active_backend = config.get("active_backend", "python")
        if active_backend == "python":
            hints = load_sast_hints(config.get("hints_path"))
            all_findings.extend(await run_probes(rm, points, hints=hints, coverage=coverage, session=session))
        elif active_backend == "zap":
            from scanners.zap_runner import ZapRunner

            runner = ZapRunner(
                zap_api_url=config.get("zap_api_url", "http://localhost:8090"),
                target=target,
                deadline_ts=timer.start + total_budget_s - report_reserve_s,
                denylist_patterns=config.get("denylist", []),
                scan_target=config.get("zap_scan_target"),
            )
            # Scan only actual injection points (pages with real params),
            # not every crawled URL -- a plain nav page with no params has
            # nothing to inject into, and scanning it anyway (observed in
            # testing) burns through the time budget on irrelevant pages
            # before reaching the ones that matter.
            active_scan_urls = sorted({p.url for p in points}) or list(crawl_result.urls)
            all_findings.extend(await runner.run(active_scan_urls, cookies=rm.cookies))
        elif active_backend == "nuclei":
            from scanners.nuclei_runner import run as nuclei_run

            all_findings.extend(await nuclei_run(points, rate_limit=int(config.get("start_rps", 25)), deadline_remaining_s=timer.remaining()))
        else:
            logger.info("active_backend=%s (none) — skipping active injection scan", active_backend)

    finally:
        await rm.aclose()

    finished_at = time.time()
    coverage["session_relogins"] = session.relogins
    output = build_output(
        all_findings,
        target=target,
        started_at=started_at,
        finished_at=finished_at,
        request_count=rm.request_count,
        injection_point_count=len(points),
        latencies=rm.latencies,
        coverage=coverage,
    )
    write_output(output, config.get("output_path", "output/dast_results.json"))
    return output


def _route_map_pages(route_map: list[dict], target: str, scope_guard: ScopeGuard) -> list[str]:
    """Pages only the route map knows about, so passive checks and form discovery see them too."""
    pages = []
    for route in route_map:
        selector = route.get("selector")
        if route.get("method") != "GET" or "{" in route["path"] or (selector and scope_guard.is_selector_denylisted(selector)):
            continue
        url = urljoin(target + "/", route["path"].lstrip("/"))
        pages.append(f"{url}?{urlencode(parse_qsl(selector, keep_blank_values=True))}" if selector else url)
    return list(dict.fromkeys(pages))
