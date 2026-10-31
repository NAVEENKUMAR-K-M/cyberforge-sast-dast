"""Top-level orchestrator: wires scope guard -> auth -> discovery -> passive
-> active backend -> normalize/write, respecting the overall time budget.
"""
from __future__ import annotations

import asyncio
import logging
import time

from core.auth import login
from core.models import InjectionPoint
from core.request_manager import Budget, RequestManager
from core.scheduler import DeadlineTimer, allocate
from core.scope_guard import ScopeGuard
from discovery.baseline import get_baseline
from discovery.crawler import crawl
from discovery.injection_points import build_injection_points
from discovery.route_map_loader import load_route_map
from results.normalizer import build_output, write_output
from scanners.passive import PassiveScanner
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
    started_at = time.time()
    try:
        auth_ok = await login(rm, config.get("auth", {}))
        if not auth_ok:
            logger.warning("Auth did not appear to succeed; continuing unauthenticated")

        # --- Discovery ---
        route_map = load_route_map(config["route_map_path"]) if config.get("route_map_path") else []
        seed_urls = config.get("seed_urls") or [target]
        crawl_result = await crawl(rm, scope_guard, seed_urls, max_pages=config.get("max_pages", 200))
        points = build_injection_points(route_map, crawl_result)
        logger.info("Discovered %d injection points across %d URLs", len(points), len(crawl_result.urls))

        baselines = {}
        for point in points:
            if timer.remaining() <= phases.active_s + phases.passive_s + report_reserve_s:
                break
            b = await get_baseline(rm, point.method, point.url)
            if b is not None:
                baselines[point.key()] = b

        # --- Passive checks (reuse responses already fetched during crawl) ---
        passive = PassiveScanner(rm, scope_guard, target)
        for url in list(crawl_result.urls)[:200]:
            if timer.remaining() <= phases.active_s + report_reserve_s:
                break
            resp = await rm.get(url)
            passive.inspect_response(url, resp)
        all_findings.extend(await passive.active_checks())
        all_findings.extend(passive.finalize())

        # --- Light stored-content check ---
        try:
            submissions = await submit_markers(rm, crawl_result.forms)
            get_urls = [u for u in crawl_result.urls if u not in {f.action for f in crawl_result.forms}]
            all_findings.extend(await check_persistence(rm, submissions, get_urls))
        except Exception:
            logger.exception("stored-marker check failed")

        # --- Active backend (ZAP primary, Nuclei optional alt) ---
        active_backend = config.get("active_backend", "zap")
        if active_backend == "zap":
            from scanners.zap_runner import ZapRunner

            runner = ZapRunner(
                zap_api_url=config.get("zap_api_url", "http://localhost:8090"),
                target=target,
                deadline_ts=timer.start + total_budget_s - report_reserve_s,
                denylist_patterns=config.get("denylist", []),
            )
            all_findings.extend(await runner.run(list(crawl_result.urls), cookies=rm.cookies))
        elif active_backend == "nuclei":
            from scanners.nuclei_runner import run as nuclei_run

            all_findings.extend(await nuclei_run(points, rate_limit=int(config.get("start_rps", 25)), deadline_remaining_s=timer.remaining()))
        else:
            logger.info("active_backend=%s (none) — skipping active injection scan", active_backend)

    finally:
        await rm.aclose()

    finished_at = time.time()
    output = build_output(
        all_findings,
        target=target,
        started_at=started_at,
        finished_at=finished_at,
        request_count=rm.request_count,
        injection_point_count=len(points),
        latencies=rm.latencies,
    )
    write_output(output, config.get("output_path", "output/dast_results.json"))
    return output
