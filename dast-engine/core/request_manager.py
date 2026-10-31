"""Rate-limited, scope-checked, deadline-aware HTTP client used by every
other module. All outbound traffic goes through RequestManager.send().
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

from core.scope_guard import ScopeGuard, ScopeViolation

logger = logging.getLogger("dast.request_manager")


@dataclass
class Budget:
    deadline_ts: float  # absolute time.monotonic() deadline for *scanning*
    report_reserve_s: float = 15.0  # seconds held back for reporting

    def remaining(self) -> float:
        return max(0.0, self.deadline_ts - self.report_reserve_s - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0


class AdaptiveRateLimiter:
    """Token-bucket-ish limiter that starts fast and backs off on errors/latency.

    start=25rps, halves on error-burst or p95>1s, floor=5rps.
    """

    def __init__(self, start_rps: float = 25.0, floor_rps: float = 5.0, ceiling_rps: float = 25.0):
        self.rps = start_rps
        self.floor = floor_rps
        self.ceiling = ceiling_rps
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._recent_latencies: list[float] = []
        self._recent_errors = 0
        self._recent_total = 0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / max(self.rps, 0.1)
            wait = self._last + min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = max(now, self._last + min_interval)

    def record(self, elapsed: float, is_error: bool) -> None:
        self._recent_latencies.append(elapsed)
        self._recent_total += 1
        if is_error:
            self._recent_errors += 1
        if self._recent_total >= 20:
            p95 = sorted(self._recent_latencies)[int(len(self._recent_latencies) * 0.95) - 1]
            error_rate = self._recent_errors / self._recent_total
            if p95 > 1.0 or error_rate > 0.2:
                self.rps = max(self.floor, self.rps / 2)
                logger.info("Backing off rate to %.1f rps (p95=%.2fs, err_rate=%.2f)", self.rps, p95, error_rate)
            self._recent_latencies.clear()
            self._recent_errors = 0
            self._recent_total = 0


class RequestManager:
    def __init__(
        self,
        scope_guard: ScopeGuard,
        budget: Budget,
        timeout: float = 10.0,
        start_rps: float = 25.0,
        floor_rps: float = 5.0,
        verify_tls: bool = False,
        follow_redirects: bool = False,
    ):
        self.scope_guard = scope_guard
        self.budget = budget
        self.limiter = AdaptiveRateLimiter(start_rps=start_rps, floor_rps=floor_rps, ceiling_rps=start_rps)
        self.request_count = 0
        self.latencies: list[float] = []
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=False,  # we manually vet redirects via scope_guard
        )
        self.cookies: dict = {}
        self.extra_headers: dict = {}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "RequestManager":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def send(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        json: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
        allow_redirect_follow_once: bool = True,
        serial: bool = False,
        bypass_denylist: bool = False,
    ) -> httpx.Response | None:
        """Send a single request. Returns None if out of scope, denylisted,
        or the budget has expired (scan deadline reached).

        `bypass_denylist` is only for deliberate, config-specified setup
        steps (e.g. auth.py's post_login actions) that intentionally target
        a denylisted path such as DVWA's security.php. The denylist exists
        to stop the *crawler* from wandering onto destructive/state-changing
        pages, not to block an explicit, one-time, operator-approved action.
        The host allowlist is still enforced either way.
        """
        if self.budget.expired():
            return None
        in_scope = self.scope_guard.is_in_scope(url) or (
            bypass_denylist and self.scope_guard.is_allowed_host(url)
        )
        if not in_scope:
            raise ScopeViolation(f"Refusing out-of-scope request: {url}")

        await self.limiter.acquire()

        merged_headers = {**self.extra_headers, **(headers or {})}
        merged_cookies = {**self.cookies, **(cookies or {})}
        # Send cookies as a plain Cookie header rather than via httpx's
        # per-request `cookies=` (deprecated: it mutates client-wide jar
        # state in a way that's ambiguous for our single-target use).
        if merged_cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in merged_cookies.items())
            merged_headers.setdefault("Cookie", cookie_header)

        start = time.monotonic()
        is_error = False
        try:
            resp = await self._client.request(
                method,
                url,
                params=params,
                data=data,
                json=json,
                headers=merged_headers,
            )
            self.request_count += 1
        except (httpx.RequestError, httpx.InvalidURL) as exc:
            # httpx.InvalidURL: fuzzing a param that ends up reflected into
            # a redirect's Location header can produce a Location value
            # that isn't a valid URL at all (e.g. a path-traversal payload
            # landing in an open-redirect param). httpx validates/builds
            # the redirect request eagerly *even when follow_redirects is
            # off* (it still populates response.next_request), so a
            # malformed Location raises here regardless -- this is an
            # expected, not exceptional, outcome of probing, not a real
            # connection failure.
            logger.debug("Request error %s %s: %s", method, url, exc)
            is_error = True
            self.limiter.record(time.monotonic() - start, is_error)
            return None
        elapsed = time.monotonic() - start
        is_error = resp.status_code >= 500
        self.limiter.record(elapsed, is_error)
        self.latencies.append(elapsed)

        if (
            allow_redirect_follow_once
            and resp.is_redirect
            and "location" in resp.headers
        ):
            location = resp.headers["location"]
            if not self.scope_guard.check_redirect(url, location):
                # Do not follow off-scope redirects; caller still gets this response.
                return resp
        return resp

    async def get(self, url: str, **kwargs) -> httpx.Response | None:
        return await self.send("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response | None:
        return await self.send("POST", url, **kwargs)
