"""Rate-limited, scope-checked, deadline-aware HTTP client used by every
other module. All outbound traffic goes through RequestManager.send().
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

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


OVERLOAD_STATUSES = {429, 502, 503, 504}
# (cookie the app sets, header it expects the value back in)
CSRF_COOKIES = (("XSRF-TOKEN", "X-XSRF-TOKEN"), ("csrftoken", "X-CSRFToken"))


class AdaptiveRateLimiter:
    """Token-bucket-ish limiter that starts fast, backs off when the server struggles, and speeds up again
    once it has stopped struggling.

    start=25rps, halves on error-burst or on a share of slow answers, floor=5rps. "Slow" is judged against
    what that endpoint normally takes: a lookup that always waits four seconds on DNS isn't a server in
    trouble, but a page that was quick and suddenly isn't is.
    """

    def __init__(self, start_rps: float = 25.0, floor_rps: float = 5.0, ceiling_rps: float = 25.0):
        self.rps = start_rps
        self.floor = floor_rps
        self.ceiling = ceiling_rps
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._typical: dict[str, float] = {}
        self._recent_slow = 0
        self._recent_errors = 0
        self._recent_total = 0
        self._recent_max = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / max(self.rps, 0.1)
            wait = self._last + min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = max(now, self._last + min_interval)

    def record(self, elapsed: float, is_error: bool, key: str | None = None) -> None:
        typical = self._typical.get(key) if key is not None else None
        # A first answer from an endpoint has nothing to be compared with, so only an extreme one counts.
        slow = elapsed > 1.0 and (elapsed > 3 * typical if typical is not None else elapsed > 8.0)
        if key is not None:
            self._typical[key] = elapsed if typical is None else 0.7 * typical + 0.3 * elapsed
        self._recent_total += 1
        self._recent_slow += slow
        self._recent_errors += is_error
        self._recent_max = max(self._recent_max, elapsed)
        if self._recent_total >= 20:
            error_rate = self._recent_errors / self._recent_total
            if self._recent_slow / self._recent_total > 0.05 or error_rate > 0.2:
                self.rps = max(self.floor, self.rps / 2)
                logger.info("Backing off rate to %.1f rps (slow=%d/%d, err_rate=%.2f)", self.rps, self._recent_slow, self._recent_total, error_rate)
            elif self.rps < self.ceiling:
                self.rps = min(self.ceiling, self.rps * 1.5)
                logger.info("Speeding up to %.1f rps", self.rps)
            self._recent_slow = self._recent_errors = self._recent_total = 0
            self._recent_max = 0.0


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
        self._timeout, self._verify_tls = timeout, verify_tls
        self.request_count = 0
        self.latencies: list[float] = []
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=False,  # we manually vet redirects via scope_guard
        )
        self.cookies: dict = {}
        self.extra_headers: dict = {}
        self.landing_url: str | None = None  # the page a successful login lands on

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
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            self._add_csrf_header(merged_headers)
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
            self.limiter.record(time.monotonic() - start, is_error, key=urlsplit(url).path)
            return None
        elapsed = time.monotonic() - start
        # A plain 500 is how an app without debug output answers a broken query, so it is a finding's
        # signal and says nothing about load. Only an overloaded server or a gateway in front of it asks us to slow down.
        is_error = resp.status_code in OVERLOAD_STATUSES
        # A serial request is a deliberate sleep payload: it is slow on purpose.
        self.limiter.record(0.0 if serial else elapsed, is_error, key=urlsplit(url).path)
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

    def _add_csrf_header(self, headers: dict) -> None:
        """Apps that hand out their CSRF token in a cookie (Laravel and Angular's XSRF-TOKEN, Django's csrftoken) expect
        it back in a header on every write. A browser's script does that without being asked, so a scan has to."""
        for cookie_name, header_name in CSRF_COOKIES:
            if header_name in headers:
                continue
            try:
                value = self._client.cookies.get(cookie_name)
            except Exception:  # more than one cookie of that name; not worth guessing which
                value = None
            if value:
                headers[header_name] = unquote(value)

    async def fresh_get(self, url: str) -> httpx.Response | None:
        """A GET as a first-time visitor, with no cookies. Some things only happen on a first
        visit: a server sets its session cookie once, and later responses never repeat it."""
        if self.budget.expired() or not self.scope_guard.is_in_scope(url):
            return None
        await self.limiter.acquire()
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify_tls, follow_redirects=False) as client:
                resp = await client.get(url)
        except (httpx.RequestError, httpx.InvalidURL) as exc:
            logger.debug("Fresh request error %s: %s", url, exc)
            return None
        self.request_count += 1
        return resp

    def clear_session(self) -> None:
        self.cookies.clear()
        self._client.cookies.clear()

    async def get(self, url: str, **kwargs) -> httpx.Response | None:
        return await self.send("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response | None:
        return await self.send("POST", url, **kwargs)
