"""OWASP ZAP-backed active scanner.

Why ZAP for the active-injection classes (SQLi/XSS/CMDi/path-traversal/open-
redirect) instead of hand-rolled payload probes: ZAP's Alerts API already
reports the exact url, method, param and attack payload for every finding,
which is precisely the attribution correlation needs, and it's a standard,
non-destructive, widely-used scanner for authorized testing — so this
module only drives ZAP and normalizes its output, it does not author any
exploit payloads itself.

Requires a running ZAP daemon (see Dockerfile / docker-compose), e.g.:
  docker run -p 8090:8090 zaproxy/zap-stable zap.sh -daemon \
    -host 0.0.0.0 -port 8090 -config api.disablekey=true

If ZAP is unreachable, run() returns an empty list and logs a warning so
the rest of the pipeline (passive checks, schema, eval) still works.

Docker note: when ZAP runs in its own container (as in docker-compose.dev.yml)
"localhost" inside that container means the ZAP container itself, not the
target -- it can't reach a target published only on the *host's* loopback.
Pass `scan_target` as the address ZAP's container can actually reach (e.g.
the target container's service name on the same compose network, like
"http://dvwa:80") while `target`/seed_urls stay on the public host address
used everywhere else in the pipeline; this module rewrites ZAP's result
URLs back onto the public host so the output schema stays consistent.
"""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlsplit, urlunsplit, urlparse

from core.models import Confidence, Evidence, Finding, Severity

logger = logging.getLogger("dast.zap_runner")

CWEID_MAP = {
    89: "CWE-89",   # SQL injection
    90: "CWE-90",   # LDAP injection
    79: "CWE-79",   # XSS
    78: "CWE-78",   # OS command injection
    22: "CWE-22",   # Path traversal
    601: "CWE-601",  # Open redirect
    98: "CWE-98",   # Remote file inclusion
}

RISK_TO_SEVERITY = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}

# Only enable ascan rule groups relevant to the CWEs we're scoring, to stay
# inside the time budget and avoid noisy out-of-scope alert categories.
#
# The *_TIME_BASED_SQLI_PLUGIN_IDS (below) are deliberately excluded here:
# each one works by sending a payload that makes the DB sleep and timing
# the response, per parameter -- confirmed in testing to consume most of
# the scan budget on their own while the plain "SQL Injection" scanner
# (40018, error/boolean-based) already catches the same bugs almost
# instantly. Time-based detection is a reasonable trade to drop for a hard
# 150s-per-scan budget.
ACTIVE_SCAN_PLUGIN_IDS = [
    "40018",  # SQL Injection (error/boolean-based -- fast, catches the same bugs)
    "40024",  # SQL Injection - SQLite
    "40012",  # XSS Reflected
    "40014",  # XSS Persistent
    "40026",  # XSS DOM
    "90020",  # Remote OS Command Injection
    "6",      # Path Traversal
    "7",      # Remote File Inclusion
    "10044",  # Open Redirect
]

REPLACER_RULE_DESCRIPTION = "dast-session"


def _rewrite_netloc(url: str, from_netloc: str, to_netloc: str) -> str:
    parts = urlsplit(url)
    if parts.netloc != from_netloc:
        return url
    return urlunsplit((parts.scheme, to_netloc, parts.path, parts.query, parts.fragment))


class ZapRunner:
    def __init__(
        self,
        zap_api_url: str,
        target: str,
        deadline_ts: float,
        denylist_patterns: list[str] | None = None,
        scan_target: str | None = None,
    ):
        self.zap_api_url = zap_api_url.rstrip("/")
        self.target = target.rstrip("/")
        # The address ZAP's own process/container can actually reach.
        # Defaults to `target` (same-host setups); override for Dockerized
        # ZAP (see module docstring).
        self.scan_target = (scan_target or target).rstrip("/")
        self.deadline_ts = deadline_ts
        self.denylist_patterns = denylist_patterns or []
        self._zap = None

    def _target_netloc(self) -> str:
        return urlsplit(self.target).netloc

    def _scan_netloc(self) -> str:
        return urlsplit(self.scan_target).netloc

    def _to_scan_url(self, url: str) -> str:
        return _rewrite_netloc(url, self._target_netloc(), self._scan_netloc())

    def _to_public_url(self, url: str) -> str:
        return _rewrite_netloc(url, self._scan_netloc(), self._target_netloc())

    def _connect(self):
        try:
            from zapv2 import ZAPv2
        except ImportError:
            logger.warning("python-owasp-zap-v2.4 (zapv2) not installed; skipping ZAP active scan")
            return None
        proxies = {"http": self.zap_api_url, "https": self.zap_api_url}
        try:
            zap = ZAPv2(apikey="", proxies=proxies)
            zap.core.version  # probe connectivity
            return zap
        except Exception as exc:
            logger.warning("Cannot reach ZAP daemon at %s: %s", self.zap_api_url, exc)
            return None

    async def run(self, seed_urls: list[str], cookies: dict | None = None) -> list[Finding]:
        loop = asyncio.get_event_loop()
        self._zap = await loop.run_in_executor(None, self._connect)
        if self._zap is None:
            return []
        return await loop.run_in_executor(None, self._run_sync, seed_urls, cookies or {})

    def _run_sync(self, seed_urls: list[str], cookies: dict) -> list[Finding]:
        zap = self._zap
        scan_urls = [self._to_scan_url(u) for u in seed_urls]
        scan_target = self._to_scan_url(self.target)
        try:
            # core.exclude_from_proxy only affects traffic proxied *through*
            # ZAP from an external client -- it does NOT stop the spider or
            # active scanner's own internally-generated requests. Those need
            # their own exclude lists, or the spider will happily follow a
            # "Logout" link (killing the session) and the CSRF/form-crawling
            # part of the scan can auto-submit a destructive form it finds
            # (confirmed in testing: it hit setup.php, resetting the DB, and
            # security.php, resetting the difficulty level, mid-scan).
            try:
                zap.spider.clear_excluded_from_scan()
                zap.ascan.clear_excluded_from_scan()
            except Exception:
                pass
            for pattern in self.denylist_patterns:
                regex = f".*{pattern}.*"
                zap.core.exclude_from_proxy(regex=regex)
                zap.spider.exclude_from_scan(regex=regex)
                zap.ascan.exclude_from_scan(regex=regex)

            if cookies:
                cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
                # add_rule is NOT idempotent across calls with the same
                # description (the daemon persists rules between scans), so
                # a stale cookie from an earlier run would otherwise silently
                # win. Remove any previous rule with this description first.
                try:
                    zap.replacer.remove_rule(description=REPLACER_RULE_DESCRIPTION)
                except Exception:
                    pass
                zap.replacer.add_rule(
                    description=REPLACER_RULE_DESCRIPTION,
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex=False,
                    matchstring="Cookie",
                    replacement=cookie_header,
                )

            reached_any = False
            for url in scan_urls:
                try:
                    result = zap.core.access_url(url=url, followredirects=True)
                except Exception as exc:
                    logger.warning("ZAP access_url raised for %s: %s", url, exc)
                    continue
                # On success this is a list of request/response dicts; on
                # failure the ZAP API collapses to a bare error-code string
                # (e.g. "internal_error", "url_not_found") via zapv2's
                # `next(itervalues(...))` unwrapping.
                if isinstance(result, str):
                    logger.warning("ZAP access_url failed for %s: %s", url, result)
                    continue
                reached_any = True
            if not reached_any:
                logger.error(
                    "ZAP could not reach any seed URL (tried rewriting %s -> %s); "
                    "check scan_target/zap_api_url network reachability from the ZAP process",
                    self._target_netloc(), self._scan_netloc(),
                )
                return []

            # Spidering from the bare root is still useful for discovery
            # (forms, extra params), but it only feeds the site tree -- it
            # does NOT scope the active scan below.
            spider_id = zap.spider.scan(scan_target)
            self._wait_for(lambda: int(zap.spider.status(spider_id)) >= 100, label="spider")

            zap.ascan.disable_all_scanners()
            for pid in ACTIVE_SCAN_PLUGIN_IDS:
                try:
                    zap.ascan.enable_scanners(pid)
                    # LOW strength = fewer payload variations per
                    # parameter, to fit inside the per-scan time budget.
                    zap.ascan.set_scanner_attack_strength(pid, "LOW")
                except Exception:
                    pass

            # Active-scan each discovered URL individually with
            # recurse=False, NOT the bare site root with recurse=True.
            # ascan.scan(scan_target, recurse=True) was found (in testing)
            # to active-scan the *entire* spidered tree -- every README,
            # image and unrelated DVWA module reachable from the root --
            # rather than just the handful of endpoints we actually care
            # about, which alone blew well past the time budget before a
            # single alert got collected.
            for url in scan_urls:
                if time.monotonic() >= self.deadline_ts:
                    logger.info("ZAP ascan: stopping before starting %s, deadline reached", url)
                    break
                try:
                    node_ascan_id = zap.ascan.scan(url=url, recurse=False, inscopeonly=False)
                except Exception as exc:
                    logger.warning("ZAP ascan.scan() raised for %s: %s", url, exc)
                    continue
                if not str(node_ascan_id).isdigit():
                    logger.warning("ZAP ascan.scan() did not return a scan id for %s: %r", url, node_ascan_id)
                    continue
                self._wait_for(lambda sid=node_ascan_id: int(zap.ascan.status(sid)) >= 100, label=f"ascan:{url}")

            alerts = zap.core.alerts(baseurl=f"{urlsplit(scan_target).scheme}://{urlsplit(scan_target).netloc}")
            return self._normalize_alerts(alerts)
        except Exception as exc:
            logger.error("ZAP scan failed: %s", exc)
            return []

    def _wait_for(self, done_fn, label: str, poll_interval: float = 2.0) -> None:
        while time.monotonic() < self.deadline_ts:
            try:
                if done_fn():
                    return
            except Exception:
                return
            time.sleep(poll_interval)
        logger.info("ZAP %s stage stopped at deadline", label)

    def _normalize_alerts(self, alerts: list[dict]) -> list[Finding]:
        findings = []
        for alert in alerts:
            cweid = int(alert.get("cweid", -1) or -1)
            cwe = CWEID_MAP.get(cweid)
            if not cwe:
                continue  # out of scope for this scanner's CWE set
            url = self._to_public_url(alert.get("url", self.scan_target))
            param = alert.get("param") or None
            method = alert.get("method", "GET") or "GET"
            risk = alert.get("risk", "Low")
            confidence_str = alert.get("confidence", "Low")
            # ZAP "confirmed" maps to our confirmed/firm; everything weaker is
            # dropped by the normalizer stage downstream (tentative never exported).
            confidence = Confidence.CONFIRMED if confidence_str in ("High",) else Confidence.FIRM

            from discovery.injection_points import derive_route_template

            route_template = derive_route_template(urlparse(url).path)
            location = "query" if method.upper() == "GET" else "body"

            findings.append(
                Finding(
                    cwe=cwe,
                    title=alert.get("alert", cwe),
                    severity=RISK_TO_SEVERITY.get(risk, Severity.MEDIUM),
                    confidence=confidence,
                    method=method.upper(),
                    url=url,
                    route_template=route_template,
                    param=param,
                    param_location=location,
                    payload=alert.get("attack", ""),
                    technique="zap-active-scan",
                    evidence=Evidence(
                        matched=alert.get("evidence", ""),
                        response_excerpt=(alert.get("otherInfo") or "")[:500],
                    ),
                    scope="endpoint",
                    tool="owasp-zap",
                )
            )
        return findings
