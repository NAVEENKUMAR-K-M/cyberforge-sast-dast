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
"""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

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
ACTIVE_SCAN_PLUGIN_IDS = [
    "40018",  # SQL Injection
    "40019",  # SQL Injection - MySQL
    "40020",  # SQL Injection - Hypersonic
    "40021",  # SQL Injection - Oracle
    "40022",  # SQL Injection - PostgreSQL
    "40024",  # SQL Injection - SQLite
    "40012",  # XSS Reflected
    "40014",  # XSS Persistent
    "40026",  # XSS DOM
    "90020",  # Remote OS Command Injection
    "6",      # Path Traversal
    "7",      # Remote File Inclusion
    "10044",  # Open Redirect
]


class ZapRunner:
    def __init__(self, zap_api_url: str, target: str, deadline_ts: float, denylist_patterns: list[str] | None = None):
        self.zap_api_url = zap_api_url.rstrip("/")
        self.target = target
        self.deadline_ts = deadline_ts
        self.denylist_patterns = denylist_patterns or []
        self._zap = None

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
        try:
            for pattern in self.denylist_patterns:
                zap.core.exclude_from_proxy(regex=f".*{pattern}.*")

            if cookies:
                cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
                zap.replacer.add_rule(
                    description="dast-session",
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex=False,
                    matchstring="Cookie",
                    replacement=cookie_header,
                )

            for url in seed_urls:
                try:
                    zap.core.access_url(url=url, followredirects=True)
                except Exception:
                    continue

            spider_id = zap.spider.scan(self.target)
            self._wait_for(lambda: int(zap.spider.status(spider_id)) >= 100, label="spider")

            zap.ascan.disable_all_scanners()
            for pid in ACTIVE_SCAN_PLUGIN_IDS:
                try:
                    zap.ascan.enable_scanners(pid)
                except Exception:
                    pass

            ascan_id = zap.ascan.scan(self.target)
            self._wait_for(lambda: int(zap.ascan.status(ascan_id)) >= 100, label="ascan")

            alerts = zap.core.alerts(baseurl=self.target)
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
            url = alert.get("url", self.target)
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
