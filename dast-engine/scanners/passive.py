"""App-level passive checks (change #2 in the plan): one finding per issue
class, not per URL. Each finding lists all affected URLs in evidence.extra.

Covers the 6 runtime-only CWEs from the PRD: missing headers (CWE-693 /
CWE-1021 / CWE-1004 / CWE-319-ish HSTS / CWE-1275 referrer), cookie flags
(CWE-614), CORS misconfig (CWE-942), info disclosure (CWE-200 / CWE-209),
directory listing (CWE-548), exposed VCS/env files (CWE-538), TRACE (CWE-650).
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from urllib.parse import urljoin

from core.models import Confidence, Evidence, Finding, Severity
from core.request_manager import RequestManager

logger = logging.getLogger("dast.passive")

STACK_TRACE_PATTERNS = [
    re.compile(r"Fatal error:.*on line \d+", re.I),
    re.compile(r"Warning:.*in .*\.php on line \d+", re.I),
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"System\.Exception", re.I),
    re.compile(r"at [\w.$]+\([\w.]+\.java:\d+\)", re.I),
    re.compile(r"org\.springframework", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
]

DB_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql_", re.I),
    re.compile(r"unterminated quoted string", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"ORA-\d{5}", re.I),
]


class PassiveScanner:
    def __init__(self, rm: RequestManager, scope_guard, base_url: str):
        self.rm = rm
        self.scope_guard = scope_guard
        self.base_url = base_url
        self._cookie_issue_urls: dict[str, set] = defaultdict(set)
        self._missing_header_urls: dict[str, set] = defaultdict(set)
        self._info_disclosure: dict[str, set] = defaultdict(set)
        self._cors_issue_urls: set = set()
        self._server_banners: set = set()

    def inspect_response(self, url: str, resp) -> None:
        """Called once per response already fetched elsewhere, to avoid
        extra requests. Accumulates evidence; call finalize() for findings."""
        if resp is None:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}

        header_checks = {
            "content-security-policy": "CWE-1021",
            "x-frame-options": "CWE-1021",
            "x-content-type-options": "CWE-693",
            "referrer-policy": "CWE-1275",
        }
        for header, _cwe in header_checks.items():
            if header not in headers:
                self._missing_header_urls[header].add(url)

        if url.startswith("https://") and "strict-transport-security" not in headers:
            self._missing_header_urls["strict-transport-security"].add(url)

        for cookie_header in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
            self._check_cookie(url, cookie_header)
        # httpx exposes raw set-cookie via .headers.multi_items() on some versions
        if hasattr(resp.headers, "multi_items"):
            for k, v in resp.headers.multi_items():
                if k.lower() == "set-cookie":
                    self._check_cookie(url, v)

        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        if acao == "*" and acac and acac.lower() == "true":
            self._cors_issue_urls.add((url, "wildcard-with-credentials"))
        elif acao and acao not in ("*", self.base_url):
            self._cors_issue_urls.add((url, f"reflects-origin:{acao}"))

        server = headers.get("server")
        xpowered = headers.get("x-powered-by")
        if server:
            self._server_banners.add(f"Server: {server}")
        if xpowered:
            self._server_banners.add(f"X-Powered-By: {xpowered}")

        body = resp.text if hasattr(resp, "text") else ""
        for pattern in STACK_TRACE_PATTERNS:
            if pattern.search(body):
                self._info_disclosure["stack_trace"].add(url)
                break
        for pattern in DB_ERROR_PATTERNS:
            if pattern.search(body):
                self._info_disclosure["db_error"].add(url)
                break
        if re.search(r"Index of /", body) or re.search(r"<title>Directory listing for", body, re.I):
            self._info_disclosure["directory_listing"].add(url)

    def _check_cookie(self, url: str, cookie_header: str) -> None:
        lower = cookie_header.lower()
        if "httponly" not in lower:
            self._cookie_issue_urls["missing_httponly"].add(url)
        if "secure" not in lower and self.base_url.startswith("https://"):
            self._cookie_issue_urls["missing_secure"].add(url)
        if "samesite" not in lower:
            self._cookie_issue_urls["missing_samesite"].add(url)

    async def check_first_visit_cookies(self, urls: list[str]) -> None:
        """Session cookies are set once, on a first visit, so a scan that already holds one
        never sees them again. Asks as a new visitor, so their flags can be checked."""
        for url in urls:
            resp = await self.rm.fresh_get(url)
            if resp is None:
                continue
            for key, value in resp.headers.multi_items():
                if key.lower() == "set-cookie":
                    self._check_cookie(url, value)

    async def active_checks(self) -> list[Finding]:
        """A handful of checks that need their own dedicated requests."""
        findings = []
        findings.extend(await self._check_sensitive_files())
        findings.extend(await self._check_trace())
        return findings

    async def _check_sensitive_files(self) -> list[Finding]:
        findings = []
        targets = {
            "/.git/HEAD": ("CWE-538", "Exposed .git directory", "ref:"),
            "/.env": ("CWE-538", "Exposed .env file", "="),
            "/backup.zip": ("CWE-538", "Exposed backup archive", None),
            "/web.config.bak": ("CWE-538", "Exposed backup config", None),
        }
        for path, (cwe, title, marker) in targets.items():
            url = urljoin(self.base_url, path)
            resp = await self.rm.get(url)
            if resp is None or resp.status_code != 200:
                continue
            if marker and marker not in resp.text:
                continue
            findings.append(
                Finding(
                    cwe=cwe,
                    title=title,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    method="GET",
                    url=url,
                    route_template=path,
                    param=None,
                    param_location=None,
                    evidence=Evidence(response_excerpt=resp.text[:200], probe_status=resp.status_code),
                    scope="app",
                )
            )
        return findings

    async def _check_trace(self) -> list[Finding]:
        findings = []
        resp = await self.rm.send("TRACE", self.base_url)
        if resp is not None and resp.status_code == 200 and "TRACE" in (resp.text or ""):
            findings.append(
                Finding(
                    cwe="CWE-650",
                    title="HTTP TRACE method enabled",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    method="TRACE",
                    url=self.base_url,
                    route_template="/",
                    param=None,
                    param_location=None,
                    evidence=Evidence(probe_status=resp.status_code),
                    scope="app",
                )
            )
        return findings

    def finalize(self) -> list[Finding]:
        findings: list[Finding] = []

        header_titles = {
            "content-security-policy": ("Missing Content-Security-Policy header", "CWE-1021", Severity.MEDIUM),
            "x-frame-options": ("Missing X-Frame-Options header", "CWE-1021", Severity.MEDIUM),
            "x-content-type-options": ("Missing X-Content-Type-Options header", "CWE-693", Severity.LOW),
            "referrer-policy": ("Missing Referrer-Policy header", "CWE-1275", Severity.LOW),
            "strict-transport-security": ("Missing Strict-Transport-Security header", "CWE-319", Severity.MEDIUM),
        }
        for header, urls in self._missing_header_urls.items():
            if not urls:
                continue
            title, cwe, severity = header_titles[header]
            findings.append(self._app_finding(cwe, title, severity, sorted(urls)))

        cookie_titles = {
            "missing_httponly": ("Session cookie missing HttpOnly flag", "CWE-1004", Severity.MEDIUM),
            "missing_secure": ("Session cookie missing Secure flag", "CWE-614", Severity.MEDIUM),
            "missing_samesite": ("Session cookie missing SameSite attribute", "CWE-1275", Severity.LOW),
        }
        for issue, urls in self._cookie_issue_urls.items():
            if not urls:
                continue
            title, cwe, severity = cookie_titles[issue]
            findings.append(self._app_finding(cwe, title, severity, sorted(urls)))

        if self._cors_issue_urls:
            urls = sorted({u for u, _ in self._cors_issue_urls})
            details = "; ".join(sorted({d for _, d in self._cors_issue_urls}))
            findings.append(
                self._app_finding(
                    "CWE-942",
                    "Permissive CORS configuration",
                    Severity.HIGH,
                    urls,
                    matched=details,
                )
            )

        if self._server_banners:
            findings.append(
                self._app_finding(
                    "CWE-200",
                    "Server/technology version disclosure",
                    Severity.LOW,
                    [self.base_url],
                    matched="; ".join(sorted(self._server_banners)),
                )
            )

        info_titles = {
            "stack_trace": ("Verbose error / stack trace disclosure", "CWE-209", Severity.MEDIUM),
            "db_error": ("Database error message disclosure", "CWE-209", Severity.MEDIUM),
            "directory_listing": ("Directory listing enabled", "CWE-548", Severity.LOW),
        }
        for issue, urls in self._info_disclosure.items():
            if not urls:
                continue
            title, cwe, severity = info_titles[issue]
            findings.append(self._app_finding(cwe, title, severity, sorted(urls)))

        return findings

    def _app_finding(self, cwe, title, severity, urls, matched="") -> Finding:
        return Finding(
            cwe=cwe,
            title=title,
            severity=severity,
            confidence=Confidence.FIRM,
            method="GET",
            url=urls[0],
            route_template="/",
            param=None,
            param_location=None,
            evidence=Evidence(matched=matched, extra={"affected_urls": urls[:50], "affected_count": len(urls)}),
            scope="app",
        )
