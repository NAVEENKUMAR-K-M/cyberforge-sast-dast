"""Open redirect probe (CWE-601).

Points the target param at a canary domain that will never resolve to
anything real, then checks the Location header, a meta-refresh tag, and
any window.location/assignment in the body for that same canary host --
never following the redirect (RequestManager already disables that).
Tier-1 hint: only parameters whose name suggests a redirect target
(url/next/redirect/return/...) get this probe at all, which keeps the
per-point cost near zero on everything else -- this never *skips* a
genuinely named redirect param, it just orders work sensibly.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from core.models import Baseline, Confidence, Evidence, Finding, InjectionPoint, Severity
from core.request_manager import RequestManager
from scanners.probes.base import Probe
from scanners.probes.util import build_request, load_payloads

logger = logging.getLogger("dast.probes.open_redirect")

REDIRECT_PARAM_HINTS = re.compile(r"(url|next|redirect|return|dest|continue|target|out|link)", re.I)


class OpenRedirectProbe(Probe):
    cwe = "CWE-601"
    name = "open_redirect"

    def __init__(self):
        self._payloads = load_payloads("open_redirect.yaml")
        self._canary = self._payloads.get("canary_host", "dast-canary.invalid")

    def is_relevant(self, point: InjectionPoint) -> bool:
        return bool(point.param and REDIRECT_PARAM_HINTS.search(point.param))

    def _points_at_canary(self, target: str) -> bool:
        """True only if `target`, parsed as a URL, actually resolves to the
        canary *host* -- not just contains the canary text somewhere in an
        otherwise same-origin path. A leading backslash is normalized to a
        slash first since browsers treat "/\\host" as protocol-relative
        the same way they treat "//host"."""
        normalized = target.replace("\\", "/")
        netloc = urlparse(normalized).netloc
        return self._canary in netloc

    async def detect(self, rm: RequestManager, point: InjectionPoint, baseline: Baseline | None, *, hinted: bool = False) -> list[Finding]:
        if point.param is None:
            return []
        if not (hinted or self.is_relevant(point)):
            return []  # not skipped for a hinted/named param; just not tried blindly on everything

        for template in self._payloads.get("payload_templates", []):
            payload = template.format(canary=self._canary)
            url, kwargs = build_request(point, payload)
            resp = await rm.send(point.method, url, allow_redirect_follow_once=False, **kwargs)
            if resp is None:
                continue

            location = resp.headers.get("location", "")
            if self._points_at_canary(location):
                return [self._finding(point, payload, "location-header", location, resp.status_code)]

            if resp.status_code < 400:
                body = resp.text
                meta_match = re.search(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>]+)', body, re.I)
                if meta_match and self._points_at_canary(meta_match.group(1)):
                    return [self._finding(point, payload, "meta-refresh", meta_match.group(0), resp.status_code)]
                js_match = re.search(r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']*' + re.escape(self._canary) + r'[^"\']*)["\']', body)
                if js_match and self._points_at_canary(js_match.group(1)):
                    return [self._finding(point, payload, "js-location", js_match.group(0), resp.status_code)]
        return []

    def _finding(self, point, payload, technique, matched, status) -> Finding:
        return Finding(
            cwe=self.cwe,
            title="Open Redirect",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            method=point.method,
            url=point.url,
            route_template=point.route_template,
            param=point.param,
            param_location=point.param_location.value if hasattr(point.param_location, "value") else point.param_location,
            payload=payload,
            technique=technique,
            evidence=Evidence(matched=matched, probe_status=status),
            tool="dast-engine",
        )

    async def verify(self, rm: RequestManager, method: str, url: str, route_template: str, param: str | None, param_location: str) -> Finding | None:
        from core.models import ParamLocation

        point = InjectionPoint(
            method=method, url=url, route_template=route_template, param=param or "",
            param_location=ParamLocation(param_location) if param_location else ParamLocation.QUERY,
        )
        findings = await self.detect(rm, point, baseline=None, hinted=True)
        return findings[0] if findings else None
