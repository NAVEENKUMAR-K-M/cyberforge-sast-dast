"""Reflected/DOM XSS probe (CWE-79).

A single unique marker per injection point is sent in a handful of shapes
(bare, tag-wrapped, attribute-wrapped) and the probe classifies exactly
where it landed in the response: encoded (safe), or unencoded inside an
executable context (HTML body / attribute / script / URL attribute) ->
firm. Playwright confirmation (off by default) can upgrade firm -> confirmed
by actually checking the script ran; see verification/browser_verifier.py.
"""
from __future__ import annotations

import logging
import re

from core.models import Baseline, Confidence, Evidence, Finding, InjectionPoint, Severity
from core.request_manager import RequestManager
from scanners.probes.base import Probe
from scanners.probes.util import build_request, load_payloads, random_marker

logger = logging.getLogger("dast.probes.xss")


def _classify_context(body: str, payload: str) -> str | None:
    """Returns the reflection context if `payload` -- special characters
    intact -- survives verbatim in the response, else None.

    Checking the bare marker alone would be wrong: a correctly-escaped
    payload still leaves the plain alphanumeric marker text sitting
    inside the escaped entities (e.g. "&lt;dzabc123&gt;"), which proves
    nothing. Only a byte-for-byte match of the *payload itself* (angle
    brackets, quotes and all) means the app didn't encode it.
    """
    occurrences = [m.start() for m in re.finditer(re.escape(payload), body)]
    if not occurrences:
        return None

    for pos in occurrences:
        before = body[max(0, pos - 80): pos]

        last_script_open = before.rfind("<script")
        last_script_close = before.rfind("</script")
        if last_script_open != -1 and last_script_open > last_script_close:
            return "script"

        # The quote char, if any, is typically the payload's OWN leading
        # character (our templates are '"{marker}"' / "'{marker}'"), so
        # it's part of the match itself, not sitting in `before` -- the
        # quote is optional here, not required, right before the match.
        attr_match = re.search(r'[a-zA-Z-]+\s*=\s*["\']?$', before)
        if attr_match:
            return "attribute"

        # Outside script/attribute context, a bare quote reflected into
        # plain body *text* proves nothing -- quotes have no special
        # meaning there, only inside an attribute or script string.
        # Confirmed as a real false positive in testing: DVWA's own SQL
        # error message echoes the quote-wrapped payload back verbatim as
        # part of the error text, which is inert, not exploitable. Only a
        # surviving angle bracket can actually open a new tag in body text.
        if "<" in payload or ">" in payload:
            return "html_body"

    return None


def _renders_as_markup(resp) -> bool:
    """False when the browser treats the response as data, such as text/plain
    or JSON, so a reflected tag can't run. No Content-Type at all can still be
    sniffed as HTML, and XML can carry scripts, so both count as markup."""
    content_type = resp.headers.get("content-type", "").lower()
    return not content_type or "html" in content_type or "xml" in content_type


class XssProbe(Probe):
    cwe = "CWE-79"
    name = "xss"

    def __init__(self):
        self._payloads = load_payloads("xss.yaml")

    async def detect(self, rm: RequestManager, point: InjectionPoint, baseline: Baseline | None, *, hinted: bool = False) -> list[Finding]:
        if point.param is None:
            return []

        marker = random_marker()
        for template in self._payloads.get("marker_payloads", []):
            payload = template.format(marker=marker)
            url, kwargs = build_request(point, payload)
            resp = await rm.send(point.method, url, **kwargs)
            if resp is None or not _renders_as_markup(resp):
                continue
            context = _classify_context(resp.text, payload)
            if context:
                confidence = Confidence.FIRM
                return [
                    Finding(
                        cwe=self.cwe,
                        title=f"Reflected Cross-Site Scripting ({context} context)",
                        severity=Severity.HIGH,
                        confidence=confidence,
                        method=point.method,
                        url=url,
                        route_template=point.route_template,
                        param=point.param,
                        param_location=point.param_location.value if hasattr(point.param_location, "value") else point.param_location,
                        payload=payload,
                        technique=f"reflected-{context}",
                        evidence=Evidence(matched=marker, response_excerpt=resp.text[:300], probe_status=resp.status_code),
                        tool="dast-engine",
                    )
                ]
        return []

    async def verify(self, rm: RequestManager, method: str, url: str, route_template: str, param: str | None, param_location: str) -> Finding | None:
        from core.models import ParamLocation

        point = InjectionPoint(
            method=method, url=url, route_template=route_template, param=param or "",
            param_location=ParamLocation(param_location) if param_location else ParamLocation.QUERY,
        )
        findings = await self.detect(rm, point, baseline=None, hinted=True)
        return findings[0] if findings else None
