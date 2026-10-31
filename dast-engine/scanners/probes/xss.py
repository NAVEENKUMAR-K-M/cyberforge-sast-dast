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
from scanners.probes.util import build_request, load_payloads, random_marker, verify_point

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
        reflected = False
        hint = point.meta.get("payload_hint")  # a shape with {marker}, tried first
        for template in ([hint] if hint else []) + self._payloads.get("marker_payloads", []):
            payload = template.replace("{marker}", marker) if template == hint else template.format(marker=marker)
            url, kwargs = build_request(point, payload)
            resp = await rm.send(point.method, url, **kwargs)
            if resp is None or not _renders_as_markup(resp):
                continue
            reflected = reflected or marker in resp.text
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
                        url=point.url,  # the tested URL, keeping a selector like ?action=view
                        route_template=point.route_template,
                        param=point.param,
                        param_location=point.param_location.value if hasattr(point.param_location, "value") else point.param_location,
                        payload=payload,
                        technique=f"reflected-{context}",
                        evidence=Evidence(matched=marker, response_excerpt=resp.text[:300], probe_status=resp.status_code),
                        tool="dast-engine",
                    )
                ]
        if reflected and self._payloads.get("unquoted_attribute_payload"):
            found = await self._unquoted_attribute(rm, point, marker)
            if found:
                return [found]
        return []

    async def _unquoted_attribute(self, rm: RequestManager, point: InjectionPoint, marker: str) -> Finding | None:
        payload = self._payloads["unquoted_attribute_payload"].format(marker=marker)
        url, kwargs = build_request(point, payload)
        resp = await rm.send(point.method, url, **kwargs)
        if resp is None or not _renders_as_markup(resp):
            return None
        for hit in re.finditer(re.escape(payload), resp.text):
            if re.search(r"[a-zA-Z-]+\s*=\s*$", resp.text[max(0, hit.start() - 80): hit.start()]):
                return Finding(
                    cwe=self.cwe,
                    title="Reflected Cross-Site Scripting (unquoted attribute context)",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    method=point.method,
                    url=point.url,
                    route_template=point.route_template,
                    param=point.param,
                    param_location=point.param_location.value if hasattr(point.param_location, "value") else point.param_location,
                    payload=payload,
                    technique="reflected-attribute_unquoted",
                    evidence=Evidence(matched=marker, response_excerpt=resp.text[:300], probe_status=resp.status_code),
                    tool="dast-engine",
                )
        return None

    async def verify(self, rm: RequestManager, method: str, url: str, route_template: str, param: str | None, param_location: str, fields: dict | None = None, hint: str | None = None) -> Finding | None:
        point = verify_point(method, url, route_template, param, param_location, fields, hint)
        findings = await self.detect(rm, point, baseline=None, hinted=True)
        return findings[0] if findings else None
