"""Light stored-content check (plan change #8): submit a unique, inert
marker string through every POST form, then re-fetch the crawled GET pages
looking for that marker. This only tracks whether *user-controlled input
persists and is echoed back* (the prerequisite for stored XSS) — it never
submits a script payload itself. Confirmation that an unencoded/executable
reflection is exploitable is left to the ZAP/Nuclei active pass, which will
independently flag the same route if it's really exploitable.
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

from core.models import Confidence, Evidence, Finding, Severity
from core.request_manager import RequestManager
from discovery.crawler import CrawledForm
from discovery.injection_points import derive_route_template
from scanners.probes.xss import _renders_as_markup
from urllib.parse import urlparse

logger = logging.getLogger("dast.stored_marker")


@dataclass
class MarkerSubmission:
    form: "CrawledForm | ApiWrite"
    field: str
    marker: str


@dataclass
class ApiWrite:
    """A write endpoint that isn't an HTML form: a JSON or form body sent to a URL the route map or an API
    document named. Shaped like a form so the persistence check can treat both alike."""
    action: str
    method: str
    location: str  # "json" or "body"


# Parameter types a marker can't be stored in.
_UNTEXT = {"integer", "number", "boolean", "uuid", "enum", "validated"}


async def submit_markers(rm: RequestManager, forms: list[CrawledForm]) -> list[MarkerSubmission]:
    submissions = []
    for form in forms:
        if form.method != "POST":
            continue
        text_fields = [name for name, t in form.field_types.items() if t in ("text", "textarea", "email")]
        if not text_fields:
            continue
        # One marker per field, so a match names the one field that persisted
        # and the correlator can compare it with a real parameter name.
        markers = {field: f"dastmark{secrets.token_hex(6)}" for field in text_fields}
        resp = await rm.post(form.action, data={**form.fields, **markers})
        if resp is not None:
            submissions.extend(MarkerSubmission(form=form, field=field, marker=marker) for field, marker in markers.items())
    return submissions


async def submit_point_markers(rm: RequestManager, points: list, skip_methods=frozenset()) -> list[MarkerSubmission]:
    """The same marker idea for API writes: one request per endpoint, a unique marker in each text field."""
    from collections import defaultdict

    groups: dict = defaultdict(list)
    for point in points:
        location = point.param_location.value if hasattr(point.param_location, "value") else str(point.param_location)
        if point.method.upper() in ("POST", "PUT", "PATCH") and point.method.upper() not in skip_methods                 and location in ("json", "body") and point.meta.get("type") not in _UNTEXT:
            groups[(point.method.upper(), point.baseline_url, location)].append(point)
    submissions = []
    for (method, url, location), members in groups.items():
        markers = {point.param: f"dastmark{secrets.token_hex(6)}" for point in members}
        first = members[0]
        siblings = {**(first.body_template or {}), **markers}
        kwargs = {"json": siblings} if location == "json" else {"data": {**first.body_extras, **siblings}}
        if first.query_extras:
            kwargs["params"] = dict(first.query_extras)
        resp = await rm.send(method, url, **kwargs)
        if resp is not None:
            write = ApiWrite(url, method, location)
            submissions.extend(MarkerSubmission(form=write, field=name, marker=marker) for name, marker in markers.items())
    return submissions


async def check_persistence(rm: RequestManager, submissions: list[MarkerSubmission], recheck_urls: list[str]) -> list[Finding]:
    findings = []
    pages = {}
    for sub in submissions:
        for url in recheck_urls:
            if url not in pages:
                pages[url] = await rm.get(url)
            resp = pages[url]
            if resp is None or not _renders_as_markup(resp):
                continue  # a marker echoed in JSON or plain text can't run in a browser
            if sub.marker in resp.text:
                findings.append(
                    Finding(
                        cwe="CWE-79",
                        title="User-controlled input persists and is echoed back (stored-content candidate)",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        method=getattr(sub.form, "method", "POST"),
                        url=sub.form.action,
                        route_template=derive_route_template(urlparse(sub.form.action).path),
                        param=sub.field,
                        param_location=getattr(sub.form, "location", "body"),
                        payload=sub.marker,
                        technique="stored-marker",
                        evidence=Evidence(matched=sub.marker, response_excerpt=resp.text[:300], extra={"echoed_at": url}),
                        scope="endpoint",
                    )
                )
                break
    return findings
