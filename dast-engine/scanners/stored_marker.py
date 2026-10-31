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
from urllib.parse import urlparse

logger = logging.getLogger("dast.stored_marker")


@dataclass
class MarkerSubmission:
    form: CrawledForm
    field: str
    marker: str


async def submit_markers(rm: RequestManager, forms: list[CrawledForm]) -> list[MarkerSubmission]:
    submissions = []
    for form in forms:
        if form.method != "POST":
            continue
        text_fields = [name for name, t in form.field_types.items() if t in ("text", "textarea", "email")]
        if not text_fields:
            continue
        marker = f"dastmark{secrets.token_hex(6)}"
        data = dict(form.fields)
        for field in text_fields:
            data[field] = marker
        resp = await rm.post(form.action, data=data)
        if resp is not None:
            submissions.append(MarkerSubmission(form=form, field=",".join(text_fields), marker=marker))
    return submissions


async def check_persistence(rm: RequestManager, submissions: list[MarkerSubmission], recheck_urls: list[str]) -> list[Finding]:
    findings = []
    for sub in submissions:
        for url in recheck_urls:
            resp = await rm.get(url)
            if resp is None:
                continue
            if sub.marker in resp.text:
                findings.append(
                    Finding(
                        cwe="CWE-79",
                        title="User-controlled input persists and is echoed back (stored-content candidate)",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        method="POST",
                        url=sub.form.action,
                        route_template=derive_route_template(urlparse(sub.form.action).path),
                        param=sub.field,
                        param_location="body",
                        payload=sub.marker,
                        technique="stored-marker",
                        evidence=Evidence(matched=sub.marker, response_excerpt=resp.text[:300], extra={"echoed_at": url}),
                        scope="endpoint",
                    )
                )
                break
    return findings
