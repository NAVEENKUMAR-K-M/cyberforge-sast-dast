"""SQL injection probe (CWE-89).

Tier 1 (always, ~3-5 requests): error-based -- send each special char and
match the response against known DB error signatures. A bare 500/diff is
never enough on its own (plan's decoy: an int-cast id param can 500 on
bad input without being injectable) -- an actual DB error string must
appear.

Tier 2 (only if tier-1 found nothing, and only when hinted or a weak
diff signal was seen): boolean-based pairs, then -- serially, as a last
resort -- a time-based payload, repeated once to rule out network jitter
before trusting it.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from core.models import Baseline, Confidence, Evidence, Finding, InjectionPoint, Severity
from core.request_manager import RequestManager
from discovery.baseline import is_similar_to_baseline
from scanners.probes.base import Probe
from scanners.probes.util import build_request, is_clean_request_noise, load_payloads
from verification.response_diff import boolean_pair_confirms

logger = logging.getLogger("dast.probes.sqli")

TIME_BASED_SLEEP_S = 4
TIME_BASED_MIN_DELTA_S = 2.5  # observed delay must exceed baseline + this


def _compile_signatures() -> list[re.Pattern]:
    sigs = load_payloads("db_error_signatures.yaml")
    patterns = []
    for group in sigs.values():
        for s in group:
            patterns.append(re.compile(re.escape(s), re.I))
    return patterns


class SqliProbe(Probe):
    cwe = "CWE-89"
    name = "sqli"

    def __init__(self):
        self._payloads = load_payloads("sqli.yaml")
        self._error_sigs = _compile_signatures()

    def _match_error(self, body: str) -> str | None:
        """Returns the actual matched text (not the pattern) so the
        caller can check for that exact phrase in a clean baseline too."""
        for pattern in self._error_sigs:
            m = pattern.search(body)
            if m:
                return m.group(0)
        return None

    async def detect(self, rm: RequestManager, point: InjectionPoint, baseline: Baseline | None, *, hinted: bool = False) -> list[Finding]:
        if point.param is None:
            return []

        # --- Tier 1: error-based ---
        for payload in self._payloads.get("error_based", []):
            url, kwargs = build_request(point, payload)
            resp = await rm.send(point.method, url, **kwargs)
            if resp is None:
                continue
            matched = self._match_error(resp.text)
            if matched and not await is_clean_request_noise(rm, point, matched):
                return [self._finding(point, payload, "error-based", Confidence.CONFIRMED, resp.status_code, matched, resp.text, baseline)]

        if baseline is None:
            return []  # can't do boolean/diff comparisons without one

        # --- Tier 1 (cont.): one cheap boolean pair ---
        pairs = self._payloads.get("boolean_pairs", [])
        weak_signal = False
        for i, pair in enumerate(pairs):
            if i > 0 and not (hinted or weak_signal):
                break  # tier-2: only try further pairs when there's a reason to
            true_url, true_kwargs = build_request(point, pair["true"])
            false_url, false_kwargs = build_request(point, pair["false"])
            true_resp = await rm.send(point.method, true_url, **true_kwargs)
            false_resp = await rm.send(point.method, false_url, **false_kwargs)
            if true_resp is None or false_resp is None:
                continue
            if boolean_pair_confirms(baseline, true_resp.text, true_resp.status_code, false_resp.text, false_resp.status_code):
                return [
                    self._finding(
                        point, f"true={pair['true']!r} false={pair['false']!r}", "boolean-based",
                        Confidence.CONFIRMED, true_resp.status_code, "", true_resp.text, baseline,
                    )
                ]
            if not is_similar_to_baseline(baseline, true_resp.text, true_resp.status_code):
                weak_signal = True  # true-payload already diverges -> worth a deeper look

        # --- Tier 2: time-based, serial, hinted only ---
        # weak_signal alone is deliberately NOT enough to trigger this: a
        # page's ordinary dynamic content (CSRF tokens, timestamps, ...)
        # can make a response "diverge from baseline" for reasons that
        # have nothing to do with SQL injection, and each time-based
        # attempt costs several seconds (2 sleeps x ~4s, serial). Across
        # many points that adds up fast enough to blow the whole scan's
        # time budget before later points are even reached -- confirmed
        # directly in testing. A SAST hint is a deliberate, specific
        # reason to pay that cost; an ambient diff on an unrelated page
        # is not.
        if hinted:
            finding = await self._time_based(rm, point, baseline)
            if finding:
                return [finding]

        return []

    async def _time_based(self, rm: RequestManager, point: InjectionPoint, baseline: Baseline) -> Finding | None:
        for template in self._payloads.get("time_based", []):
            payload = template.format(sleep=TIME_BASED_SLEEP_S)
            url, kwargs = build_request(point, payload)
            start = time.monotonic()
            resp = await rm.send(point.method, url, serial=True, **kwargs)
            elapsed = time.monotonic() - start
            if resp is None:
                continue
            if elapsed - baseline.elapsed < TIME_BASED_MIN_DELTA_S:
                continue
            # repeat once before trusting a timing signal -- jitter/load
            # spikes are common and a single slow response proves nothing
            start2 = time.monotonic()
            resp2 = await rm.send(point.method, url, serial=True, **kwargs)
            elapsed2 = time.monotonic() - start2
            if resp2 is None or elapsed2 - baseline.elapsed < TIME_BASED_MIN_DELTA_S:
                continue
            return self._finding(
                point, payload, "time-based", Confidence.FIRM, resp.status_code,
                f"delayed {elapsed:.1f}s / {elapsed2:.1f}s vs baseline {baseline.elapsed:.2f}s", "", baseline,
            )
        return None

    def _finding(self, point, payload, technique, confidence, status, matched, body_excerpt, baseline) -> Finding:
        return Finding(
            cwe=self.cwe,
            title="SQL Injection",
            severity=Severity.HIGH,
            confidence=confidence,
            method=point.method,
            url=point.url,
            route_template=point.route_template,
            param=point.param,
            param_location=point.param_location.value if hasattr(point.param_location, "value") else point.param_location,
            payload=payload,
            technique=technique,
            evidence=Evidence(
                matched=matched,
                response_excerpt=body_excerpt[:300],
                baseline_status=baseline.status if baseline else None,
                probe_status=status,
            ),
            tool="dast-engine",
        )

    async def verify(self, rm: RequestManager, method: str, url: str, route_template: str, param: str | None, param_location: str) -> Finding | None:
        from core.models import ParamLocation

        point = InjectionPoint(
            method=method, url=url, route_template=route_template, param=param or "",
            param_location=ParamLocation(param_location) if param_location else ParamLocation.QUERY,
        )
        findings = await self.detect(rm, point, baseline=None, hinted=True)
        if not findings:
            # error-based needs no baseline; retry with a fresh baseline for boolean/time-based
            from discovery.baseline import get_baseline

            baseline = await get_baseline(rm, method, url)
            findings = await self.detect(rm, point, baseline=baseline, hinted=True)
        return findings[0] if findings else None
