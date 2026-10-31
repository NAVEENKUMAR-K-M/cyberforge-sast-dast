"""OS command injection probe (CWE-78).

Each payload combines a shell separator with a *computed* marker (an
arithmetic sum, not a fixed string) so a hit means the command actually
ran -- the sum only appears in the response if the separator broke out
into a new command; the raw payload text itself is never a valid match.
Both Unix and Windows separator/command styles are tried since the target
OS isn't known ahead of time. A sleep-based fallback (serial, tier-2
only) catches blind command injection where output isn't reflected.
"""
from __future__ import annotations

import logging
import re
import time

from core.models import Baseline, Confidence, Evidence, Finding, InjectionPoint, Severity
from core.request_manager import RequestManager
from scanners.probes.base import Probe
from scanners.probes.util import build_request, is_clean_request_noise, load_payloads, random_small_ints

logger = logging.getLogger("dast.probes.cmdi")

SLEEP_S = 4
SLEEP_MIN_DELTA_S = 2.5


class CmdiProbe(Probe):
    cwe = "CWE-78"
    name = "cmdi"

    def __init__(self):
        self._payloads = load_payloads("cmdi.yaml")

    def _tier1_payloads(self, a: int, b: int) -> list[str]:
        unix_cmd = self._payloads["unix_command_template"].format(a=a, b=b)
        payloads = []
        for sep in self._payloads.get("unix_separators", []):
            payloads.append(sep.format(cmd=unix_cmd) if "{cmd}" in sep else f"{sep}{unix_cmd}")
        win_cmd = self._payloads["windows_command_template"].format(a=a, b=b)
        for sep in self._payloads.get("windows_separators", []):
            payloads.append(f"{sep} {win_cmd}")
        return payloads

    async def detect(self, rm: RequestManager, point: InjectionPoint, baseline: Baseline | None, *, hinted: bool = False) -> list[Finding]:
        if point.param is None:
            return []

        a, b = random_small_ints()
        expected_sum = str(a + b)

        sum_re = re.compile(r"\b" + re.escape(expected_sum) + r"\b")
        for payload in self._tier1_payloads(a, b):
            url, kwargs = build_request(point, payload)
            resp = await rm.send(point.method, url, **kwargs)
            if resp is None:
                continue
            if sum_re.search(resp.text) and payload not in resp.text:
                # The sum could coincidentally already be on the page
                # (e.g. a line number, a price, a hash fragment) -- confirm
                # it's not also there on a clean, unmodified request before
                # trusting it (confirmed in testing: this happened on a
                # static page completely unrelated to the injected value).
                if not await is_clean_request_noise(rm, point, expected_sum):
                    return [self._finding(point, payload, "computed-marker", Confidence.CONFIRMED, resp.status_code, expected_sum, resp.text)]

        if baseline is not None and hinted:
            finding = await self._sleep_based(rm, point, baseline)
            if finding:
                return [finding]
        return []

    async def _sleep_based(self, rm: RequestManager, point: InjectionPoint, baseline: Baseline) -> Finding | None:
        unix_payload = f"; {self._payloads['sleep_unix_template'].format(sleep=SLEEP_S)}"
        win_payload = f"& {self._payloads['sleep_windows_template'].format(sleep_plus_one=SLEEP_S + 1)}"
        for payload in (unix_payload, win_payload):
            url, kwargs = build_request(point, payload)
            start = time.monotonic()
            resp = await rm.send(point.method, url, serial=True, **kwargs)
            elapsed = time.monotonic() - start
            if resp is None or elapsed - baseline.elapsed < SLEEP_MIN_DELTA_S:
                continue
            start2 = time.monotonic()
            resp2 = await rm.send(point.method, url, serial=True, **kwargs)
            elapsed2 = time.monotonic() - start2
            if resp2 is None or elapsed2 - baseline.elapsed < SLEEP_MIN_DELTA_S:
                continue
            return self._finding(
                point, payload, "time-based", Confidence.FIRM, resp.status_code,
                f"delayed {elapsed:.1f}s / {elapsed2:.1f}s vs baseline {baseline.elapsed:.2f}s", "",
            )
        return None

    def _finding(self, point, payload, technique, confidence, status, matched, body_excerpt) -> Finding:
        return Finding(
            cwe=self.cwe,
            title="OS Command Injection",
            severity=Severity.CRITICAL,
            confidence=confidence,
            method=point.method,
            url=point.url,
            route_template=point.route_template,
            param=point.param,
            param_location=point.param_location.value if hasattr(point.param_location, "value") else point.param_location,
            payload=payload,
            technique=technique,
            evidence=Evidence(matched=matched, response_excerpt=body_excerpt[:300], probe_status=status),
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
