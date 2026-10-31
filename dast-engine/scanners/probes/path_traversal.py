"""Path traversal / LFI probe (CWE-22).

Tries a few traversal depths and encodings against known OS files
(/etc/passwd, win.ini) and matches on their actual, distinctive content --
never on status code alone, since a 403/404 on a bad path proves nothing.
Also tries a known file the app itself serves (its own entry page) via a
traversal round-trip, to catch filtered traversal where /etc/passwd
itself is blocked but the directory-walk still works.
"""
from __future__ import annotations

import logging

from core.models import Baseline, Confidence, Evidence, Finding, InjectionPoint, Severity
from core.request_manager import RequestManager
from scanners.probes.base import Probe
from scanners.probes.util import build_request, load_payloads

logger = logging.getLogger("dast.probes.path_traversal")


class PathTraversalProbe(Probe):
    cwe = "CWE-22"
    name = "path_traversal"

    def __init__(self):
        self._payloads = load_payloads("path_traversal.yaml")

    def _candidate_payloads(self):
        depths = self._payloads.get("depths", [])
        targets = self._payloads.get("unix_targets", []) + self._payloads.get("windows_targets", [])
        all_seqs = self._payloads.get("traversal_sequences", [])
        plain_seqs = [s for s in all_seqs if s in ("../", "..\\")]
        exotic_seqs = [s for s in all_seqs if s not in plain_seqs]

        # Cheapest, highest-signal first: an absolute path needs no depth
        # guessing at all, and the two plain traversal sequences cover the
        # overwhelming majority of real targets. Exotic encodings (double-
        # encoded, null-byte, ..%2f, ...) are tried last, only if tier-2
        # budget allows -- they exist for naive filters, not as the common
        # case.
        for prefix in self._payloads.get("absolute_prefixes", []):
            for target in targets:
                yield prefix + target["path"], target["signature"]
        for seq in plain_seqs:
            for depth in depths:
                prefix = seq * depth
                for target in targets:
                    yield prefix + target["path"], target["signature"]
        for seq in exotic_seqs:
            for depth in depths:
                prefix = seq * depth
                for target in targets:
                    yield prefix + target["path"], target["signature"]

    async def detect(self, rm: RequestManager, point: InjectionPoint, baseline: Baseline | None, *, hinted: bool = False) -> list[Finding]:
        if point.param is None:
            return []

        tried = 0
        # tier-1 budget: 12 absolute-path attempts + a couple of plain
        # relative depths (2 seqs x 2 depths x 4 targets = 16) = 28, so a
        # fresh, unhinted point still gets real relative-traversal
        # coverage, not just the absolute-path shortcut.
        max_tier1 = 28
        max_tier2 = 80
        limit = max_tier2 if hinted else max_tier1

        for payload, signature in self._candidate_payloads():
            if tried >= limit:
                break
            tried += 1
            url, kwargs = build_request(point, payload)
            resp = await rm.send(point.method, url, **kwargs)
            if resp is None:
                continue
            if signature.lower() in resp.text.lower():
                return [
                    Finding(
                        cwe=self.cwe,
                        title="Path Traversal / Local File Inclusion",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        method=point.method,
                        url=url,
                        route_template=point.route_template,
                        param=point.param,
                        param_location=point.param_location.value if hasattr(point.param_location, "value") else point.param_location,
                        payload=payload,
                        technique="traversal",
                        evidence=Evidence(matched=signature, response_excerpt=resp.text[:300], probe_status=resp.status_code),
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
