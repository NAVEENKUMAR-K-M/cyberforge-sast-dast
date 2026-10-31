"""Probe interface shared by every active-detection backend.

A Probe takes the injection-point list + baselines and returns Findings.
`verify()` re-checks one specific (cwe, method, route, param) tuple on
demand — this is what api.verify() exposes to the correlation engine for
bonus B-1 (upgrading a code-only finding to Confirmed).
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import Finding, InjectionPoint


class Probe(ABC):
    cwe: str = ""
    name: str = ""

    @abstractmethod
    async def run(self, points: list[InjectionPoint], baselines: dict, deadline_aware: bool = True) -> list[Finding]:
        """Run this probe's checks across all relevant injection points."""
        raise NotImplementedError

    @abstractmethod
    async def verify(self, method: str, url: str, route_template: str, param: str, param_location: str) -> Finding | None:
        """Re-test one specific point on demand. Returns a Finding if the
        vulnerability still reproduces, else None."""
        raise NotImplementedError
