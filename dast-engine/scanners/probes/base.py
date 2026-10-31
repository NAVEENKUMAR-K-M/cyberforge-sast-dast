"""Probe interface shared by every CWE-specific detector.

Each probe owns one CWE end-to-end: it knows its own payloads, how to tell
a hit from noise, and how to grade its own confidence. The scheduler/runner
only needs to call detect() for every injection point and verify() on
demand (for the correlation engine's bonus B-1).

Tiering lives *inside* each probe's detect(), not in the scheduler: tier-1
(cheap, every point) always runs; tier-2 (deeper, slower) only runs when
tier-1 produced a signal worth confirming, or when a SAST hint flags this
exact (method, route, param) as worth the extra look. SAST hints only ever
add tier-2 effort -- a point never skips tier-1 because of what hints say.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import Baseline, Finding, InjectionPoint
from core.request_manager import RequestManager


class Probe(ABC):
    cwe: str = ""
    name: str = ""

    @abstractmethod
    async def detect(
        self,
        rm: RequestManager,
        point: InjectionPoint,
        baseline: Baseline | None,
        *,
        hinted: bool = False,
    ) -> list[Finding]:
        """Test one injection point. `hinted=True` means a SAST finding
        already flagged this exact point for this CWE -- spend tier-2
        effort more readily, but tier-1 always runs regardless."""
        raise NotImplementedError

    @abstractmethod
    async def verify(
        self,
        rm: RequestManager,
        method: str,
        url: str,
        route_template: str,
        param: str | None,
        param_location: str,
    ) -> Finding | None:
        """Re-test one specific point on demand (api.verify(), bonus B-1).
        Returns a Finding if the vulnerability reproduces, else None."""
        raise NotImplementedError
