"""Allocates the 150s DAST budget across phases and enforces the deadline.

With active-injection detection delegated to ZAP/Nuclei (which run their
own internal tiering), this scheduler's job is phase-level time budgeting:
give discovery+baseline enough time to find everything, give the active
backend the remainder, and always keep the last `report_reserve_s` free.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

logger = logging.getLogger("dast.scheduler")


@dataclass
class PhaseBudget:
    discovery_s: float
    passive_s: float
    active_s: float
    report_reserve_s: float


def allocate(total_budget_s: float, report_reserve_s: float = 15.0) -> PhaseBudget:
    """Default split: 20% discovery, 10% passive, 70% active (the active
    backend is where most of the scoring weight — SQLi/XSS/etc — lives)."""
    usable = max(0.0, total_budget_s - report_reserve_s)
    return PhaseBudget(
        discovery_s=usable * 0.20,
        passive_s=usable * 0.10,
        active_s=usable * 0.70,
        report_reserve_s=report_reserve_s,
    )


class DeadlineTimer:
    def __init__(self, total_s: float):
        self.start = time.monotonic()
        self.total_s = total_s

    def elapsed(self) -> float:
        return time.monotonic() - self.start

    def remaining(self) -> float:
        return max(0.0, self.total_s - self.elapsed())

    def expired(self) -> bool:
        return self.remaining() <= 0

    def phase_deadline(self, phase_s: float) -> float:
        """Absolute monotonic deadline for a phase, clipped to total budget."""
        return min(time.monotonic() + phase_s, self.start + self.total_s)
