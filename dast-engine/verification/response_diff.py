"""Response-diffing helpers shared by passive checks and any probe/backend
that needs to compare a response against the endpoint's baseline.
"""
from __future__ import annotations

from core.models import Baseline
from discovery.baseline import is_similar_to_baseline


def diff_status(baseline: Baseline, status: int) -> bool:
    """True if status differs from baseline (a necessary, not sufficient,
    signal — a decoy int-cast param can 500 on bad input without being
    SQL-injectable, so this alone must never be treated as a finding)."""
    return status != baseline.status


def diff_body(baseline: Baseline, body: str, status: int) -> bool:
    return not is_similar_to_baseline(baseline, body, status)


def boolean_pair_confirms(
    baseline: Baseline, true_body: str, true_status: int, false_body: str, false_status: int
) -> bool:
    """Classic boolean-based confirmation: TRUE payload ~= baseline, FALSE
    payload != baseline. Both conditions must hold."""
    true_matches = is_similar_to_baseline(baseline, true_body, true_status)
    false_matches = is_similar_to_baseline(baseline, false_body, false_status)
    return true_matches and not false_matches
