"""Dedupe + confidence-tier filtering before final export.

Only 'confirmed' and 'firm' findings are exported (plan change #4);
'tentative' is reserved for internal use by probes that aren't fully sure
and want a second pass, but never reaches dast_results.json on its own.
"""
from __future__ import annotations

from core.models import Confidence, Finding

EXPORTABLE = {Confidence.CONFIRMED.value, Confidence.FIRM.value}


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Same finding_id -> keep the highest-confidence, most-recent one."""
    best: dict[str, Finding] = {}
    rank = {Confidence.CONFIRMED.value: 2, Confidence.FIRM.value: 1, Confidence.TENTATIVE.value: 0}

    for f in findings:
        fid = f.finding_id
        conf = f.confidence.value if isinstance(f.confidence, Confidence) else f.confidence
        existing = best.get(fid)
        if existing is None:
            best[fid] = f
            continue
        existing_conf = existing.confidence.value if isinstance(existing.confidence, Confidence) else existing.confidence
        if rank.get(conf, 0) > rank.get(existing_conf, 0):
            best[fid] = f
    return list(best.values())


def filter_exportable(findings: list[Finding]) -> list[Finding]:
    out = []
    for f in findings:
        conf = f.confidence.value if isinstance(f.confidence, Confidence) else f.confidence
        if conf in EXPORTABLE:
            out.append(f)
    return out
