"""Establishes a baseline response per endpoint (not per injection point —
many params share one URL) so probes can diff against "normal" behaviour.

Two requests are made so that trivially dynamic content (timestamps,
CSRF tokens, request ids) can be detected and masked out of the word-set
hash used for similarity comparison.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from core.models import Baseline
from core.request_manager import RequestManager

_DYNAMIC_TOKEN_RE = re.compile(r"\b[0-9a-f]{8,}\b|\b\d{10,}\b", re.I)


def _normalize_body(body: str) -> str:
    """Strip tokens that change on every request so two legitimate responses
    to the same endpoint hash identically."""
    return _DYNAMIC_TOKEN_RE.sub("<dyn>", body)


def _word_hash(body: str) -> str:
    normalized = _normalize_body(body)
    return hashlib.sha1(normalized.encode("utf-8", "ignore")).hexdigest()


async def get_baseline(rm: RequestManager, method: str, url: str, **kwargs) -> Baseline | None:
    resp1 = await rm.send(method, url, **kwargs)
    if resp1 is None:
        return None
    resp2 = await rm.send(method, url, **kwargs)
    if resp2 is None:
        resp2 = resp1

    body1 = resp1.text
    body2 = resp2.text
    is_dynamic = _word_hash(body1) != _word_hash(body2) or resp1.status_code != resp2.status_code

    return Baseline(
        status=resp1.status_code,
        length=len(body1),
        word_hash=_word_hash(body1),
        elapsed=resp1.elapsed.total_seconds() if resp1.elapsed else 0.0,
        is_dynamic=is_dynamic,
        body_excerpt=body1[:500],
    )


def is_similar_to_baseline(baseline: Baseline, body: str, status: int) -> bool:
    if baseline.is_dynamic:
        # Can't trust exact hash match; fall back to status + rough length band.
        return status == baseline.status and abs(len(body) - baseline.length) < max(50, baseline.length * 0.05)
    return status == baseline.status and _word_hash(body) == baseline.word_hash
