"""Shared data models used across the DAST engine.

These mirror the finding schema in results/schema.json so every module
(discovery, scanners, api.verify) produces/consumes the same shapes.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    JSON = "json"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"  # never exported to final output


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class InjectionPoint:
    """One testable (method, url, param) tuple discovered via crawl/route-map/OpenAPI."""

    method: str
    url: str
    route_template: str
    param: str
    param_location: ParamLocation
    seed_value: str = ""
    # extra context carried from SAST hints or OpenAPI, e.g. {"type": "integer"}
    meta: dict = field(default_factory=dict)
    # body template for POST/JSON requests (the other fields besides `param`)
    body_template: Optional[dict] = None
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)

    def key(self) -> str:
        return f"{self.method}|{self.route_template}|{self.param}|{self.param_location.value}"


@dataclass
class Baseline:
    status: int
    length: int
    word_hash: str
    elapsed: float
    is_dynamic: bool = False
    body_excerpt: str = ""


@dataclass
class Evidence:
    request: str = ""
    response_excerpt: str = ""
    matched: str = ""
    baseline_status: Optional[int] = None
    probe_status: Optional[int] = None
    extra: dict = field(default_factory=dict)


@dataclass
class Finding:
    cwe: str
    title: str
    severity: Severity
    confidence: Confidence
    method: str
    url: str
    route_template: str
    param: Optional[str]
    param_location: Optional[str]
    payload: str = ""
    technique: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    scope: str = "endpoint"  # "endpoint" | "app"
    source: str = "dast"
    tool: str = "dast-engine"
    timestamp: float = field(default_factory=time.time)

    @property
    def finding_id(self) -> str:
        """Stable id per FR-6: identical across re-runs for the same bug.

        Deliberately excludes payload/timestamp/evidence so re-scans dedupe
        to the same id even if the exact payload text differs.

        App-scope findings (scope="app": missing headers, cookie flags,
        ...) additionally include `title`. Without it, two genuinely
        different checks that happen to share one CWE code (e.g. missing
        Referrer-Policy and missing SameSite both map to CWE-1275) would
        collide onto the same id and silently drop one from the output --
        this was caught by exactly that collision. Endpoint-scope findings
        deliberately stay CWE/route/param/location only: their title can
        vary by run for the same underlying bug (XSS's title includes the
        reflection context classified that run), so including it there
        would break the very stability this id exists for.
        """
        parts = [
            self.cwe,
            self.method.upper(),
            self.route_template,
            self.param or "",
            self.param_location or "",
        ]
        if self.scope == "app":
            parts.append(self.title)
        basis = "|".join(parts)
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "source": self.source,
            "tool": self.tool,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else self.confidence,
            "method": self.method,
            "url": self.url,
            "route_template": self.route_template,
            "param": self.param,
            "param_location": self.param_location,
            "payload": self.payload,
            "technique": self.technique,
            "evidence": {
                "request": self.evidence.request,
                "response_excerpt": self.evidence.response_excerpt,
                "matched": self.evidence.matched,
                "baseline_status": self.evidence.baseline_status,
                "probe_status": self.evidence.probe_status,
                **self.evidence.extra,
            },
            "scope": self.scope,
            "timestamp": self.timestamp,
        }
