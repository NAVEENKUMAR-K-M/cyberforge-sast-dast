"""The output format shared with the correlator. See docs/finding-format.md."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

CONFIDENCE = ("high", "medium", "low")
LOCATIONS = ("query", "body", "json", "any", "cookie", "header", "path", "file", "session", "unknown")


@dataclass
class Param:
    name: str
    location: str
    value: str | None = None

    def key(self):
        return (self.name, self.location, self.value)

    def to_json(self):
        out = {"name": self.name, "location": self.location}
        if self.value is not None:
            out["value"] = self.value
        return out


@dataclass
class Route:
    path: str
    selector: str | None = None
    kind: str = "file"  # file | selector | framework
    methods: set = field(default_factory=set)
    aliases: list = field(default_factory=list)
    handler_file: str = ""
    handler_function: str = "<top-level>"
    start_line: int = 1
    end_line: int = 1
    params: dict = field(default_factory=dict)
    required: dict = field(default_factory=dict)
    form_fields: list = field(default_factory=list)

    @property
    def id(self) -> str:
        return hashlib.sha1(f"{self.path}|{self.selector or ''}".encode()).hexdigest()[:12]

    def to_json(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "methods": sorted(self.methods) or ["GET"],
            "path": self.path,
            "aliases": self.aliases,
            "selector": self.selector,
            "handler": {
                "file": self.handler_file,
                "function": self.handler_function,
                "start_line": self.start_line,
                "end_line": self.end_line,
            },
            "params": [p.to_json() for p in sorted(self.params.values(), key=lambda p: p.name)],
            "required_params": [p.to_json() for p in sorted(self.required.values(), key=lambda p: p.name)],
            "form_fields": self.form_fields,
        }

    def ref(self):
        return {
            "id": self.id,
            "methods": sorted(self.methods) or ["GET"],
            "path": self.path,
            "selector": self.selector,
        }


@dataclass
class Finding:
    fingerprint: str
    cwe: int
    cwe_family: int
    title: str
    severity: str
    confidence: str
    file: str
    line: int
    snippet: str
    function: str
    sink: str
    status: str = "open"  # open | suppressed
    suppression_reason: str | None = None
    source_params: dict = field(default_factory=dict)
    trace: list = field(default_factory=list)
    routes: dict = field(default_factory=dict)
    conditions: list = field(default_factory=list)
    stored_flow: dict | None = None
    engines: set = field(default_factory=set)

    def to_json(self):
        return {
            "fingerprint": self.fingerprint,
            "tool": "sast",
            "cwe": f"CWE-{self.cwe}",
            "cwe_family": f"CWE-{self.cwe_family}",
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "function": self.function,
            "sink": self.sink,
            "status": self.status,
            "suppression_reason": self.suppression_reason,
            "source_params": [p.to_json() for p in sorted(self.source_params.values(), key=lambda p: p.name)],
            "trace": self.trace,
            "routes": [r.ref() for r in sorted(self.routes.values(), key=lambda r: (r.path, r.selector or ""))],
            "conditions": sorted(self.conditions),
            "stored_flow": self.stored_flow,
            "engines": sorted(self.engines),
        }


def fingerprint(cwe_family: int, file: str, function: str, expression: str) -> str:
    """Stable across edits and rescans: no line numbers, whitespace ignored."""
    normal = re.sub(r"\s+", "", expression)
    raw = f"{cwe_family}|{file}|{function}|{normal}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    language: str
    source_root: str
    web_root: str
    routes: list
    findings: list
    stats: dict = field(default_factory=dict)
