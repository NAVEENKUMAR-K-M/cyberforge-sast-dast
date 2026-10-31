"""Optional, lighter-weight active scanner backend using the `nuclei` CLI
(off by default; selected via config `active_backend: nuclei`).

Nuclei's own community DAST templates own the payloads; this module only
invokes the binary, reads its JSONL output, and maps each hit back onto an
InjectionPoint (so route_template/param/location attribution stays exact)
by diffing the matched URL's query string against the point's seed value.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from core.models import Confidence, Evidence, Finding, InjectionPoint, Severity

logger = logging.getLogger("dast.nuclei_runner")

TAG_TO_CWE = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "rce": "CWE-78",
    "cmdi": "CWE-78",
    "lfi": "CWE-22",
    "redirect": "CWE-601",
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def is_available() -> bool:
    return shutil.which("nuclei") is not None


def _diff_param(original_url: str, matched_url: str) -> str | None:
    orig_qs = parse_qs(urlparse(original_url).query)
    matched_qs = parse_qs(urlparse(matched_url).query)
    for name, values in matched_qs.items():
        if orig_qs.get(name) != values:
            return name
    extra = set(matched_qs) - set(orig_qs)
    if extra:
        return next(iter(extra))
    return None


async def run(
    points: list[InjectionPoint],
    rate_limit: int,
    deadline_remaining_s: float,
) -> list[Finding]:
    if not is_available():
        logger.warning("nuclei binary not found on PATH; skipping nuclei pass")
        return []

    get_points = [p for p in points if p.method.upper() == "GET"]
    urls = sorted({p.url for p in get_points})
    if not urls:
        return []

    with tempfile.TemporaryDirectory() as tmp:
        url_file = Path(tmp) / "urls.txt"
        out_file = Path(tmp) / "out.jsonl"
        url_file.write_text("\n".join(urls), encoding="utf-8")

        cmd = [
            "nuclei",
            "-l", str(url_file),
            "-dast",
            "-tags", ",".join(TAG_TO_CWE.keys()),
            "-jsonl",
            "-o", str(out_file),
            "-rate-limit", str(max(1, rate_limit)),
            "-timeout", "10",
            "-no-color",
            "-silent",
            "-disable-update-check",
        ]
        timeout_s = max(5.0, deadline_remaining_s)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout_s)
        except asyncio.TimeoutError:
            logger.info("nuclei run hit the deadline; killing and using partial output")
            proc.kill()
        except Exception as exc:
            logger.error("Failed to run nuclei: %s", exc)
            return []

        if not out_file.exists():
            return []
        lines = out_file.read_text(encoding="utf-8", errors="ignore").splitlines()

    url_to_point: dict[str, InjectionPoint] = {p.url: p for p in get_points}
    findings: list[Finding] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = rec.get("info", {})
        tags = [t.lower() for t in info.get("tags", [])]
        cwe = next((TAG_TO_CWE[t] for t in tags if t in TAG_TO_CWE), None)
        if not cwe:
            continue

        matched_url = rec.get("matched-at") or rec.get("host") or ""
        base_point = None
        base_path = urlparse(matched_url).path
        for p in get_points:
            if urlparse(p.url).path == base_path:
                base_point = p
                break

        param = _diff_param(base_point.url, matched_url) if base_point else None
        route_template = base_point.route_template if base_point else base_path

        findings.append(
            Finding(
                cwe=cwe,
                title=info.get("name", cwe),
                severity=SEVERITY_MAP.get(info.get("severity", "medium"), Severity.MEDIUM),
                confidence=Confidence.FIRM,
                method="GET",
                url=matched_url,
                route_template=route_template,
                param=param or (base_point.param if base_point else None),
                param_location="query",
                payload=(rec.get("extracted-results") or [""])[0] if rec.get("extracted-results") else "",
                technique="nuclei-dast",
                evidence=Evidence(matched=rec.get("matcher-name", ""), extra={"template-id": rec.get("template-id")}),
                scope="endpoint",
                tool="nuclei",
            )
        )
    return findings
