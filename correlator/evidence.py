"""What a runtime finding actually shows.

A technique name or the scanner's own confidence tier is not evidence. Each check below reads the
recorded payload and response, and says why the finding passed or fell short. It decides one thing:
does the recorded evidence show the weakness itself, or only that the input reached something?

Levels, weakest to strongest:
- none:       no runtime evidence at all;
- unchecked:  there is runtime evidence, but no check for this kind of weakness;
- partial:    the input reached the target, but exploitation isn't shown (a database error, a marker
              reflected where it wouldn't run);
- validated:  the recorded evidence shows the weakness itself.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

LEVELS = ["none", "unchecked", "partial", "validated"]

# The same margin the scanners use before they trust a delay.
MIN_DELAY_S = 2.5
FILE_SIGNATURES = (re.compile(r"root:[^:\n]*:0:0:"), re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I))
RUNS_SCRIPT = re.compile(r"<script|\bon[a-z]+\s*=|javascript:", re.I)


def best(levels) -> str:
    return max(levels, key=LEVELS.index, default="none")


def _computed(payload: str, matched: str, excerpt: str):
    """The payload asked the target to add two numbers and the answer came back. An echo of the
    payload can't produce a sum that isn't in it."""
    if not matched.isdigit():
        return None
    sums = {str(int(a) + int(b)) for a, b in re.findall(r"\b(\d+)\s*\+\s*(\d+)\b", payload)}
    if matched not in sums:
        return None
    if matched in payload:
        return "partial", f"the computed value {matched} is also in the payload, so it may be an echo"
    if not re.search(rf"\b{matched}\b", excerpt):
        return "partial", f"the computed value {matched} is not in the recorded response excerpt"
    return "validated", f"the target computed {matched}, which is not in the payload, and returned it"


def _delay(matched: str):
    """Two delayed responses against a baseline, as the scanners record them."""
    found = re.search(r"delayed ([\d.]+)s / ([\d.]+)s vs baseline ([\d.]+)s", matched)
    if not found:
        return None
    first, second, baseline = (float(x) for x in found.groups())
    if min(first, second) - baseline >= MIN_DELAY_S:
        return "validated", f"two requests were delayed {first}s and {second}s against a {baseline}s baseline"
    return "partial", f"the delays ({first}s, {second}s) are too close to the {baseline}s baseline"


def _injection(fallback):
    """Executed input is shown by a computed result or a controlled delay, nothing weaker."""
    def run(payload, ev, rt):
        matched, excerpt = str(ev.get("matched") or ""), str(ev.get("response_excerpt") or "")
        return _computed(payload, matched, excerpt) or _delay(matched) or ("partial", fallback)
    return run


def _traversal(payload, ev, rt):
    matched, excerpt = str(ev.get("matched") or ""), str(ev.get("response_excerpt") or "")
    if not matched:
        return "partial", "no file content was recorded"
    in_excerpt = matched.lower() in excerpt.lower() and any(s.search(excerpt) for s in FILE_SIGNATURES)
    if matched.lower() in payload.lower():
        return "partial", "the file signature is also in the payload, so it may be an echo"
    if not in_excerpt:
        return "partial", "the response excerpt doesn't contain recognisable system file content"
    return "validated", "the response contains system file content that the payload doesn't"


def _redirect(payload, ev, rt):
    matched = str(ev.get("matched") or "")
    status = ev.get("probe_status")
    chosen = urlparse(payload).hostname
    sent_to = urlparse(matched).hostname
    own = urlparse(rt["url"]).hostname
    if not chosen or chosen == own:
        return "partial", "the destination the test asked for is not outside the application"
    if isinstance(status, int) and 300 <= status < 400 and sent_to == chosen:
        return "validated", f"the server redirected to {chosen}, the destination the test chose"
    return "partial", "a redirect to the chosen destination appears in the page, but the server did not send it"


def _xss(payload, ev, rt):
    excerpt = str(ev.get("response_excerpt") or "")
    if payload not in excerpt:
        return "partial", "the payload is not reflected unchanged in the recorded response excerpt"
    if RUNS_SCRIPT.search(payload):
        return "validated", "a script-running payload is reflected unchanged"
    return "partial", "the payload is reflected, but it contains nothing that would run in a browser"


CHECKS = {
    89: _injection("an error from the database shows the input reached the query, not that it can be exploited"),
    78: _injection("the response changed, but no computed result or controlled delay shows the input is executed"),
    22: _traversal, 601: _redirect, 79: _xss,
}


def check(finding: dict) -> dict:
    """The evidence level of one DAST finding, with the reason."""
    runtime = finding["runtime"]
    family = int(finding["cwe_family"].split("-")[1])
    if family not in CHECKS:
        level, reason = "unchecked", f"no evidence check exists for {finding['cwe_family']}"
    else:
        level, reason = CHECKS[family](runtime["payload"], runtime["evidence"] or {}, runtime)
    return {"dast_id": finding["id"], "level": level, "reason": reason}


def assess(findings: list) -> dict:
    """The level for a group of runtime findings: the strongest check among them."""
    checks = [check(f) for f in findings]
    return {"level": best(c["level"] for c in checks), "checks": checks}
