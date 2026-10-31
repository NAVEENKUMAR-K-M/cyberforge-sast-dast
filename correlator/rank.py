"""Orders issues for a developer (FR-9): Confirmed first, then by CVSS v3.0 Temporal score.

The Base vector starts from a standard baseline for the weakness, and changes only where our evidence
says something CVSS asks about. The Temporal metrics record what the scans proved: a runtime exploit,
or only code analysis. Every choice is listed in `risk_factors`.
"""
from __future__ import annotations

from correlator import cvss

# Baseline Base vectors, chosen the way NVD typically scores these weaknesses in web apps.
BASELINES = {
    89: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",    # SQL injection
    78: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",    # OS command injection
    94: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",    # code injection
    502: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # unsafe deserialization
    798: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # hard-coded credentials
    22: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",    # path traversal: reads files
    538: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # exposed files
    79: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",    # XSS: runs in the victim's browser
    601: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # open redirect
    942: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",   # permissive CORS
    327: "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",   # weak hash: needs the hashes first
    330: "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",   # predictable randomness
    319: "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",   # missing transport security
    489: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",   # debug output, information disclosure
    1021: "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  # clickjacking
    693: "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",   # missing protection header
    1004: "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  # cookie without HttpOnly
    614: "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",   # cookie without Secure
    1275: "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  # cookie without SameSite, referrer leaks
    650: "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",   # TRACE enabled
}
# For a weakness with no baseline above, from the scanner's own severity.
BY_SEVERITY = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}
# Weaknesses an attacker reaches through a request. Without a known URL, network access isn't shown.
REQUEST_DRIVEN = {89, 78, 94, 502, 22, 79, 601}
LABEL_ORDER = {"Confirmed": 0, "Code only": 1, "Runtime only": 1}


def assess(issue: dict) -> dict:
    """Returns the CVSS v3.0 metrics, scores and the reason for each choice."""
    family = int(issue["cwe_family"].split("-")[1])
    baseline = BASELINES.get(family) or BY_SEVERITY[issue["severity"]]
    metrics = cvss.parse(baseline)
    source = f"{issue['cwe_family']} baseline" if family in BASELINES else f"no baseline for {issue['cwe_family']}, from {issue['severity']} severity"
    factors = [f"{source}: {baseline}"]

    if family in REQUEST_DRIVEN and not issue["routes"] and not issue["dast_ids"]:
        metrics["AV"] = "L"
        factors.append("AV:L, no known URL reaches this code")
    locations = {p["location"] for p in issue["params"]}
    if metrics["UI"] == "R" and locations and locations <= {"header", "cookie"}:
        metrics["AC"] = "H"
        factors.append("AC:H, the input is a header or cookie another site can't set for its victim")

    verification = {f["runtime"]["verification"] for f in issue["evidence"]["runtime"]}
    if "confirmed" in verification:
        metrics["E"] = "F"
        factors.append("E:F, a runtime test exploited it")
    elif verification:
        metrics["E"] = "P"
        factors.append("E:P, a runtime test showed it but didn't fully exploit it")
    else:
        metrics["E"] = "U"
        factors.append("E:U, found by code analysis only, not exploited")

    if issue["label"] == "Confirmed" or "confirmed" in verification:
        metrics["RC"] = "C"
        factors.append("RC:C, " + ("found in both the code and the running app" if issue["label"] == "Confirmed" else "confirmed by a runtime test"))
    elif issue["confidence"] == "low":
        metrics["RC"] = "U"
        factors.append("RC:U, low-confidence code analysis")
    else:
        metrics["RC"] = "R"
        factors.append("RC:R, reasonable evidence from one scanner")

    base = cvss.base_score(metrics)
    temporal = cvss.temporal_score(base, metrics)
    return {
        "cvss": {"version": "3.0", "vector": cvss.vector_string(metrics), "base_score": base,
                 "temporal_score": temporal, "rating": cvss.rating(temporal)},
        "risk_score": temporal,
        "risk_factors": factors,
    }


def rank(issues: list) -> list:
    """Reported before held back, Confirmed before the rest, then the highest CVSS Temporal score,
    then Base score. The issue ID breaks ties, so the order never changes between runs."""
    for issue in issues:
        issue.update(assess(issue))
    ordered = sorted(issues, key=lambda i: (not i["reportable"], LABEL_ORDER[i["label"]], -i["risk_score"],
                                            -i["cvss"]["base_score"], i["issue_id"]))
    for position, issue in enumerate(ordered, 1):
        issue["rank"] = position
    return ordered
