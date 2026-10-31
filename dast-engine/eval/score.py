"""Scores a dast_results.json run against an answer-key JSON.

Usage:
    python eval/score.py output/dvwa_results.json eval/answer_keys/dvwa.json

Reports: detection %, false-alarm rate, request count, p95 latency, and
elapsed time, matching the targets in the PRD.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def _shape(route_template: str) -> str:
    """A route without its trailing slash and with every placeholder name dropped, so `/p/{id}` and
    `/p/{pid}` are the same route."""
    return re.sub(r"\{[^}]*\}", "{}", route_template).rstrip("/")


def _matches(finding: dict, key_entry: dict) -> bool:
    """A key_entry's `method` and `param` are optional: a safe_decoy in
    particular often only cares about matching cwe + route_template
    regardless of method, or route_template alone regardless of param."""
    if finding["cwe"] != key_entry["cwe"]:
        return False
    if key_entry.get("method") and finding["method"].upper() != key_entry["method"].upper():
        return False
    if _shape(finding["route_template"]) != _shape(key_entry["route_template"]):
        return False
    if key_entry.get("param") and finding.get("param") != key_entry["param"]:
        return False
    return True


def score(results: dict, answer_key: dict) -> dict:
    findings = results.get("findings", [])
    expected = answer_key.get("expected", [])
    decoys = answer_key.get("safe_decoys", [])

    detected = 0
    missed = []
    for exp in expected:
        if any(_matches(f, exp) for f in findings):
            detected += 1
        else:
            missed.append(exp)

    detection_rate = detected / len(expected) if expected else 0.0

    false_alarms = [f for f in findings if any(_matches(f, d) for d in decoys)]
    false_alarm_rate = len(false_alarms) / len(findings) if findings else 0.0

    return {
        "detection_rate": round(detection_rate, 3),
        "detected": detected,
        "expected_total": len(expected),
        "missed": missed,
        "false_alarm_rate": round(false_alarm_rate, 3),
        "false_alarm_count": len(false_alarms),
        "false_alarms": false_alarms,
        "total_findings": len(findings),
        "request_count": results.get("request_count"),
        "p95_latency_seconds": results.get("p95_latency_seconds"),
        "elapsed_seconds": results.get("elapsed_seconds"),
        "within_5min_budget": (results.get("elapsed_seconds") or 9e9) <= 300,
    }


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <dast_results.json> <answer_key.json>")
        sys.exit(1)

    results = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    answer_key = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

    report = score(results, answer_key)
    print(json.dumps(report, indent=2))

    print(f"\nDetection rate: {report['detection_rate']*100:.1f}% ({report['detected']}/{report['expected_total']})")
    print(f"False alarm rate: {report['false_alarm_rate']*100:.1f}% ({report['false_alarm_count']}/{report['total_findings']})")
    print(f"Requests: {report['request_count']}  p95 latency: {report['p95_latency_seconds']}s  elapsed: {report['elapsed_seconds']}s")

    if report["detection_rate"] < 0.80:
        print("WARNING: detection rate below 80% target")
    if report["false_alarm_rate"] > 0.10:
        print("WARNING: false alarm rate above 10% target")
    if not report["within_5min_budget"]:
        print("WARNING: elapsed time exceeded the 5 minute budget")


if __name__ == "__main__":
    main()
