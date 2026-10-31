"""Exports findings as SARIF 2.1.0, for code scanning tools and CI."""
from __future__ import annotations

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(result) -> dict:
    rules = {}
    runs = []
    for item in result.findings:
        rules.setdefault(item["cwe"], {
            "id": item["cwe"],
            "name": item["title"].replace(" ", ""),
            "shortDescription": {"text": item["title"]},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{item['cwe'].split('-')[1]}.html",
        })
        entry = {
            "ruleId": item["cwe"],
            "level": LEVELS.get(item["severity"], "warning"),
            "message": {"text": f"{item['title']} via {item['sink']}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": item["file"]},
                "region": {"startLine": item["line"], "snippet": {"text": item["snippet"]}},
            }}],
            "partialFingerprints": {"cyberforge/v1": item["fingerprint"]},
            "properties": {
                "confidence": item["confidence"],
                "routes": item["routes"],
                "sourceParams": item["source_params"],
            },
        }
        if item["status"] == "suppressed":
            entry["suppressions"] = [{"kind": "inSource", "justification": item["suppression_reason"]}]
        if item["trace"]:
            entry["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {
                    "physicalLocation": {"artifactLocation": {"uri": step["file"]}, "region": {"startLine": step["line"]}},
                    "message": {"text": step["note"]},
                }} for step in item["trace"]
            ]}]}]
        runs.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "cyberforge-sast", "version": "0.1.0", "rules": list(rules.values())}},
            "results": runs,
        }],
    }
