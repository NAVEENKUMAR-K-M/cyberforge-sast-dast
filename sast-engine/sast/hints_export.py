"""Writes hints for the DAST engine: which exact (route, parameter, CWE) the code suggests are
worth a closer look. A hint only adds effort there. It never makes DAST skip anything.
"""
from __future__ import annotations

VERSION = "1.0"


def to_hints(result) -> dict:
    routes_by_id = {route["id"]: route for route in result.routes}
    seen, hints = set(), []
    for finding in result.findings:
        # Low confidence was wrong in every hand-checked case, so it isn't worth scan time.
        if finding["status"] != "open" or finding["confidence"] == "low":
            continue
        references = list(finding["routes"])
        if finding["stored_flow"]:
            references += finding["stored_flow"]["write_routes"]
        for reference in references:
            route = routes_by_id.get(reference["id"], {})
            paths = [reference["path"], *route.get("aliases", [])]
            for path in paths:
                for method in reference["methods"]:
                    for param in finding["source_params"]:
                        key = (path, method, reference["selector"], param["name"], finding["cwe_family"])
                        if key not in seen:
                            seen.add(key)
                            hints.append({"route": path, "method": method, "selector": reference["selector"],
                                          "param": param["name"], "cwe": finding["cwe_family"]})
    return {"version": VERSION, "hints": hints}
