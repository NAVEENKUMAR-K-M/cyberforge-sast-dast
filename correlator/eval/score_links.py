"""Scores issues.json against an answer key in sast-engine/eval/keys format, using the PRD's measures.

Usage:  python correlator/eval/score_links.py issues.json sast-engine/eval/keys/shop.json
"""
from __future__ import annotations

import json
import re
import sys


def _code_match(finding, item) -> bool:
    code = finding["code"]
    if finding["cwe_family"] != f"CWE-{item['cwe']}" or code["file"] != item.get("file"):
        return False
    return "lines" not in item or item["lines"][0] <= code["line"] <= item["lines"][1]


def _shape(path: str) -> str:
    """A route with every placeholder written `{}`: a crawl calls `/p/{id}` what the code calls `/p/{pid}`."""
    return re.sub(r"\{[^}]*\}", "{}", path)


def _runtime_match(finding, item) -> bool:
    route = finding["routes"][0] if finding["routes"] else None
    # A stored bug is found where it is written, and the key names that route when it differs from the read route.
    wanted = _shape(item.get("write_route") or item["route"])
    return (route is not None and finding["cwe_family"] == f"CWE-{item['cwe']}" and _shape(route["path"]).endswith(wanted)
            and finding["params"] and finding["params"][0]["name"] == item["param"]
            and item.get("selector") in (None, route["selector"]))


def score(issues: dict, key: dict) -> dict:
    confirmed = [i for i in issues["issues"] if i["label"] == "Confirmed"]
    reported = [i for i in issues["issues"] if i["reportable"]]
    linked, wrong = set(), []
    for issue in confirmed:
        code_side = {p["id"] for p in key["pairs"] if any(_code_match(f, p) for f in issue["evidence"]["code"])}
        runtime_side = {p["id"] for p in key["pairs"] if any(_runtime_match(f, p) for f in issue["evidence"]["runtime"])}
        if code_side & runtime_side:
            linked |= code_side & runtime_side
        elif code_side and runtime_side:
            wrong.append(issue["issue_id"])  # joins two different known bugs
    code_found = [i["id"] for i in key["code_only"] if any(_code_match(f, i) for r in reported for f in r["evidence"]["code"])]
    decoys = [d["id"] for d in key["decoys"] if any(_code_match(f, d) for r in reported for f in r["evidence"]["code"])]
    pairs = len(key["pairs"])
    return {
        "correct_links": f"{len(linked)}/{pairs} ({100 * len(linked) / max(pairs, 1):.0f}%)",
        "wrong_links": f"{len(wrong)}/{len(confirmed)} confirmed issues",
        "code_only_found": f"{len(code_found)}/{len(key['code_only'])}",
        "decoys_reported": f"{len(decoys)}/{len(key['decoys'])}",
        "false_alarm_share": f"{100 * len(decoys) / max(len(reported), 1):.1f}% of {len(reported)} reported issues",
        "pairs_not_linked": sorted(p["id"] for p in key["pairs"] if p["id"] not in linked),
        "wrong_link_issues": wrong,
        "decoys": decoys,
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    with open(sys.argv[1]) as handle:
        issues = json.load(handle)
    with open(sys.argv[2]) as handle:
        key = json.load(handle)
    print(json.dumps(score(issues, key), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
