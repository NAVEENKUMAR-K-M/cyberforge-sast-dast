"""Scores a findings.json against an answer key, using the PRD's definitions."""
from __future__ import annotations

import argparse
import json
import sys

FAMILY_PREFIX = "CWE-"


def _matches(finding, item) -> bool:
    if finding["cwe_family"] != f"{FAMILY_PREFIX}{item['cwe']}":
        return False
    if "file" not in item:
        # Some bugs can fairly be fixed in more than one file, so they're matched as a correlator would.
        return _route_ok(finding, item) and _param_ok(finding, item)
    if finding["file"] != item["file"]:
        return False
    if "lines" not in item:
        return True
    low, high = item["lines"]
    return low <= finding["line"] <= high


def _route_ok(finding, item) -> bool:
    if "route" not in item:
        return True
    selector = item.get("selector")
    return any(r["path"].endswith(item["route"]) and (selector is None or r["selector"] == selector) for r in finding["routes"])


def _param_ok(finding, item) -> bool:
    return "param" not in item or any(p["name"] == item["param"] for p in finding["source_params"])


def score(findings, key) -> dict:
    open_items = [f for f in findings if f["status"] == "open"]
    bugs = key["pairs"] + key["code_only"]
    missed, weak_link = [], []
    matched = set()
    for item in bugs:
        hits = [f for f in open_items if _matches(f, item)]
        if not hits:
            suppressed = [f for f in findings if f["status"] == "suppressed" and _matches(f, item)]
            missed.append({"id": item["id"], "hard": item.get("hard"), "wrongly_marked_safe": bool(suppressed)})
            continue
        matched.update(f["fingerprint"] for f in hits)
        if not any(_route_ok(f, item) and _param_ok(f, item) for f in hits):
            weak_link.append(item["id"])
    alarms, marked_safe = [], []
    for item in key["decoys"]:
        if any(_matches(f, item) for f in open_items):
            alarms.append(item["id"])
        else:
            marked_safe.append(item["id"])
    pair_ids = {i["id"] for i in key["pairs"]}
    linkable = [i for i in key["pairs"] if i["id"] not in {m["id"] for m in missed} and i["id"] not in weak_link]
    total = len(bugs)
    return {
        "code_detection": f"{total - len(missed)}/{total} ({100 * (total - len(missed)) / max(total, 1):.0f}%)",
        "linkable_pairs": f"{len(linkable)}/{len(pair_ids)} found with the right route and parameter",
        "decoys_reported": f"{len(alarms)}/{len(key['decoys'])}",
        "false_alarm_share": f"{100 * len(alarms) / max(len(open_items), 1):.1f}% of {len(open_items)} open findings",
        "missed": missed,
        "wrong_route_or_param": weak_link,
        "false_alarms": alarms,
        "open_not_in_key": sum(1 for f in open_items if f["fingerprint"] not in matched),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("findings")
    parser.add_argument("key")
    args = parser.parse_args()
    with open(args.findings) as handle:
        findings = json.load(handle)["findings"]
    with open(args.key) as handle:
        key = json.load(handle)
    print(json.dumps(score(findings, key), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
