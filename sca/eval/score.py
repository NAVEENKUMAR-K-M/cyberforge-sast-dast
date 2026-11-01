"""Scores sca.json against a key: `python sca/eval/score.py out/sca.json sca/benchmarks/composer-app/key.json`.

Two errors are counted apart from plain mismatches, because they are the ones that mislead:
- **false Reachable**: Reachable where the truth isn't;
- **unsafe reassurance**: a status more reassuring than the truth (Imported-only where it is Reachable or Unknown;
  Present-only where it is anything but Present-only).
"""
from __future__ import annotations

import json
import sys

# How reassuring a status is. A result more reassuring than the truth is an unsafe reassurance, so Present-only
# ("nothing uses the package") on a package the app does use is one, as well as either on a Reachable or Unknown row.
REASSURANCE = {"Reachable": 0, "Unknown": 0, "Imported-only": 1, "Present-only": 2}


def score(report: dict, key: dict) -> dict:
    found = {(r["package"], r["advisory"]["id"]): r for r in report["dependencies"]}
    rows, matched, false_reachable, unsafe = [], 0, [], []
    for want in key["rows"]:
        got = found.pop((want["package"], want["advisory"]), None)
        status = got["status"] if got else "missing"
        ok = status == want["expected"]
        matched += ok
        name = f"{want['package']} {want['advisory']}"
        if status == "Reachable" and want["truth"] != "Reachable":
            false_reachable.append(name)
        if REASSURANCE.get(status, 0) > REASSURANCE[want["truth"]]:
            unsafe.append(name)
        rows.append({"row": name, "expected": want["expected"], "truth": want["truth"], "got": status, "ok": ok})
    return {"status_matches": f"{matched}/{len(key['rows'])}", "false_reachable": false_reachable,
            "unsafe_reassurance": unsafe, "rows": rows,
            "not_in_key": sorted(f"{p} {a}" for p, a in found)}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 2:
        print("usage: score.py <sca.json> <key.json>", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as a, open(argv[1], encoding="utf-8") as b:
        result = score(json.load(a), json.load(b))
    print(json.dumps(result, indent=2))
    return 0 if not result["false_reachable"] and not result["unsafe_reassurance"] else 1


if __name__ == "__main__":
    sys.exit(main())
