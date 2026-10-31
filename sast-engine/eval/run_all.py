"""Scans every benchmark and prints a scoreboard. Run benchmarks/fetch.sh first."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.score import score  # noqa: E402
from sast.core.language import ScanOptions, load_adapter  # noqa: E402

# name, folder, role, language
APPS = [
    ("shop", "benchmarks/shop", "own, runtime-verified", "php"),
    ("lashop", "benchmarks/lashop/overlay", "own, runtime-verified", "php"),
    ("djshop", "benchmarks/djshop", "own, runtime-verified", "python"),
    ("pyshop", "benchmarks/pyshop", "own, runtime-verified", "python"),
    ("fastshop", "benchmarks/fastshop", "own, runtime-verified", "python"),
    ("vulpy", "benchmarks/external/vulpy/bad", "holdout (Python)", "python"),
    ("vulpy_good", "benchmarks/external/vulpy/good", "holdout (Python)", "python"),
    ("vampi", "benchmarks/external/vampi", "holdout (Python)", "python"),
    ("vulnflask", "benchmarks/external/vulnflask", "holdout (Python)", "python"),
    ("dvwa", "benchmarks/external/dvwa", "development", "php"),
    ("mutillidae", "benchmarks/external/mutillidae", "development", "php"),
    ("xvwa", "benchmarks/external/xvwa", "holdout", "php"),
    ("bwapp", "benchmarks/external/bwapp", "holdout", "php"),
]
EXTENSIONS = {"php": ".php", "python": ".py"}


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print(f"{'app':<12}{'role':<24}{'detected':<16}{'pairs':<10}{'decoys':<8}{'routes':<8}{'open':<6}{'safe':<6}{'secs':<6}")
    problems = 0
    for name, path, role, language in APPS:
        full = os.path.join(root, path)
        # An empty folder is what an interrupted download leaves behind, so look for source, not just the folder.
        if not any(f.endswith(EXTENSIONS[language]) for _, _, files in os.walk(full) for f in files):
            print(f"{name:<12}not fetched: run benchmarks/fetch.sh")
            problems += 1
            continue
        result = load_adapter(language).scan(full, ScanOptions())  # the settings an unseen app gets
        with open(os.path.join(root, "eval", "keys", f"{name}.json")) as handle:
            scored = score(result.findings, json.load(handle))
        problems += len(scored["missed"]) + len(scored["false_alarms"]) + len(scored["wrong_route_or_param"])
        opened = sum(1 for f in result.findings if f["status"] == "open")
        print(f"{name:<12}{role:<24}{scored['code_detection']:<16}{scored['linkable_pairs'].split()[0]:<10}"
              f"{scored['decoys_reported']:<8}{len(result.routes):<8}{opened:<6}{len(result.findings) - opened:<6}{result.stats['seconds']:<6}")
        for label in ("missed", "wrong_route_or_param", "false_alarms"):
            if scored[label]:
                print(f"  {label}: {scored[label]}")
        if result.stats["semgrep_error"] or result.stats["budget_exhausted_entries"]:
            print(f"  warning: {result.stats['semgrep_error']} budget={result.stats['budget_exhausted_entries']}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
