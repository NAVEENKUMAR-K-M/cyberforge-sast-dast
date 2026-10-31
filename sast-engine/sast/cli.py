"""Command line: `python -m sast.cli scan <source> --out <dir>`."""
from __future__ import annotations

import argparse
import json
import os
import sys

from sast.common_export import to_common
from sast.core.language import ScanOptions
from sast.lang.php.adapter import PhpAdapter
from sast.sarif import to_sarif

ADAPTERS = {"php": PhpAdapter}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cyberforge-sast", description="Static analysis with a route map for correlation.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a source folder")
    scan.add_argument("source", help="folder holding the application's source code")
    scan.add_argument("--out", default="out", help="folder for findings.json and routes.json")
    scan.add_argument("--language", default="php", choices=sorted(ADAPTERS))
    scan.add_argument("--web-root", help="web root relative to source; detected when left out")
    scan.add_argument("--base-path", default="", help="URL prefix the app is served under, such as /dvwa")
    scan.add_argument("--exclude", action="append", default=[], help="folder name to skip; can be repeated")
    scan.add_argument("--no-semgrep", action="store_true", help="skip the pattern rules")
    scan.add_argument("--sarif", action="store_true", help="also write findings.sarif")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.source):
        print(f"error: source folder not found: {args.source}", file=sys.stderr)
        return 2
    options = ScanOptions(args.web_root, args.base_path, args.exclude, not args.no_semgrep)
    result = ADAPTERS[args.language]().scan(args.source, options)
    os.makedirs(args.out, exist_ok=True)
    meta = {"language": result.language, "source_root": result.source_root, "web_root": result.web_root, "stats": result.stats}
    with open(os.path.join(args.out, "findings.json"), "w") as handle:
        json.dump({**meta, "findings": result.findings}, handle, indent=2)
    with open(os.path.join(args.out, "routes.json"), "w") as handle:
        json.dump({**meta, "routes": result.routes}, handle, indent=2)
    with open(os.path.join(args.out, "findings.common.json"), "w") as handle:  # FR-3: common/FORMAT.md
        json.dump(to_common(result), handle, indent=2)
    if args.sarif:
        with open(os.path.join(args.out, "findings.sarif"), "w") as handle:
            json.dump(to_sarif(result), handle, indent=2)
    _print_summary(result, args.out)
    return 0


def _print_summary(result, out) -> None:
    open_items = [f for f in result.findings if f["status"] == "open"]
    stats = result.stats
    print(f"Scanned {stats['files']} files in {stats['seconds']}s: {len(result.routes)} routes, "
          f"{len(open_items)} open findings, {len(result.findings) - len(open_items)} marked safe")
    if stats["budget_exhausted_entries"]:
        print(f"warning: analysis budget ran out on {stats['budget_exhausted_entries']} entry points; results may be incomplete")
    if stats["semgrep_error"]:
        print(f"warning: pattern rules didn't run: {stats['semgrep_error']}")
    for item in open_items[:25]:
        routes = item["routes"][0]["path"] if item["routes"] else "no route"
        print(f"  {item['severity']:<8} {item['cwe']:<8} {item['file']}:{item['line']}  {routes}")
    if len(open_items) > 25:
        print(f"  ... and {len(open_items) - 25} more")
    print(f"Wrote {os.path.join(out, 'findings.json')}, {os.path.join(out, 'routes.json')} and {os.path.join(out, 'findings.common.json')}")


if __name__ == "__main__":
    sys.exit(main())
