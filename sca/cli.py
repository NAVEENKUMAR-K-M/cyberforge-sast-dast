"""Command line: `python -m sca.cli scan <app> --routes routes.json --out out/sca`."""
from __future__ import annotations

import argparse
import json
import os
import sys

from sca.http import DEFAULT_CACHE, Fetcher
from sca.inventory import InventoryError
from sca.scan import run


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sca", description="Can the app reach a vulnerable library function?")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a Composer app")
    scan.add_argument("app", help="the app folder (with composer.json and composer.lock)")
    scan.add_argument("--routes", default=None, help="SAST's routes.json; its handlers are the entry points")
    scan.add_argument("--deps-source", default=None, help="the dependency source to analyse (default: <app>/vendor)")
    scan.add_argument("--lock", default=None, help="composer.lock, if not in the app folder")
    scan.add_argument("--out", required=True, help="folder for sca.json and sbom.cdx.json")
    scan.add_argument("--cache-dir", default=DEFAULT_CACHE, help=f"advisory cache (default: {DEFAULT_CACHE})")
    scan.add_argument("--offline", action="store_true", help="use only the cache; nothing is fetched")
    scan.add_argument("--max-functions", type=int, default=200_000, help="stop the call graph after this many functions")
    scan.add_argument("--timeout", type=float, default=60.0, help="stop the call graph after this many seconds")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.app):
        print(f"error: {args.app} is not a folder", file=sys.stderr)
        return 2
    if args.routes and not os.path.isfile(args.routes):
        print(f"error: {args.routes} doesn't exist", file=sys.stderr)
        return 2
    from common.env import load_env            # GITHUB_TOKEN may live in .env; it is optional
    load_env()
    fetcher = Fetcher(args.cache_dir, offline=args.offline, token=os.environ.get("GITHUB_TOKEN"))
    try:
        report, sbom = run(args.app, fetcher, routes_path=args.routes, deps_dir=args.deps_source, lock_path=args.lock,
                           max_states=args.max_functions, timeout=args.timeout)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    for name, data in (("sca.json", report), ("sbom.cdx.json", sbom)):
        with open(os.path.join(args.out, name), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")

    stats = report["stats"]
    lookup = report["advisory_lookup"]
    print(f"{len(report['packages'])} packages; advisory lookup {lookup['status']}"
          + (f" (OSV, {lookup['fetched_at']})" if lookup["fetched_at"] else ""))
    print(f"{len(report['dependencies'])} affected: {stats['Reachable']} Reachable, {stats['Unknown']} Unknown, "
          f"{stats['Imported-only']} Imported-only, {stats['Present-only']} Present-only; "
          f"{stats['supply_chain']} supply-chain findings")
    for row in report["dependencies"]:
        print(f"  #{row['rank']} {row['status']:<13} {row['package']}@{row['version']}  {row['advisory']['id']}")
        print(f"      {row['reason']}")
    for finding in report["supply_chain"]:
        print(f"  [{finding['kind']}] {finding['title']}")
    for message in report["diagnostics"]:
        print(f"warning: {message}")
    print(f"Wrote {os.path.join(args.out, 'sca.json')} and {os.path.join(args.out, 'sbom.cdx.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
