"""Command line: `python -m correlator.cli --sast <file> --dast <file> --out issues.json`."""
from __future__ import annotations

import argparse
import json
import os
import sys

from correlator.correlate import InputError, correlate, load_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="correlator", description="Links SAST and DAST findings into one issue per bug.")
    parser.add_argument("--sast", required=True, help="the SAST engine's findings.common.json")
    parser.add_argument("--dast", required=True, help="the DAST engine's *.common.json")
    parser.add_argument("--out", required=True, help="where to write issues.json")
    parser.add_argument("--base-path", default=None,
                        help="URL prefix the app is served under, such as /app (default: the path in the DAST target)")
    args = parser.parse_args(argv)

    try:
        sast = load_report(args.sast, "sast")
        dast = load_report(args.dast, "dast")
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = correlate(sast, dast, args.base_path, sources={"sast": args.sast, "dast": args.dast})
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")

    stats = result["stats"]
    print(f"{stats['issues']} issues ({stats['reportable']} reported): {stats['confirmed']} Confirmed, "
          f"{stats['code_only']} Code only, {stats['runtime_only']} Runtime only")
    print(f"{stats['links']} links, {stats['ambiguous']} ambiguous, {stats['conflicts']} conflicts for review, "
          f"{stats['suppressed']} code findings marked safe and left out")
    for message in result["diagnostics"]:
        print(f"warning: {message}")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
