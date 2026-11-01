"""Command line: `python -m correlator.cli --sast <file> --dast <file> --out issues.json`."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

from correlator.correlate import InputError, correlate, load_report
from correlator.loop import dast_executor, run_loop
from correlator.env import load_env
from correlator.planner import PROVIDERS, ChatPlanner
from correlator.report import render


DEFAULT_MODEL = "openai/gpt-oss-120b"   # the Groq default: stronger than gpt-oss-20b in two live runs on the shop


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="correlator", description="Links SAST and DAST findings into one issue per bug.")
    parser.add_argument("--sast", required=True, help="the SAST engine's findings.common.json")
    parser.add_argument("--dast", required=True, help="the DAST engine's *.common.json")
    parser.add_argument("--out", required=True, help="where to write issues.json")
    parser.add_argument("--base-path", default=None,
                        help="URL prefix the app is served under, such as /app (default: the path in the DAST target)")
    parser.add_argument("--investigate", action="store_true",
                        help="re-test credible Code only issues live with the DAST engine and correlate the results again")
    parser.add_argument("--dast-engine", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dast-engine"),
                        help="the DAST engine folder (for --investigate)")
    parser.add_argument("--dast-python", default=None, help="Python for the DAST engine (default: <dast-engine>/.venv)")
    parser.add_argument("--dast-config", default=None, help="DAST config file (for --investigate)")
    parser.add_argument("--planner", choices=["none", *PROVIDERS], default="none",
                        help="who proposes the second test when the first doesn't settle a case. A provider sends the handler's "
                             "source to its API; its key is read from .env (GROQ_API_KEY or OPENAI_API_KEY)")
    parser.add_argument("--planner-model", default=None, help=f"the model (default for groq: {DEFAULT_MODEL})")
    parser.add_argument("--source-root", default=None, help="the folder SAST scanned, so the planner can read handler source")
    parser.add_argument("--max-cases", type=int, default=10, help="most issues to re-test")
    parser.add_argument("--budget", type=float, default=120.0, help="seconds to spend re-testing")
    parser.add_argument("--sca", default=None,
                        help="sca.json from `python -m sca.cli scan`, shown as a separate dependencies section")
    args = parser.parse_args(argv)

    try:
        sast = load_report(args.sast, "sast")
        dast = load_report(args.dast, "dast")
        dependencies = _dependencies(args.sca) if args.sca else None
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    sources = {"sast": args.sast, "dast": args.dast}
    if args.investigate:
        python = args.dast_python or os.path.join(args.dast_engine, ".venv", "bin", "python")
        if not os.path.isfile(python):
            print(f"error: --investigate needs the DAST engine's Python, but {python} doesn't exist (use --dast-python)", file=sys.stderr)
            return 2
        if not dast.get("target"):
            print("error: --investigate needs the DAST report to name its target URL", file=sys.stderr)
            return 2
        config = os.path.abspath(args.dast_config) if args.dast_config else None   # the engine runs from its own folder
        planner = None
        if args.planner != "none":
            load_env()
            key_name = PROVIDERS[args.planner][1]
            if not os.environ.get(key_name):
                print(f"error: --planner {args.planner} needs {key_name} in .env (see .env.example) or the environment", file=sys.stderr)
                return 2
            planner = ChatPlanner(args.planner, args.planner_model or DEFAULT_MODEL, args.source_root)
        executor = dast_executor(os.path.abspath(args.dast_engine), os.path.abspath(python), config, dast["target"])
        result, investigated = run_loop(sast, dast, executor, planner, base_path=args.base_path, sources=sources,
                                        max_cases=args.max_cases, budget_seconds=args.budget)
        evidence_file = os.path.splitext(args.out)[0] + ".dast.common.json"
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(evidence_file, "w", encoding="utf-8") as handle:
            json.dump(investigated, handle, indent=2)
            handle.write("\n")
        result["inputs"]["dast"]["path"] = evidence_file   # the report with the new findings, so the result can be rebuilt from it
    else:
        result = correlate(sast, dast, args.base_path, sources=sources)
    if dependencies is not None:
        result["dependencies"] = dependencies      # kept apart: SCA rows never enter linking, labels or the issue ranking
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    page = os.path.splitext(args.out)[0] + ".html"
    with open(page, "w", encoding="utf-8") as handle:
        handle.write(render(result))

    stats = result["stats"]
    print(f"{stats['issues']} issues ({stats['reportable']} reported): {stats['confirmed']} Confirmed, "
          f"{stats['code_only']} Code only, {stats['runtime_only']} Runtime only")
    print(f"{stats['links']} links, {stats['ambiguous']} ambiguous, {stats['conflicts']} conflicts for review, "
          f"{stats['suppressed']} code findings marked safe and left out")
    if args.investigate:
        outcomes = Counter(r["outcome"] for r in result["investigations"])
        print(f"Re-tested {stats['investigated']} issues: " + (", ".join(f"{n} {k}" for k, n in sorted(outcomes.items())) or "none")
              + f"; {stats['upgraded']} became Confirmed")
    if dependencies is not None:
        counts = dependencies["stats"]
        print(f"Dependencies: {counts['Reachable']} Reachable, {counts['Unknown']} Unknown, {counts['Imported-only']} "
              f"Imported-only, {counts['Present-only']} Present-only; {counts['supply_chain']} supply-chain findings")
    for message in result["diagnostics"]:
        print(f"warning: {message}")
    top = [i for i in result["issues"] if i["reportable"]][:5]
    if top:
        print("Top issues:")
    for issue in top:
        code = issue["evidence"]["code"]
        where = issue["routes"][0]["path"] if issue["routes"] else "whole app"
        if code:
            where += f"  {code[0]['code']['file']}:{code[0]['code']['line']}"
        print(f"  #{issue['rank']} {issue['label']:<12} CVSS {issue['risk_score']:<4} {issue['cwe']:<8} {where}")
    print(f"Wrote {args.out} and {page}")
    return 0


def _dependencies(path: str) -> dict:
    """The parts of an SCA report the issue page shows."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise InputError(f"can't read {path}: {exc}") from None
    if not isinstance(data, dict) or data.get("tool") != "cyberforge-sca":
        raise InputError(f"{path} isn't an SCA report from `python -m sca.cli scan`")
    analysis = data.get("analysis") or {}
    return {"source": path, "advisory_lookup": data.get("advisory_lookup") or {}, "rows": data.get("dependencies") or [],
            "supply_chain": data.get("supply_chain") or [], "stats": data.get("stats") or {},
            "analysis": {k: analysis.get(k) for k in ("roots", "packages_analysed", "complete", "limit", "assumptions")}}


if __name__ == "__main__":
    sys.exit(main())
