"""One command for the whole pipeline: `python -m cyberforge scan --source <dir> --target <url>`.

It drives the same ScanManager as the web workspace, so a command-line run and a click in the UI do exactly the
same work (SAST, then DAST using SAST's route map and hints, then the correlator with auto-verify and, when an AI
key is set, the bounded AI-assisted follow-up) and the run also shows up in the workspace's scan history.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

from cyberforge.runtime import CUSTOM_LANGUAGES, CUSTOM_TARGET_ID


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberforge",
        description="Scan an application's source code and its running instance, then link the two views of each bug.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run SAST and/or DAST and correlate the results")
    scan.add_argument("--source", help="folder holding the application's source code (SAST). Without it, only the runtime scan runs")
    scan.add_argument("--target", help="base URL of the running application (DAST), such as http://localhost:8081. "
                                       "Without it, only the source scan runs")
    scan.add_argument("--language", default="auto", choices=CUSTOM_LANGUAGES, help="source language; detected from the files by default")
    scan.add_argument("--deadline", type=int, default=480, help="seconds the runtime scan may take, 30 to 600 (default 480)")
    scan.add_argument("--base-path", default="", help="URL prefix the application is served under, such as /shop")
    scan.add_argument("--no-semgrep", action="store_true", help="skip the SAST pattern rules")
    scan.add_argument("--no-ai", action="store_true", help="skip the AI-assisted follow-up even when an API key is configured")
    scan.add_argument("--no-sca", action="store_true",
                      help="skip the dependency analysis (PHP applications with a composer.lock). It sends package names and versions, "
                           "never source code, to public advisory services")
    scan.add_argument("--sarif", action="store_true", help="also write the SAST findings as SARIF")
    scan.add_argument("--fail-on", choices=["confirmed-high"], help="exit with status 1 if the scan finds a Confirmed high or critical issue (CI gate)")
    scan.add_argument("--login-url", help="login page or JSON login endpoint (same host as --target)")
    scan.add_argument("--username")
    scan.add_argument("--password")
    scan.add_argument("--bearer-token", help="bearer token to send on every request")
    scan.add_argument("--header", action="append", default=[], help="extra request header as Name:Value; can be repeated")
    scan.add_argument("--cookie", action="append", default=[], help="existing session cookie as name=value; can be repeated")
    return parser


def build_request(args: argparse.Namespace) -> dict:
    """The same request body the web workspace sends for a custom application."""
    return {
        "target_id": CUSTOM_TARGET_ID,
        "source_path": args.source,
        "target_url": args.target,
        "language": args.language,
        "run_sast": bool(args.source),
        "run_dast": bool(args.target),
        "deadline_seconds": args.deadline,
        "base_path": args.base_path,
        "semgrep": not args.no_semgrep,
        "sarif": args.sarif,
        "ci_gate": args.fail_on is not None,
        "use_ai": not args.no_ai,
        "use_sca": not args.no_sca,
        "use_route_map": True,     # reaches pages a crawler can't find; this is what lifts runtime detection
        "use_sast_hints": True,
        "auth": {
            "login_url": args.login_url or "", "username": args.username or "", "password": args.password or "",
            "bearer_token": args.bearer_token or "", "headers": list(args.header), "cookies": list(args.cookie),
        },
    }


def _clock(seconds: float) -> str:
    return f"{int(seconds // 60)}:{int(seconds % 60):02d}"


def _relative(path: Path) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:   # a different drive on Windows
        return str(path)


def _where(issue: dict) -> str:
    route = next((r["path"] for r in issue.get("routes", []) if r.get("path")), "")
    code = next((e["code"] for e in issue.get("evidence", {}).get("code", []) if e.get("code")), None)
    location = f"{code['file']}:{code['line']}" if code else ""
    return "  ".join(part for part in (route, location) if part) or "app-wide"


def summarize(record: dict) -> int:
    """Prints what the scan found and returns the process exit status."""
    if record["status"] != "complete":
        print(f"error: the scan {record['status']}: {record.get('error') or 'see the last log lines below'}", file=sys.stderr)
        for line in record["logs"][-15:]:
            print("  " + line, file=sys.stderr)
        return 1
    report_path = Path(record["report_path"])
    issues = json.loads(report_path.read_text(encoding="utf-8"))["issues"]
    counts = Counter(issue["label"] for issue in issues)
    print(f"\n{len(issues)} issues in {record['elapsed_seconds']:.0f}s: {counts['Confirmed']} Confirmed, "
          f"{counts['Code only']} Code only, {counts['Runtime only']} Runtime only")
    assisted = sum(1 for issue in issues if (issue.get("investigation") or {}).get("ai_assisted"))
    if assisted:
        print(f"{assisted} issue(s) were proven by an AI-proposed follow-up test (the correlator judged the evidence)")
    for issue in issues[:5]:
        print(f"  #{issue['rank']:<3} {issue['label']:<12} CVSS {issue['risk_score']:.1f}  {issue['cwe']:<8} {_where(issue)}")
    if len(issues) > 5:
        print(f"  ... and {len(issues) - 5} more")
    print(f"\nReport: {_relative(report_path.with_suffix('.html'))}\n        {_relative(report_path)}")
    print("Open the workspace (python -m web.server, or the Docker UI) to browse the evidence.")
    gate = record.get("gate")
    if gate and not gate["passed"]:
        print(f"CI gate failed: {gate['count']} Confirmed high or critical issue(s)", file=sys.stderr)
        return 1
    return 0


async def run(args: argparse.Namespace) -> int:
    from web.scan_manager import ScanManager   # imports no web framework; the CLI and the UI share one code path

    manager = ScanManager()
    try:
        job = await manager.start(build_request(args))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    scan_id = job["id"]
    task = manager.tasks[scan_id]
    started = last_beat = time.monotonic()
    stage = None
    try:
        while not task.done():
            await asyncio.sleep(1)
            current = manager.jobs[scan_id]["stage"]
            now = time.monotonic()
            if current != stage:
                stage, last_beat = current, now
                print(f"[{_clock(now - started)}] {stage}", flush=True)
            elif now - last_beat >= 20:
                last_beat = now
                print(f"[{_clock(now - started)}] still working: {stage}", flush=True)
        await task
    except asyncio.CancelledError:
        await manager.stop(scan_id)
        raise
    return summarize(manager.jobs[scan_id])


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.source and not args.target:
        parser.error("give --source, --target or both")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
