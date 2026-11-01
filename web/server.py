"""Run the local workspace: ``python -m web.server [--report out/issues.json]``."""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from correlator.report import render
from web.scan_manager import DAST_PYTHON, TARGETS, ScanManager

ROOT = Path(__file__).resolve().parents[1]
WEB = Path(__file__).resolve().parent
VALIDATOR = jsonschema.Draft202012Validator(json.loads((ROOT / "correlator/issues.schema.json").read_text()))


def create_app(report_path: Path | str = "out/issues.json", *, example: bool = False) -> FastAPI:
    """Serve findings and orchestrate scans of the built-in local targets only."""
    path = Path(report_path).resolve()
    app = FastAPI(title="CyberForge", docs_url=None, redoc_url=None, openapi_url=None)
    scans = ScanManager()
    app.state.scans = scans

    def read_report() -> dict:
        selected_path = scans.get_report_path(path)
        try:
            report = json.loads(selected_path.read_text(encoding="utf-8"))
            VALIDATOR.validate(report)
        except FileNotFoundError:
            raise HTTPException(404, "No report found. Generate issues.json, then start the workspace with --report <path>.") from None
        except (ValueError, OSError, jsonschema.ValidationError):
            raise HTTPException(422, "The selected file is not a valid CyberForge issues report. Regenerate it with the correlator.") from None
        return report

    def source_stats(report: dict, source: str) -> tuple[dict, str | None]:
        # Use recorded metadata only. Missing inputs never imply a successful scan.
        reference = report["inputs"][source].get("path")
        if not reference:
            return {}, f"{source.upper()} scan metadata was not recorded."
        source_path = Path(reference)
        candidates = [source_path] if source_path.is_absolute() else [ROOT / source_path, path.parent / source_path]
        for candidate in candidates:
            try:
                doc = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(doc, dict) and doc.get("source") == source and isinstance(doc.get("stats"), dict):
                return doc["stats"], None
        return {}, f"{source.upper()} scan metadata is unavailable; its original common report could not be read."

    @app.middleware("http")
    async def local_response_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/report")
    def get_report():
        report = read_report()
        selected_path = scans.get_report_path(path)
        notes = []
        stats = {}
        for source in ("sast", "dast"):
            stats[source], note = source_stats(report, source)
            if note:
                notes.append(note)
        source = report["inputs"]["sast"].get("target", "")
        name = Path(source.rstrip("/")).name or "Application"
        latest = scans.get_job(scans.latest_job) if scans.latest_job else None
        opts = latest.get("options", {}) if latest else {}
        is_followup_job = bool(opts.get("investigation"))
        if is_followup_job:
            latest = scans.get_job(opts.get("source_scan_id")) or latest
        investigation_run = is_followup_job or bool(opts.get("investigation_included"))
        return {
            "report": report,
            "scan": {
                "name": latest["target_name"] if latest else ("Benchmark shop" if example else name),
                "target": report["inputs"]["dast"].get("target", ""),
                "source": source,
                "report_path": str(selected_path),
                "modified_at": datetime.fromtimestamp(selected_path.stat().st_mtime, timezone.utc).isoformat(),
                "example": example and latest is None,
                "stats": stats,
                "notes": notes,
                "scan_id": scans.latest_job,
                "target_id": latest["target_id"] if latest else None,
                "elapsed_seconds": latest["elapsed_seconds"] if latest else None,
                "investigation_run": investigation_run,
            },
        }

    @app.get("/api/targets")
    def get_targets():
        return {"targets": scans.targets()}

    @app.get("/api/ai/status")
    def ai_status():
        from correlator.env import load_env
        from correlator.planner import PROVIDERS
        import os

        load_env()
        return {"providers": [
            {"id": provider, "label": provider.title(), "configured": bool(os.environ.get(key_name))}
            for provider, (_, key_name, _) in PROVIDERS.items()
        ], "ready": any(os.environ.get(key_name) for _, key_name, _ in PROVIDERS.values())}

    @app.post("/api/scans")
    async def start_scan(request: dict):
        try:
            return await scans.start(request)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/api/scans/{scan_id}/investigate")
    async def investigate_scan(scan_id: str, request: dict):
        if request.get("consent") is not True:
            raise HTTPException(400, "Confirm the AI data-sharing notice before starting.")
        try:
            report = read_report()
            return await scans.start_investigation(scan_id, request.get("provider"), request.get("model"), report)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/api/verify")
    async def verify_code_finding(request: dict):
        report = read_report()
        target_id = request.get("target_id")
        target = scans.target_for(target_id)
        if target is None or not target["sast_supported"]:
            raise HTTPException(400, "Choose a PHP or Python target supported by the SAST engine.")
        issue_id = request.get("issue_id")
        issue = next((item for item in report["issues"] if item["issue_id"] == issue_id), None)
        if not issue or issue["label"] != "Code only":
            raise HTTPException(400, "Choose a code-only issue to re-test.")
        code_finding = next((item for item in issue["evidence"]["code"]
                             if item.get("code") and item.get("routes") and item.get("params")), None)
        if not code_finding:
            raise HTTPException(400, "This issue has no source finding to verify.")
        code = code_finding["code"]
        routes = code_finding.get("routes") or []
        params = code_finding.get("params") or []
        route = next((entry for entry in routes if entry.get("path")), None)
        param = next((entry for entry in params if entry.get("name")), None)
        if not route or not param:
            raise HTTPException(400, "This finding has no mapped route and input parameter for safe auto-verification.")
        location = param.get("location", "query")
        if location == "any":
            location = "body" if "POST" in route.get("methods", []) else "query"
        if location not in {"query", "body", "json", "path", "header", "cookie"}:
            raise HTTPException(400, f"Auto-verification does not support the {location} input location yet.")
        try:
            target_url = scans.validate_target_url(request.get("target_url", report["inputs"]["dast"].get("target", "")))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if target_id in TARGETS and urlsplit(target_url).port != urlsplit(target["url"]).port:
            raise HTTPException(400, f"{target['name']} verification must use local port {urlsplit(target['url']).port}.")
        recorded_target = urlsplit(report["inputs"]["dast"].get("target", ""))
        if recorded_target.netloc and recorded_target.netloc.lower() != urlsplit(target_url).netloc.lower():
            raise HTTPException(400, "Verification must use the same local host and port as this report.")

        args = [str(ROOT / "dast-engine" / "main.py"), "verify", "--target", target_url,
                "--cwe", code_finding["cwe"],
                "--method", (route.get("methods") or ["GET"])[0], "--route", route["path"],
                "--param", param["name"], "--param-location", location]
        if target["config"]:
            args += ["--config", str(target["config"])]
        if route.get("selector"):
            args += ["--selector", route["selector"]]
        try:
            auth = scans.validate_auth(request.get("auth"))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if auth.get("login_url"):
            try:
                login_url = scans.validate_target_url(auth["login_url"])
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None
            if urlsplit(login_url).netloc.lower() != urlsplit(target_url).netloc.lower():
                raise HTTPException(400, "The login URL must use the same local host and port as the target.")
        for key, flag in (("login_url", "--login-url"), ("username", "--username"),
                          ("password", "--password"), ("bearer_token", "--bearer-token")):
            if auth.get(key):
                args += [flag, str(auth[key])]
        if auth.get("json_login"):
            args.append("--json-login")
        for value in auth.get("headers", [])[:10]:
            args += ["--header", str(value)]
        for value in auth.get("cookies", [])[:10]:
            args += ["--cookie", str(value)]
        verification_started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            str(DAST_PYTHON), *args, cwd=str(ROOT / "dast-engine"),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=45)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise HTTPException(504, "Runtime verification timed out after 45 seconds.") from None
        if process.returncode != 0:
            raise HTTPException(500, "Runtime verification failed: " + stderr.decode("utf-8", "replace")[-800:])
        try:
            outcome = json.loads(stdout.decode("utf-8", "replace").strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise HTTPException(500, "Runtime verification returned an unreadable result.") from None
        if not outcome.get("reproduced") or not outcome.get("finding"):
            return {"reproduced": False, "message": "The targeted runtime probe did not reproduce this finding.", "finding": None}

        dast_path = Path(report["inputs"]["dast"]["path"])
        if not dast_path.is_absolute():
            dast_path = (ROOT / dast_path).resolve()
        try:
            dast_doc = json.loads(dast_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise HTTPException(409, "The source DAST common report is unavailable, so verification cannot be merged.") from None
        exporter_path = ROOT / "dast-engine" / "results" / "common_export.py"
        spec = importlib.util.spec_from_file_location("cyberforge_dast_common_export", exporter_path)
        exporter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(exporter)
        verified = exporter.finding_to_common(outcome["finding"])
        if not any(item["id"] == verified["id"] for item in dast_doc["findings"]):
            dast_doc["findings"].append(verified)
        dast_doc.setdefault("stats", {})["finding_count"] = len(dast_doc["findings"])

        verification_dir = ROOT / "out" / "scans" / ("verify-" + uuid.uuid4().hex[:10])
        verification_dir.mkdir(parents=True, exist_ok=True)
        new_dast_path = verification_dir / "dast.common.json"
        new_dast_path.write_text(json.dumps(dast_doc, indent=2), encoding="utf-8")
        output_path = verification_dir / "issues.json"
        sast_path = Path(report["inputs"]["sast"]["path"])
        if not sast_path.is_absolute():
            sast_path = (ROOT / sast_path).resolve()
        correlation = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "correlator.cli", "--sast", str(sast_path), "--dast", str(new_dast_path),
            "--out", str(output_path), cwd=str(ROOT), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await correlation.communicate()
        if correlation.returncode != 0:
            raise HTTPException(500, "Could not correlate verification evidence: " + err.decode("utf-8", "replace")[-800:])
        verified_issue = next((item for item in json.loads(output_path.read_text(encoding="utf-8"))["issues"]
                               if code_finding["id"] in item["sast_ids"]), None)
        new_job = scans.record_verification(target_id, target_url, output_path, issue_id,
                                            time.monotonic() - verification_started)
        return {"reproduced": True, "message": "Runtime evidence was added and the correlated report was refreshed.",
                "finding": verified, "issue": verified_issue, "scan": new_job, "log": out.decode("utf-8", "replace")[-1200:]}

    @app.get("/api/scans")
    def list_scans():
        return {"scans": scans.list_jobs()}

    @app.get("/api/scans/compare")
    def compare_scans(baseline: str, current: str):
        old, new = scans.get_job(baseline), scans.get_job(current)
        if not old or not new:
            raise HTTPException(404, "Choose two scans from this server's history.")
        if old["status"] != "complete" or new["status"] != "complete":
            raise HTTPException(409, "Both scans must be complete before comparing them.")
        try:
            old_report = json.loads(Path(old["report_path"]).read_text(encoding="utf-8"))
            new_report = json.loads(Path(new["report_path"]).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise HTTPException(404, "A scan report is no longer available.") from None
        before = {item["issue_id"]: item for item in old_report["issues"]}
        after = {item["issue_id"]: item for item in new_report["issues"]}
        return {
            "baseline": {"id": baseline, "target": old["target_name"], "completed_at": old["completed_at"]},
            "current": {"id": current, "target": new["target_name"], "completed_at": new["completed_at"]},
            "new": [after[k] for k in sorted(after.keys() - before.keys())],
            "fixed": [before[k] for k in sorted(before.keys() - after.keys())],
            "still_open": [after[k] for k in sorted(after.keys() & before.keys())],
        }

    @app.get("/api/scans/{scan_id}/routes")
    def get_routes(scan_id: str):
        job = scans.get_job(scan_id)
        if not job:
            raise HTTPException(404, "Scan not found.")
        try:
            report = json.loads(Path(job["report_path"]).read_text(encoding="utf-8"))
            sast_file = Path(report["inputs"]["sast"]["path"])
            if not sast_file.is_absolute():
                sast_file = (ROOT / sast_file).resolve()
            route_file = sast_file.parent / "routes.json"
            routes = json.loads(route_file.read_text(encoding="utf-8")).get("routes", [])
        except (OSError, ValueError):
            routes = []
            route_file = Path()
        return {"routes": routes, "available": bool(routes) or route_file.is_file()}

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        job = scans.get_job(scan_id)
        if not job:
            raise HTTPException(404, "Scan not found.")
        return job

    @app.post("/api/scans/{scan_id}/stop")
    async def stop_scan(scan_id: str):
        job = await scans.stop(scan_id)
        if not job:
            raise HTTPException(404, "Scan not found.")
        return job

    @app.get("/api/export")
    def export_json():
        return JSONResponse(read_report(), headers={"Content-Disposition": 'attachment; filename="issues.json"'})

    @app.get("/api/export/html", response_class=HTMLResponse)
    def export_html():
        return HTMLResponse(render(read_report()), headers={"Content-Disposition": 'attachment; filename="issues.html"'})

    @app.get("/api/export/sarif")
    def export_sarif():
        report = read_report()
        results = []
        for issue in report["issues"]:
            severity = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}[issue["severity"]]
            result = {
                "ruleId": issue["cwe"],
                "level": severity,
                "message": {"text": f"{issue['label']}: {issue['title']} (CVSS {issue['risk_score']})"},
                "properties": {"issueId": issue["issue_id"], "label": issue["label"], "riskScore": issue["risk_score"],
                               "runtimeEvidence": issue["evidence"]["runtime"], "dastIds": issue["dast_ids"]},
            }
            code = next((f for f in issue["evidence"]["code"] if f.get("code")), None)
            if code:
                result["locations"] = [{"physicalLocation": {
                    "artifactLocation": {"uri": code["code"]["file"]},
                    "region": {"startLine": code["code"]["line"], "snippet": {"text": code["code"].get("snippet", "")}},
                }}]
            results.append(result)
        rules = sorted({
            issue["cwe"] for issue in report["issues"]
        })
        return JSONResponse({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "CyberForge", "rules": [
                {"id": rule, "shortDescription": {"text": rule}} for rule in rules
            ]}}, "results": results}],
        }, headers={"Content-Disposition": 'attachment; filename="cyberforge.sarif.json"'})

    # API routes are registered first so missing endpoints cannot fall through to the SPA.
    @app.get("/api/{rest:path}")
    def unknown_api(rest: str):
        raise HTTPException(404, "API endpoint not found.")

    if (WEB / "dist/index.html").exists():
        app.mount("/", StaticFiles(directory=WEB / "dist", html=True), name="workspace")
    else:
        @app.get("/", response_class=HTMLResponse)
        def build_instructions():
            return HTMLResponse("<h1>Build the workspace</h1><p>Run <code>cd web &amp;&amp; npm install &amp;&amp; npm run build</code>, then restart the server.</p>", status_code=503)

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default="out/issues.json", help="Correlator JSON report, relative to the current directory")
    parser.add_argument("--example", action="store_true", help="Open the bundled, clearly labelled example report")
    parser.add_argument("--port", default=8000, type=int)
    parser.add_argument("--host", default="127.0.0.1",
                        help="Address to bind. Keep 127.0.0.1 unless running in a container, where Docker publishes the port on loopback only")
    args = parser.parse_args()
    import uvicorn

    uvicorn.run(create_app(WEB / "example.issues.json" if args.example else args.report, example=args.example),
                host=args.host, port=args.port)


if __name__ == "__main__":
    main()
