"""Serve one correlated report locally: python -m web.server --report out/issues.json."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from correlator.report import render

ROOT = Path(__file__).resolve().parents[1]
WEB = Path(__file__).resolve().parent
VALIDATOR = jsonschema.Draft202012Validator(json.loads((ROOT / "correlator/issues.schema.json").read_text()))


def create_app(report_path: Path | str = "out/issues.json", *, example: bool = False) -> FastAPI:
    """The server reads a fixed operator-selected file. It never scans or fetches a target."""
    path = Path(report_path).resolve()
    app = FastAPI(title="CyberForge", docs_url=None, redoc_url=None, openapi_url=None)

    def read_report() -> dict:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
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
        notes = []
        stats = {}
        for source in ("sast", "dast"):
            stats[source], note = source_stats(report, source)
            if note:
                notes.append(note)
        source = report["inputs"]["sast"].get("target", "")
        name = Path(source.rstrip("/")).name or "Application"
        return {
            "report": report,
            "scan": {
                "name": "Benchmark shop" if example else name,
                "target": report["inputs"]["dast"].get("target", ""),
                "source": source,
                "report_path": str(path),
                "modified_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                "example": example,
                "stats": stats,
                "notes": notes,
            },
        }

    @app.get("/api/export")
    def export_json():
        return JSONResponse(read_report(), headers={"Content-Disposition": 'attachment; filename="issues.json"'})

    @app.get("/api/export/html", response_class=HTMLResponse)
    def export_html():
        return HTMLResponse(render(read_report()), headers={"Content-Disposition": 'attachment; filename="issues.html"'})

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
    args = parser.parse_args()
    import uvicorn

    uvicorn.run(create_app(WEB / "example.issues.json" if args.example else args.report, example=args.example),
                host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
