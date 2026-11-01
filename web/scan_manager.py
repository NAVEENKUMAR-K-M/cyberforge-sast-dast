"""Local orchestration for the built-in SAST, DAST and correlation CLIs."""
from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberforge.runtime import (  # noqa: E402
    CUSTOM_LANGUAGES, CUSTOM_TARGET_ID, allowed_hosts, custom_only, python_for, resolve_source, workspace_root,
)

OUT = ROOT / "out" / "scans"
SAST_PYTHON = python_for("sast")
DAST_PYTHON = python_for("dast")
PYTHON = sys.executable
# The dependency analysis looks advisories up on the network; a slow or unreachable service must not hold a scan up.
SCA_SECONDS = 150

TARGETS = {
    "dvwa": {
        "name": "DVWA",
        "url": "http://localhost:8080",
        "source": ROOT / "benchmarks" / "dvwa",
        "language": "php",
        "sast_supported": True,
        "config": ROOT / "dast-engine" / "dvwa.yaml",
        "description": "Local PHP target. The DVWA app must be running before a scan.",
    },
    "juice_shop": {
        "name": "OWASP Juice Shop",
        "url": "http://localhost:3000",
        "source": ROOT / "benchmarks" / "juice-shop",
        "language": "javascript",
        "sast_supported": False,
        "config": ROOT / "dast-engine" / "config.yaml",
        "description": "DAST is supported. The SAST engine analyzes PHP and Python, not JavaScript.",
    },
    "benchmark_shop": {
        "name": "CyberForge Benchmark Shop",
        "url": "http://127.0.0.1:8088",
        "source": ROOT / "sast-engine" / "benchmarks" / "shop",
        "language": "php",
        "sast_supported": True,
        "config": ROOT / "dast-engine" / "shop.yaml",
        "description": "Bundled PHP target. Start it with the repository Docker Compose file.",
    },
    "python_shop": {
        "name": "CyberForge Python Shop",
        "url": "http://127.0.0.1:8089",
        "source": ROOT / "sast-engine" / "benchmarks" / "pyshop",
        "language": "python",
        "sast_supported": True,
        "config": ROOT / "dast-engine" / "pyshop.yaml",
        "description": "Bundled Flask target. Start it with sast-engine/benchmarks/pyshop/docker-compose.yml.",
    },
    "fastshop": {
        "name": "CyberForge FastAPI Shop",
        "url": "http://127.0.0.1:8091",
        "source": ROOT / "sast-engine" / "benchmarks" / "fastshop",
        "language": "python",
        "sast_supported": True,
        "config": ROOT / "dast-engine" / "config.yaml",
        "description": "Bundled FastAPI target. Start with uvicorn main:app --host 127.0.0.1 --port 8091 from sast-engine/benchmarks/fastshop.",
    },
    "laravel_shop": {
        "name": "CyberForge Laravel Shop",
        "url": "http://127.0.0.1:8092",
        "source": ROOT / "sast-engine" / "benchmarks" / "lashop" / "overlay",
        "language": "php",
        "sast_supported": True,
        "config": ROOT / "dast-engine" / "config.yaml",
        "description": "Bundled Laravel 11 target. Start with docker compose -f sast-engine/benchmarks/lashop/docker-compose.yml up -d --build.",
    },
    "django_shop": {
        "name": "CyberForge Django Shop",
        "url": "http://127.0.0.1:8093",
        "source": ROOT / "sast-engine" / "benchmarks" / "djshop",
        "language": "python",
        "sast_supported": True,
        "config": ROOT / "dast-engine" / "config.yaml",
        "description": "Bundled Django 5 target. Start with docker compose -f sast-engine/benchmarks/djshop/docker-compose.yml up -d --build.",
    },
}


def _unreachable(url: str, timeout: float = 10.0) -> str | None:
    """Why nothing answers at this URL, or None when something does. Any HTTP status counts as an answer (a 404 is
    one); the certificate is not checked, because this only asks whether the application is there."""
    try:
        urllib.request.urlopen(urllib.request.Request(url), timeout=timeout, context=ssl._create_unverified_context()).close()
    except urllib.error.HTTPError:
        return None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"Nothing answered at {url} ({getattr(exc, 'reason', exc)}). Is the application running, and is the URL right?"
    return None


class ScanManager:
    def __init__(self):
        self.jobs: dict[str, dict] = {}
        self.latest_report: Path | None = None
        self.latest_job: str | None = None
        self.tasks: dict[str, asyncio.Task] = {}
        self.processes: dict[str, asyncio.subprocess.Process] = {}
        self.lock = asyncio.Lock()
        self._restore_history()

    def _restore_history(self):
        """Recover completed local reports after the UI server restarts."""
        if not OUT.is_dir():
            return
        recovered = []
        for folder in OUT.iterdir():
            report_path = folder / "issues.json"
            if not folder.is_dir() or not report_path.is_file():
                continue
            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
                report_time = report_path.stat().st_mtime
                manifest_path = folder / "scan.json"
                if manifest_path.is_file():
                    job = json.loads(manifest_path.read_text(encoding="utf-8"))
                else:
                    target_url = data.get("inputs", {}).get("dast", {}).get("target", "")
                    port = urlsplit(target_url).port
                    target_id = next((key for key, item in TARGETS.items() if urlsplit(item["url"]).port == port), "dvwa")
                    target = TARGETS[target_id]
                    timestamp = datetime.fromtimestamp(report_time, timezone.utc).isoformat()
                    job = {
                        "id": folder.name,
                        "target_id": target_id,
                        "target_name": target["name"],
                        "target_url": target_url,
                        "status": "complete",
                        "stage": "Recovered report",
                        "created_at": timestamp,
                        "started_at": None,
                        "completed_at": timestamp,
                        "elapsed_seconds": None,
                        "options": {"run_sast": bool(data.get("inputs", {}).get("sast", {}).get("target")),
                                    "run_dast": bool(target_url)},
                        "error": None,
                        "report_path": str(report_path),
                        "gate": None,
                        "restored": True,
                    }
                job["logs"] = []
                job["restored"] = True
                self.jobs[job["id"]] = job
                if job["status"] == "complete":
                    recovered.append((report_time, job["id"], report_path))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        if recovered:
            _, self.latest_job, self.latest_report = max(recovered)

    @staticmethod
    def _persist_job(job: dict):
        """Persist timing and scan metadata, but never logs or authentication data."""
        folder = Path(job["report_path"]).parent
        if not folder.is_dir():
            return
        metadata = {key: value for key, value in job.items() if key not in {"logs", "auth"}}
        (folder / "scan.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def targets(self) -> list[dict]:
        result = []
        if not custom_only():
            for target_id, target in TARGETS.items():
                source = target["source"]
                result.append({
                    "id": target_id,
                    "name": target["name"],
                    "url": target["url"],
                    "language": target["language"],
                    "sast_supported": target["sast_supported"],
                    "source_available": source.is_dir(),
                    "description": target["description"],
                })
        root = workspace_root()
        result.append({
            "id": CUSTOM_TARGET_ID,
            "name": "Custom application",
            "url": "",
            "language": "auto",
            "sast_supported": True,
            "source_available": True,
            "custom": True,
            "default_source": str(root) if root else "",
            "description": "Scan any application on this machine: give its source folder and the URL where it runs. "
                           + (f"The source must be inside {root}. " if root else "") + "Untick SAST to run only the runtime scan, or DAST for only the source scan.",
        })
        return result

    def target_for(self, target_id: str | None) -> dict | None:
        """The target record for a built-in id, or, for a custom run, the one stored on the job whose report is open."""
        if target_id in TARGETS:
            return TARGETS[target_id]
        if target_id != CUSTOM_TARGET_ID:
            return None
        job = self.jobs.get(self.latest_job or "")
        spec = (job or {}).get("target_spec")
        return self._spec_target(spec) if spec else None

    @staticmethod
    def _spec_target(spec: dict) -> dict:
        return {"name": spec["name"], "url": spec.get("url", ""), "source": Path(spec["source"]) if spec.get("source") else None,
                "language": spec.get("language", "auto"), "sast_supported": True, "config": None, "description": "Custom application"}

    @classmethod
    def _custom_target(cls, request: dict, run_sast: bool, url: str) -> tuple[dict, dict]:
        language = request.get("language", "auto")
        if language not in CUSTOM_LANGUAGES:
            raise ValueError("Choose auto, php or python as the source language.")
        source = resolve_source(request.get("source_path")) if run_sast else None
        label = source.name if source else (urlsplit(url).netloc or "custom")
        spec = {"name": f"Custom application ({label})", "source": str(source) if source else "", "language": language, "url": url}
        return cls._spec_target(spec), spec

    @staticmethod
    def validate_target_url(value: str) -> str:
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError("Enter a local target URL.")
        parsed = urlsplit(value.strip())
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError("Use an http(s) URL without embedded credentials.")
        host = (parsed.hostname or "").lower()
        if host not in allowed_hosts():
            raise ValueError("For safety, scans can target only this machine: " + ", ".join(sorted(allowed_hosts())) + ".")
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("The target URL has an invalid port.") from None
        if port is None or not (1 <= port <= 65535):
            raise ValueError("Specify the local application's port in the target URL.")
        if parsed.query or parsed.fragment:
            raise ValueError("Enter the application base URL without a query or fragment.")
        return value.strip().rstrip("/")

    @classmethod
    def validate_auth(cls, value) -> dict:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("Authentication settings must be an object.")
        auth = dict(value)
        for field in ("login_url", "username", "password", "bearer_token"):
            if auth.get(field) is not None and not isinstance(auth[field], str):
                raise ValueError(f"{field.replace('_', ' ').capitalize()} must be text.")
            if len(auth.get(field) or "") > 4096:
                raise ValueError(f"{field.replace('_', ' ').capitalize()} is too long.")
        for field, marker in (("headers", ":"), ("cookies", "=")):
            items = auth.get(field, [])
            if not isinstance(items, list) or len(items) > 10:
                raise ValueError(f"Provide up to 10 {field} as separate lines.")
            if any(not isinstance(item, str) or marker not in item or len(item) > 4096 or "\r" in item or "\n" in item for item in items):
                raise ValueError(f"Each {field[:-1]} must be a valid single-line value.")
        auth["headers"] = [item.strip() for item in auth.get("headers", [])]
        auth["cookies"] = [item.strip() for item in auth.get("cookies", [])]
        return auth

    async def start(self, request: dict) -> dict:
        target_id = request.get("target_id")
        run_sast = request.get("run_sast") is True
        run_dast = request.get("run_dast") is True
        if not run_sast and not run_dast:
            raise ValueError("Choose SAST, DAST, or both.")
        target_spec = None
        if target_id == CUSTOM_TARGET_ID:
            # A custom application has no fixed port, so the only gates are the host allow-list and, for the
            # source, the workspace folder. DAST gets no config file, so its scope is exactly this one target.
            url = self.validate_target_url(request.get("target_url", "")) if run_dast else ""
            target, target_spec = self._custom_target(request, run_sast, url)
        else:
            if target_id not in TARGETS or custom_only():
                raise ValueError("Choose one of the available local test applications.")
            target = TARGETS[target_id]
            url = self.validate_target_url(request.get("target_url", target["url"]))
            expected_port = urlsplit(target["url"]).port
            if urlsplit(url).port != expected_port:
                raise ValueError(f"{target['name']} scans must use its configured local port {expected_port}.")
            if run_sast and not target["sast_supported"]:
                raise ValueError("The SAST engine supports PHP and Python; Juice Shop can run DAST only.")
            if run_sast and not target["source"].is_dir():
                raise ValueError(f"Source folder is missing: {target['source']}")
        backend = request.get("active_backend", "python")
        if backend not in {"python", "none", "zap", "nuclei"}:
            raise ValueError("Choose a supported DAST backend.")
        try:
            deadline = int(request.get("deadline_seconds", 480))
        except (ValueError, TypeError):
            raise ValueError("Scan deadline must be between 30 and 600 seconds.") from None
        if not 30 <= deadline <= 600:
            raise ValueError("Scan deadline must be between 30 and 600 seconds.")
        base_path = request.get("base_path", "")
        if not isinstance(base_path, str) or (base_path and not re.fullmatch(r"/[A-Za-z0-9._~/-]+", base_path)):
            raise ValueError("Base path must be an empty path or start with / and contain only URL path characters.")
        web_root = request.get("web_root", "")
        if not isinstance(web_root, str) or (web_root and (Path(web_root).is_absolute() or ".." in web_root.replace("\\", "/").split("/"))):
            raise ValueError("Web root must be a relative folder inside the selected source tree.")
        excludes = request.get("exclude", [])
        if not isinstance(excludes, list) or len(excludes) > 20 or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", item) for item in excludes):
            raise ValueError("Exclude values must be folder names such as vendor or tests.")
        auth = self.validate_auth(request.get("auth"))
        for key in ("login_url", "username", "password", "bearer_token"):
            if key == "login_url" and auth.get(key):
                checked = self.validate_target_url(auth[key])
                if urlsplit(checked).netloc.lower() != urlsplit(url).netloc.lower():
                    raise ValueError("The login URL must use the same local host and port as the target.")
        request["auth"] = auth

        scan_id = uuid.uuid4().hex[:12]
        folder = OUT / scan_id
        job = {
            "id": scan_id,
            "target_id": target_id,
            "target_name": target["name"],
            "target_url": url,
            "status": "queued",
            "stage": "Queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "completed_at": None,
            "elapsed_seconds": None,
            "options": {"run_sast": run_sast, "run_dast": run_dast, "active_backend": backend,
                        "deadline_seconds": deadline, "sarif": bool(request.get("sarif")),
                        "ci_gate": bool(request.get("ci_gate")), "semgrep": request.get("semgrep") is not False,
                        "web_root": web_root, "exclude": excludes[:20],
                        "use_route_map": request.get("use_route_map") is True,
                        "use_sast_hints": request.get("use_sast_hints") is not False,
                        "use_sca": request.get("use_sca") is not False},
            "logs": [],
            "error": None,
            "report_path": str(folder / "issues.json"),
            "gate": None,
        }
        if target_spec:
            job["target_spec"] = target_spec
        async with self.lock:
            active = [j for j in self.jobs.values() if j["status"] in {"queued", "running", "stopping"}]
            if active:
                raise ValueError("A scan is already running. Wait for it to finish or stop it first.")
            self.jobs[scan_id] = job
            task = asyncio.create_task(self._run(scan_id, request, target, folder))
            self.tasks[scan_id] = task
        return self.public_job(job)

    async def start_investigation(self, scan_id: str, provider: str, model: str | None,
                                  report: dict) -> dict:
        """Start the correlator's bounded, opt-in AI investigation for a completed scan."""
        from correlator.env import load_env
        from correlator.planner import PROVIDERS

        if provider not in PROVIDERS:
            raise ValueError("Choose a supported AI provider.")
        if model is not None and not isinstance(model, str):
            raise ValueError("Model name must be text.")
        model = model.strip() if isinstance(model, str) else ""
        if len(model) > 120 or any(ord(char) < 32 for char in model):
            raise ValueError("Model name must be 120 characters or fewer.")
        load_env()
        key_name = PROVIDERS[provider][1]
        if not os.environ.get(key_name):
            raise ValueError(f"{provider.title()} is not configured. Set {key_name} in the server environment or repository .env.")
        if provider == "openai" and not model:
            raise ValueError("Enter an OpenAI model id. The correlator's default model is intended for Groq.")

        original = self.jobs.get(scan_id)
        if not original or original.get("status") != "complete":
            raise ValueError("Choose a completed live scan to investigate.")
        current_report = self.latest_report
        if not current_report or current_report.resolve() != Path(original["report_path"]).resolve():
            raise ValueError("The selected scan is not the report currently open in the workspace.")
        if original.get("options", {}).get("investigation"):
            raise ValueError("An AI investigation report cannot start another investigation.")
        if any(j.get("status") == "complete" and j.get("options", {}).get("source_scan_id") == scan_id
               for j in self.jobs.values()):
            raise ValueError("This scan already has an AI investigation report.")
        sast_target = report.get("inputs", {}).get("sast", {}).get("target")
        if not sast_target:
            raise ValueError("This report has no source folder for the bounded investigation loop.")
        custom_spec = original.get("target_spec")
        if custom_spec and custom_spec.get("source"):
            source_root = Path(custom_spec["source"]).resolve()   # checked against the workspace when the scan started
        else:
            source_path = Path(sast_target)
            source_root = (source_path if source_path.is_absolute() else ROOT / source_path).resolve()
            try:
                source_root.relative_to(ROOT.resolve())
            except ValueError:
                raise ValueError("Investigation source must be inside this CyberForge workspace.") from None
        if not source_root.is_dir():
            raise ValueError("The scanned source folder is no longer available.")
        runtime_target = report.get("inputs", {}).get("dast", {}).get("target", "")
        try:
            checked_target = self.validate_target_url(runtime_target)
        except ValueError as exc:
            raise ValueError("The report does not contain a valid local runtime target for investigation.") from exc
        if urlsplit(checked_target).netloc.lower() != urlsplit(original["target_url"]).netloc.lower():
            raise ValueError("Investigation must use the same local runtime target as the selected scan.")

        scan_id_new = "ai-" + uuid.uuid4().hex[:10]
        folder = OUT / scan_id_new
        job = {
            "id": scan_id_new,
            "target_id": original["target_id"],
            "target_name": original["target_name"],
            "target_url": original["target_url"],
            "status": "queued",
            "stage": "Queued for AI investigation",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "completed_at": None,
            "elapsed_seconds": None,
            "options": {"investigation": True, "source_scan_id": scan_id,
                        "provider": provider, "model": model or None},
            "logs": [],
            "error": None,
            "report_path": str(folder / "issues.json"),
            "gate": None,
        }
        if custom_spec:
            job["target_spec"] = custom_spec
        async with self.lock:
            active = [j for j in self.jobs.values() if j["status"] in {"queued", "running", "stopping"}]
            if active:
                raise ValueError("A scan or investigation is already running. Wait for it to finish first.")
            self.jobs[scan_id_new] = job
            task = asyncio.create_task(self._run_investigation(scan_id_new, scan_id, report, source_root, folder))
            self.tasks[scan_id_new] = task
        return self.public_job(job)

    @staticmethod
    def public_job(job: dict) -> dict:
        # Credentials are never included in job data or returned to the browser.
        return {key: value for key, value in job.items() if key != "auth"}

    def list_jobs(self) -> list[dict]:
        return [self.public_job(j) for j in sorted(self.jobs.values(), key=lambda x: x["created_at"], reverse=True)]

    def get_job(self, scan_id: str) -> dict | None:
        job = self.jobs.get(scan_id)
        return self.public_job(job) if job else None

    async def stop(self, scan_id: str) -> dict | None:
        job = self.jobs.get(scan_id)
        if not job:
            return None
        if job["status"] in {"queued", "running"}:
            job["status"] = "stopping"
            process = self.processes.get(scan_id)
            if process and process.returncode is None:
                process.terminate()
            task = self.tasks.get(scan_id)
            if task:
                task.cancel()
        return self.public_job(job)

    def get_report_path(self, fallback: Path) -> Path:
        return self.latest_report or fallback

    def record_verification(self, target_id: str, target_url: str, report_path: Path, issue_id: str, elapsed_seconds: float) -> dict:
        scan_id = "verify-" + uuid.uuid4().hex[:10]
        target = self.target_for(target_id)
        custom_spec = (self.jobs.get(self.latest_job or "") or {}).get("target_spec") if target_id == CUSTOM_TARGET_ID else None
        job = {
            "id": scan_id,
            "target_id": target_id,
            "target_name": target["name"],
            "target_url": target_url,
            "status": "complete",
            "stage": "Verification complete",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed_seconds, 2),
            "options": {"run_sast": False, "run_dast": True, "verification_of": issue_id},
            "logs": [f"Re-tested code-only issue {issue_id} at its mapped local route."],
            "error": None,
            "report_path": str(report_path),
            "gate": None,
        }
        if custom_spec:
            job["target_spec"] = custom_spec
        self.jobs[scan_id] = job
        self.latest_report = report_path
        self.latest_job = scan_id
        self._persist_job(job)
        return self.public_job(job)

    async def _log(self, scan_id: str, message: str):
        job = self.jobs[scan_id]
        job["logs"].append(message.rstrip())
        job["logs"] = job["logs"][-800:]

    async def _command(self, scan_id: str, label: str, executable: Path, args: list[str], cwd: Path):
        if not executable.is_file():
            raise RuntimeError(f"{label} environment is not installed: {executable}")
        await self._log(scan_id, f"$ {label}")
        process = await asyncio.create_subprocess_exec(
            str(executable), *args, cwd=str(cwd), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.processes[scan_id] = process
        assert process.stdout is not None
        async for raw in process.stdout:
            await self._log(scan_id, raw.decode("utf-8", "replace"))
        code = await process.wait()
        self.processes.pop(scan_id, None)
        if code != 0:
            raise RuntimeError(f"{label} exited with code {code}.")

    async def _dependency_analysis(self, scan_id: str, source: Path, routes: Path, folder: Path) -> Path | None:
        """Reachability-aware dependency analysis of a Composer application. It adds to a scan and never fails one:
        if it errors, times out or can't reach the advisory services, the scan carries on without a dependencies
        section and the log says why."""
        out = folder / "sca"
        args = ["-m", "sca.cli", "scan", str(source), "--routes", str(routes), "--out", str(out)]
        try:
            await asyncio.wait_for(self._command(scan_id, "Dependency analysis", SAST_PYTHON, args, ROOT), timeout=SCA_SECONDS)
        except asyncio.TimeoutError:
            process = self.processes.pop(scan_id, None)
            if process and process.returncode is None:
                process.terminate()
            await self._log(scan_id, f"Dependency analysis stopped after {SCA_SECONDS} seconds; the scan continues without it.")
            return None
        except RuntimeError as exc:
            await self._log(scan_id, f"Dependency analysis skipped: {exc}")
            return None
        report = out / "sca.json"
        return report if report.is_file() else None

    async def _run(self, scan_id: str, request: dict, target: dict, folder: Path):
        job = self.jobs[scan_id]
        job["status"] = "running"
        job["started_at"] = datetime.now(timezone.utc).isoformat()
        started_clock = time.monotonic()
        try:
            folder.mkdir(parents=True, exist_ok=True)
            sast_common = folder / "sast.common.json"
            dast_native = folder / "dast.json"
            dast_common = folder / "dast.common.json"
            sast_routes = folder / "routes.json"
            sast_hints = folder / "hints.json"
            output = folder / "issues.json"
            base_path = request.get("base_path", "")
            url = job["target_url"]
            if job["options"]["run_dast"]:
                # Without this, an app that isn't up gets minutes of requests that all fail, then an ordinary-looking
                # report with no runtime findings.
                problem = await asyncio.to_thread(_unreachable, url)
                if problem:
                    raise RuntimeError(problem)

            if job["options"]["run_sast"]:
                job["stage"] = "Source analysis"
                args = ["-m", "sast.cli", "scan", str(target["source"]), "--out", str(folder / "sast"),
                        "--language", target["language"]]
                if job["options"]["sarif"]:
                    args.append("--sarif")
                if job["options"]["web_root"]:
                    args += ["--web-root", job["options"]["web_root"]]
                if not job["options"]["semgrep"]:
                    args.append("--no-semgrep")
                for excluded in job["options"]["exclude"]:
                    args += ["--exclude", excluded]
                if base_path:
                    args += ["--base-path", base_path]
                await self._command(scan_id, "SAST scan", SAST_PYTHON, args, ROOT / "sast-engine")
                sast_common = folder / "sast" / "findings.common.json"
                sast_routes = folder / "sast" / "routes.json"
                sast_hints = folder / "sast" / "hints.json"
            else:
                sast_common.write_text(json.dumps({"schema_version": "1.0", "source": "sast", "tool": "cyberforge-sast",
                    "target": str(target["source"] or ""), "stats": {"files": 0, "entry_points": 0, "routes": 0, "seconds": 0}, "findings": []}, indent=2), encoding="utf-8")

            sca_report = None
            source = Path(target["source"]) if target["source"] else None
            if job["options"]["run_sast"] and job["options"]["use_sca"] and source and (source / "composer.lock").is_file():
                job["stage"] = "Source analysis (dependencies)"   # keeps the first stage lit in the progress rail
                sca_report = await self._dependency_analysis(scan_id, source, sast_routes, folder)
            job["options"]["dependency_analysis"] = sca_report is not None

            if job["options"]["run_dast"]:
                job["stage"] = "Runtime analysis"
                args = [str(ROOT / "dast-engine" / "main.py"), "scan", "--target", url,
                        "--output", str(dast_native),
                        "--active-backend", job["options"]["active_backend"],
                        "--deadline", str(job["options"]["deadline_seconds"])]
                if target["config"]:   # a custom application has none: DAST then scopes itself to exactly this target
                    args += ["--config", str(target["config"])]
                if job["options"]["run_sast"] and job["options"]["use_route_map"]:
                    args += ["--route-map", str(sast_routes)]
                if job["options"]["run_sast"] and job["options"]["use_sast_hints"]:
                    args += ["--hints", str(sast_hints)]
                auth = request.get("auth") or {}
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
                await self._command(scan_id, "DAST scan", DAST_PYTHON, args, ROOT / "dast-engine")
                if not dast_common.is_file():
                    raise RuntimeError("DAST finished without writing its common-format report.")
            else:
                dast_common.write_text(json.dumps({"schema_version": "1.0", "source": "dast", "tool": "cyberforge-dast",
                    "target": url, "stats": {"elapsed_seconds": 0, "request_count": 0, "finding_count": 0, "coverage": {}}, "findings": []}, indent=2), encoding="utf-8")

            job["stage"] = "Correlating findings"
            args = ["-m", "correlator.cli", "--sast", str(sast_common), "--dast", str(dast_common), "--out", str(output)]
            if base_path:
                args += ["--base-path", base_path]
            if sca_report:
                args += ["--sca", str(sca_report)]
            # Auto-verify (B-1) is part of the correlation engine, not a manual extra step: whenever both
            # scans actually ran, every scan gets the deterministic round-1 re-test for free. A configured
            # AI key additionally unlocks the bounded, bigger-picture round 2 -- no key, no network call,
            # no cost; it only widens what round 1 already does safely with no third party involved.
            investigation_included = False
            if job["options"]["run_sast"] and job["options"]["run_dast"]:
                args += ["--investigate", "--max-cases", "20", "--budget", "180", "--dast-python", str(DAST_PYTHON)]
                if target["config"]:
                    args += ["--dast-config", str(target["config"])]
                investigation_included = True
                from correlator.env import load_env
                from correlator.planner import PROVIDERS

                load_env()
                provider = next((p for p in ("groq", "openai") if p in PROVIDERS and os.environ.get(PROVIDERS[p][1])), None)
                if provider and request.get("use_ai") is not False:
                    args += ["--planner", provider, "--source-root", str(target["source"])]
            job["options"]["investigation_included"] = investigation_included
            await self._command(scan_id, "Correlation", Path(PYTHON), args, ROOT)
            if not output.is_file():
                raise RuntimeError("Correlation finished without writing issues.json.")
            self.latest_report = output
            self.latest_job = scan_id
            if job["options"]["ci_gate"]:
                report = json.loads(output.read_text(encoding="utf-8"))
                blocked = [i for i in report["issues"] if i["label"] == "Confirmed" and i["severity"] in {"critical", "high"}]
                job["gate"] = {"passed": not blocked, "threshold": "confirmed high or critical", "count": len(blocked)}
            job["status"] = "complete"
            job["stage"] = "Complete"
        except asyncio.CancelledError:
            job["status"] = "stopped"
            job["stage"] = "Stopped"
            await self._log(scan_id, "Scan stopped by operator.")
        except Exception as exc:  # surfaced in job detail; the server remains available
            job["status"] = "failed"
            job["stage"] = "Failed"
            job["error"] = str(exc)
            await self._log(scan_id, f"ERROR: {exc}")
        finally:
            job["completed_at"] = datetime.now(timezone.utc).isoformat()
            job["elapsed_seconds"] = round(time.monotonic() - started_clock, 2)
            self.processes.pop(scan_id, None)
            self._persist_job(job)

    async def _run_investigation(self, job_id: str, source_scan_id: str, report: dict,
                                 source_root: Path, folder: Path):
        job = self.jobs[job_id]
        original = self.jobs[source_scan_id]
        job["status"] = "running"
        job["started_at"] = datetime.now(timezone.utc).isoformat()
        started_clock = time.monotonic()
        try:
            folder.mkdir(parents=True, exist_ok=True)
            def report_path(source: str) -> Path:
                value = Path(report["inputs"][source]["path"])
                return value.resolve() if value.is_absolute() else (ROOT / value).resolve()

            sast_path, dast_path = report_path("sast"), report_path("dast")
            for candidate in (sast_path, dast_path):
                try:
                    candidate.relative_to(ROOT.resolve())
                except ValueError:
                    raise RuntimeError("Investigation input report must be inside the CyberForge workspace.") from None
                if not candidate.is_file():
                    raise RuntimeError("The original SAST or DAST report is no longer available.")

            target = TARGETS.get(original["target_id"]) or self._spec_target(original["target_spec"])
            args = ["-m", "correlator.cli", "--sast", str(sast_path), "--dast", str(dast_path),
                    "--out", str(folder / "issues.json"), "--investigate", "--planner",
                    job["options"]["provider"], "--source-root", str(source_root),
                    "--dast-engine", str(ROOT / "dast-engine"), "--dast-python", str(DAST_PYTHON),
                    "--max-cases", "20", "--budget", "180"]
            if target["config"]:
                args += ["--dast-config", str(target["config"])]
            if job["options"].get("model"):
                args += ["--planner-model", job["options"]["model"]]
            job["stage"] = "AI-assisted bounded retest and correlation"
            await self._command(job_id, "Opt-in AI investigation", Path(PYTHON), args, ROOT)
            output = Path(job["report_path"])
            if not output.is_file():
                raise RuntimeError("Investigation finished without writing its evidence report.")
            self.latest_report = output
            self.latest_job = job_id
            job["status"] = "complete"
            job["stage"] = "Investigation complete"
        except asyncio.CancelledError:
            job["status"] = "stopped"
            job["stage"] = "Stopped"
            await self._log(job_id, "Investigation stopped by operator.")
        except Exception as exc:
            job["status"] = "failed"
            job["stage"] = "Failed"
            job["error"] = str(exc)
            await self._log(job_id, f"ERROR: {exc}")
        finally:
            job["completed_at"] = datetime.now(timezone.utc).isoformat()
            job["elapsed_seconds"] = round(time.monotonic() - started_clock, 2)
            self.processes.pop(job_id, None)
            self._persist_job(job)
