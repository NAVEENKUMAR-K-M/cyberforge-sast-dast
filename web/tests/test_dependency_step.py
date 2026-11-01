"""The dependency analysis inside a scan: when it runs, what it is handed, and that it can never fail a scan.

The real ScanManager._run runs; only the subprocess runner is replaced by one that records each command and writes
the files that step would have written.
"""
import asyncio
import json
from pathlib import Path

import pytest

from web import scan_manager
from web.scan_manager import ScanManager


@pytest.fixture(autouse=True)
def isolated_scan_history(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_manager, "OUT", tmp_path / "scan-history")


def value(args, flag):
    return args[args.index(flag) + 1]


class FakeProcess:
    returncode = None

    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True


class Recorder:
    """Stands in for ScanManager._command. `sca` is how the dependency step behaves: ok, fail, hang or empty."""

    def __init__(self, sca="ok"):
        self.sca, self.calls, self.process = sca, [], FakeProcess()

    async def __call__(self, manager, scan_id, label, executable, args, cwd):
        self.calls.append((label, list(args)))
        if label == "SAST scan":
            out = Path(value(args, "--out"))
            out.mkdir(parents=True, exist_ok=True)
            for name in ("findings.common.json", "routes.json", "hints.json"):
                (out / name).write_text("{}")
        elif label == "Dependency analysis":
            if self.sca == "fail":
                raise RuntimeError("Dependency analysis exited with code 1.")
            if self.sca == "hang":
                manager.processes[scan_id] = self.process
                await asyncio.sleep(30)
            if self.sca == "ok":
                out = Path(value(args, "--out"))
                out.mkdir(parents=True, exist_ok=True)
                (out / "sca.json").write_text(json.dumps({"tool": "cyberforge-sca"}))
        elif label == "DAST scan":
            Path(value(args, "--output")).with_suffix(".common.json").write_text("{}")
        elif label == "Correlation":
            Path(value(args, "--out")).write_text(json.dumps({"issues": []}))

    def labels(self):
        return [label for label, _ in self.calls]

    def args(self, label):
        return next(args for name, args in self.calls if name == label)


def scan(monkeypatch, tmp_path, *, lock=True, sca="ok", **request):
    """Runs one custom scan to the end and returns (job, recorder)."""
    source = tmp_path / "app"
    source.mkdir(exist_ok=True)
    if lock:
        (source / "composer.lock").write_text("{}")
    recorder = Recorder(sca)

    async def command(self, scan_id, label, executable, args, cwd):   # a real function, so it is bound like the method it replaces
        await recorder(self, scan_id, label, executable, args, cwd)

    monkeypatch.setattr(ScanManager, "_command", command)

    async def go():
        manager = ScanManager()
        body = {"target_id": "custom", "source_path": str(source), "language": "php", "target_url": "http://localhost:8081",
                "run_sast": True, "run_dast": True, **request}
        job = await manager.start(body)
        await manager.tasks[job["id"]]
        return manager.jobs[job["id"]]

    return asyncio.run(go()), recorder


def test_runs_after_the_source_scan_and_before_the_runtime_scan(monkeypatch, tmp_path):
    job, recorder = scan(monkeypatch, tmp_path)
    assert job["status"] == "complete"
    assert recorder.labels() == ["SAST scan", "Dependency analysis", "DAST scan", "Correlation"]


def test_it_is_given_the_source_and_the_route_map_the_source_scan_wrote(monkeypatch, tmp_path):
    job, recorder = scan(monkeypatch, tmp_path)
    args = recorder.args("Dependency analysis")
    folder = Path(job["report_path"]).parent
    assert args[:4] == ["-m", "sca.cli", "scan", str((tmp_path / "app").resolve())]
    assert Path(value(args, "--routes")) == folder / "sast" / "routes.json"
    assert Path(value(args, "--out")) == folder / "sca"


def test_the_correlator_is_handed_its_result(monkeypatch, tmp_path):
    job, recorder = scan(monkeypatch, tmp_path)
    folder = Path(job["report_path"]).parent
    assert Path(value(recorder.args("Correlation"), "--sca")) == folder / "sca" / "sca.json"
    assert job["options"]["dependency_analysis"] is True


@pytest.mark.parametrize("why,kwargs", [
    ("the application has no composer.lock", {"lock": False}),
    ("it was switched off", {"use_sca": False}),
    ("the source was not scanned", {"run_sast": False}),
])
def test_it_does_not_run_when_there_is_nothing_to_analyse_or_it_is_off(monkeypatch, tmp_path, why, kwargs):
    job, recorder = scan(monkeypatch, tmp_path, **kwargs)
    assert job["status"] == "complete", why
    assert "Dependency analysis" not in recorder.labels(), why
    assert "--sca" not in recorder.args("Correlation"), why
    assert job["options"]["dependency_analysis"] is False, why


def test_it_runs_by_default(monkeypatch, tmp_path):
    job, _ = scan(monkeypatch, tmp_path)
    assert job["options"]["use_sca"] is True


def test_a_failing_dependency_analysis_never_fails_the_scan(monkeypatch, tmp_path):
    job, recorder = scan(monkeypatch, tmp_path, sca="fail")
    assert job["status"] == "complete" and job["error"] is None
    assert recorder.labels() == ["SAST scan", "Dependency analysis", "DAST scan", "Correlation"]
    assert "--sca" not in recorder.args("Correlation")
    assert any("Dependency analysis skipped" in line and "exited with code 1" in line for line in job["logs"])
    assert job["options"]["dependency_analysis"] is False


def test_a_dependency_analysis_that_never_ends_is_stopped_and_the_scan_goes_on(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_manager, "SCA_SECONDS", 0.05)
    job, recorder = scan(monkeypatch, tmp_path, sca="hang")
    assert job["status"] == "complete"
    assert recorder.process.terminated is True
    assert "--sca" not in recorder.args("Correlation")
    assert any("Dependency analysis stopped after 0.05 seconds" in line for line in job["logs"])
    assert recorder.labels()[-2:] == ["DAST scan", "Correlation"]


def test_a_dependency_analysis_that_writes_nothing_is_not_passed_on(monkeypatch, tmp_path):
    job, recorder = scan(monkeypatch, tmp_path, sca="empty")
    assert job["status"] == "complete" and "--sca" not in recorder.args("Correlation")


def test_the_stage_name_keeps_the_source_stage_lit_in_the_progress_rail(monkeypatch, tmp_path):
    seen = []

    async def go():
        manager = ScanManager()
        recorder = Recorder()

        async def command(self, scan_id, label, executable, args, cwd):
            seen.append((label, self.jobs[scan_id]["stage"]))
            await recorder(self, scan_id, label, executable, args, cwd)

        monkeypatch.setattr(ScanManager, "_command", command)
        source = tmp_path / "app"
        source.mkdir()
        (source / "composer.lock").write_text("{}")
        job = await manager.start({"target_id": "custom", "source_path": str(source), "language": "php",
                                   "target_url": "http://localhost:8081", "run_sast": True, "run_dast": True})
        await manager.tasks[job["id"]]

    asyncio.run(go())
    stage = dict(seen)["Dependency analysis"]
    assert "source" in stage.lower() and "dependenc" in stage.lower()   # the rail lights a step by this word
