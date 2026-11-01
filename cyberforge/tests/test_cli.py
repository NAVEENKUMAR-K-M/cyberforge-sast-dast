import json

import pytest

from cyberforge import cli
from web import scan_manager
from web.scan_manager import ScanManager


@pytest.fixture(autouse=True)
def isolated_scan_history(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_manager, "OUT", tmp_path / "scan-history")


def parse(*argv):
    return cli.build_parser().parse_args(["scan", *argv])


def test_the_request_matches_what_the_workspace_sends_for_a_custom_application():
    request = cli.build_request(parse("--source", "app", "--target", "http://localhost:8081", "--language", "php"))
    assert request["target_id"] == "custom"
    assert (request["source_path"], request["target_url"], request["language"]) == ("app", "http://localhost:8081", "php")
    assert request["run_sast"] is True and request["run_dast"] is True
    assert request["use_route_map"] is True and request["use_sast_hints"] is True   # what lifts runtime detection
    assert request["ci_gate"] is False and request["use_ai"] is True and request["deadline_seconds"] == 480


def test_source_only_and_target_only_runs_switch_off_the_other_scanner():
    assert cli.build_request(parse("--source", "app"))["run_dast"] is False
    assert cli.build_request(parse("--target", "http://localhost:8081"))["run_sast"] is False


def test_flags_map_to_request_fields():
    request = cli.build_request(parse("--target", "http://localhost:1", "--no-ai", "--no-semgrep", "--fail-on", "confirmed-high",
                                      "--deadline", "90", "--header", "X-A:1", "--header", "X-B:2", "--cookie", "s=1",
                                      "--login-url", "http://localhost:1/login", "--username", "u", "--password", "p"))
    assert request["use_ai"] is False and request["semgrep"] is False and request["ci_gate"] is True
    assert request["deadline_seconds"] == 90
    assert request["auth"]["headers"] == ["X-A:1", "X-B:2"] and request["auth"]["cookies"] == ["s=1"]
    assert (request["auth"]["login_url"], request["auth"]["username"], request["auth"]["password"]) == ("http://localhost:1/login", "u", "p")


def test_giving_neither_a_source_nor_a_target_is_a_usage_error():
    with pytest.raises(SystemExit) as stopped:
        cli.main(["scan"])
    assert stopped.value.code == 2


def test_a_host_that_is_not_this_machine_is_refused_before_anything_runs(capsys):
    assert cli.main(["scan", "--target", "http://example.com:80"]) == 2
    assert "only this machine" in capsys.readouterr().err


def test_a_source_folder_that_does_not_exist_is_refused(tmp_path, capsys):
    assert cli.main(["scan", "--source", str(tmp_path / "nope")]) == 2
    assert "not found" in capsys.readouterr().err


def finished(tmp_path, issues, status="complete", gate=None):
    report = tmp_path / "issues.json"
    report.write_text(json.dumps({"issues": issues}))
    return {"status": status, "error": None, "logs": ["one", "two"], "report_path": str(report), "elapsed_seconds": 75.0, "gate": gate}


def issue(rank, label, cwe="CWE-89", ai=False):
    return {"rank": rank, "label": label, "cwe": cwe, "risk_score": 9.3, "routes": [{"path": "/api/orders"}],
            "evidence": {"code": [{"code": {"file": "orders.py", "line": 88}}], "runtime": []},
            "investigation": {"ai_assisted": ai} if ai else None}


def test_the_summary_counts_labels_and_shows_where_to_look(tmp_path, capsys):
    record = finished(tmp_path, [issue(1, "Confirmed", ai=True), issue(2, "Code only"), issue(3, "Runtime only")])
    assert cli.summarize(record) == 0
    out = capsys.readouterr().out
    assert "3 issues in 75s: 1 Confirmed, 1 Code only, 1 Runtime only" in out
    assert "#1   Confirmed" in out and "/api/orders  orders.py:88" in out
    assert "1 issue(s) were proven by an AI-proposed follow-up test" in out
    assert "issues.html" in out


def test_only_the_top_five_issues_are_listed(tmp_path, capsys):
    cli.summarize(finished(tmp_path, [issue(n, "Code only") for n in range(1, 9)]))
    out = capsys.readouterr().out
    assert "#5 " in out and "#6 " not in out and "and 3 more" in out


def test_a_failed_scan_exits_nonzero_and_shows_the_last_log_lines(tmp_path, capsys):
    record = finished(tmp_path, [], status="failed")
    record["error"] = "SAST scan exited with code 1."
    assert cli.summarize(record) == 1
    err = capsys.readouterr().err
    assert "SAST scan exited with code 1." in err and "one" in err and "two" in err


def test_the_ci_gate_decides_the_exit_status(tmp_path, capsys):
    assert cli.summarize(finished(tmp_path, [], gate={"passed": True, "count": 0})) == 0
    assert cli.summarize(finished(tmp_path, [], gate={"passed": False, "count": 2})) == 1
    assert "CI gate failed: 2" in capsys.readouterr().err


def test_a_run_through_the_command_line_lands_in_the_workspace_history(monkeypatch, tmp_path, capsys):
    """The CLI drives the same ScanManager as the UI, so what it writes is what the UI lists."""
    source = tmp_path / "shop"
    source.mkdir()

    async def fake_run(self, scan_id, request, target, folder):
        folder.mkdir(parents=True)
        report = folder / "issues.json"
        report.write_text(json.dumps({"issues": [issue(1, "Confirmed")]}))
        job = self.jobs[scan_id]
        job.update(status="complete", stage="Complete", elapsed_seconds=3.0)
        self._persist_job(job)

    monkeypatch.setattr(ScanManager, "_run", fake_run)
    assert cli.main(["scan", "--source", str(source), "--target", "http://localhost:8081"]) == 0
    assert "1 Confirmed" in capsys.readouterr().out

    restored = ScanManager()   # what the UI does when it starts
    [job] = restored.list_jobs()
    assert job["target_id"] == "custom" and job["status"] == "complete"
    assert job["target_spec"]["source"] == str(source.resolve())


def test_dependency_analysis_is_on_unless_switched_off():
    assert cli.build_request(parse("--source", "app"))["use_sca"] is True
    assert cli.build_request(parse("--source", "app", "--no-sca"))["use_sca"] is False
