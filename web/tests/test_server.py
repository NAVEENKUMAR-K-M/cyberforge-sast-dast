import json

import pytest
from fastapi.testclient import TestClient

from web import scan_manager
from web.server import WEB, create_app


@pytest.fixture(autouse=True)
def isolated_scan_history(tmp_path, monkeypatch):
    """ScanManager reads real scan history from a module-level constant, not an instance argument, so
    without this a developer's own past scans on this machine silently outrank the report a test asks
    for (get_report_path prefers scans.latest_report over the explicit path) and the test fails for a
    reason that has nothing to do with the code under test."""
    monkeypatch.setattr(scan_manager, "OUT", tmp_path / "scan-history")


def report_file(tmp_path):
    path = tmp_path / "issues.json"
    path.write_text((WEB / "example.issues.json").read_text())
    return path


def test_reads_real_report_without_inventing_scan_completeness(tmp_path):
    with TestClient(create_app(report_file(tmp_path))) as client:
        response = client.get("/api/report")
    assert response.status_code == 200
    data = response.json()
    assert data["report"]["issues"][0]["label"] == "Confirmed"
    assert data["scan"]["stats"] == {"sast": {}, "dast": {}}
    assert len(data["scan"]["notes"]) == 2
    assert response.headers["cache-control"] == "no-store"


def test_source_coverage_is_loaded_and_report_refreshes(tmp_path):
    path = report_file(tmp_path)
    report = json.loads(path.read_text())
    source = tmp_path / "dast.common.json"
    source.write_text(json.dumps({"source": "dast", "stats": {"coverage": {"deadline_reached": True, "points_tested": 3}}}))
    report["inputs"]["dast"]["path"] = source.name
    path.write_text(json.dumps(report))
    with TestClient(create_app(path)) as client:
        assert client.get("/api/report").json()["scan"]["stats"]["dast"]["coverage"]["deadline_reached"] is True
        report["issues"] = []
        path.write_text(json.dumps(report))
        assert client.get("/api/report").json()["report"]["issues"] == []


def test_missing_report_and_wrong_format_have_actionable_errors(tmp_path):
    path = tmp_path / "missing.json"
    with TestClient(create_app(path)) as client:
        assert client.get("/api/report").status_code == 404
        path.write_text('{"findings": []}')
        assert client.get("/api/report").status_code == 422
        path.write_text('not json')
        assert client.get("/api/report").status_code == 422


def test_exports_keep_json_evidence_and_escape_html(tmp_path):
    path = report_file(tmp_path)
    doc = json.loads(path.read_text())
    doc["issues"][0]["evidence"]["runtime"][0]["runtime"]["payload"] = '<script>alert("x")</script>'
    path.write_text(json.dumps(doc))
    with TestClient(create_app(path)) as client:
        downloaded = client.get("/api/export")
        assert downloaded.json() == doc
        assert 'attachment' in downloaded.headers["content-disposition"]
        page = client.get("/api/export/html")
        assert '<script>alert' not in page.text
        assert '&lt;script&gt;alert' in page.text


def test_fixed_report_path_cannot_be_overridden_from_a_request(tmp_path):
    path = report_file(tmp_path)
    with TestClient(create_app(path)) as client:
        assert client.get("/api/report?path=/etc/passwd").json()["report"] == json.loads(path.read_text())
        assert client.get("/api/unknown").status_code == 404


def test_example_is_explicitly_labelled():
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        data = client.get("/api/report").json()
    assert data["scan"]["example"] is True
    assert data["scan"]["name"] == "Benchmark shop"


def test_target_catalog_includes_each_runnable_first_party_benchmark():
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        targets = {item["id"]: item for item in client.get("/api/targets").json()["targets"]}
    assert {"dvwa", "juice_shop", "benchmark_shop", "python_shop", "fastshop", "laravel_shop", "django_shop"} <= set(targets)
    assert targets["fastshop"]["url"].endswith(":8091")
    assert targets["laravel_shop"]["url"].endswith(":8092")
    assert targets["django_shop"]["url"].endswith(":8093")
    assert all(targets[key]["sast_supported"] for key in ("python_shop", "fastshop", "laravel_shop", "django_shop"))


def test_ai_status_reports_configuration_without_returning_secret_values(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-secret-groq-value")
    monkeypatch.setenv("OPENAI_API_KEY", "test-secret-openai-value")
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.get("/api/ai/status")
    assert response.status_code == 200
    body = response.text
    assert "test-secret" not in body
    assert {provider["id"] for provider in response.json()["providers"]} == {"groq", "openai"}
    assert all(provider["configured"] for provider in response.json()["providers"])


def test_investigation_requires_explicit_data_sharing_consent():
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.post("/api/scans/scan-id/investigate", json={"provider": "groq", "consent": False})
    assert response.status_code == 400
    assert "data-sharing" in response.json()["detail"]


def test_investigation_reports_missing_provider_setup(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.post("/api/scans/scan-id/investigate", json={"provider": "groq", "consent": True})
    assert response.status_code == 400
    assert "not configured" in response.json()["detail"]


def test_investigation_prevents_overlapping_runs(monkeypatch):
    from datetime import datetime, timezone

    from web.scan_manager import TARGETS

    monkeypatch.setenv("GROQ_API_KEY", "test-provider-key")
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        scans = client.app.state.scans
        now = datetime.now(timezone.utc).isoformat()
        scans.latest_report = WEB / "example.issues.json"
        scans.jobs["source-scan"] = {
            "id": "source-scan", "target_id": "benchmark_shop", "target_name": "Shop",
            "target_url": TARGETS["benchmark_shop"]["url"], "status": "complete",
            "report_path": str(WEB / "example.issues.json"), "options": {}, "created_at": now,
        }
        scans.jobs["active-scan"] = {"id": "active-scan", "status": "running", "created_at": now}
        response = client.post("/api/scans/source-scan/investigate", json={"provider": "groq", "consent": True})
    assert response.status_code == 400
    assert "already running" in response.json()["detail"]


def test_ai_status_can_report_missing_provider_without_secret_material(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.get("/api/ai/status")
    assert response.status_code == 200
    assert response.json()["ready"] is False
    assert all(not provider["configured"] for provider in response.json()["providers"])


# ---- custom application: scan something that isn't one of the built-in demo apps ----

def custom_request(source, url="http://localhost:8081", **extra):
    return {"target_id": "custom", "source_path": str(source), "target_url": url, "language": "auto",
            "run_sast": True, "run_dast": True, **extra}


def test_custom_application_is_offered_next_to_the_built_in_targets():
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        targets = client.get("/api/targets").json()["targets"]
    ids = [target["id"] for target in targets]
    assert "custom" in ids and "benchmark_shop" in ids
    custom = next(target for target in targets if target["id"] == "custom")
    assert custom["custom"] is True and custom["sast_supported"] is True


def test_custom_only_mode_hides_the_built_in_targets(monkeypatch):
    monkeypatch.setenv("CYBERFORGE_CUSTOM_ONLY", "1")
    monkeypatch.setenv("CYBERFORGE_WORKSPACE", "/workspace")
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        targets = client.get("/api/targets").json()["targets"]
        refused = client.post("/api/scans", json={"target_id": "benchmark_shop", "run_dast": True})
    assert [target["id"] for target in targets] == ["custom"]
    assert targets[0]["default_source"].endswith("workspace")
    assert refused.status_code == 400


def test_custom_scan_refuses_a_host_that_is_not_this_machine(tmp_path):
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.post("/api/scans", json=custom_request(tmp_path, url="http://example.com:8081"))
    assert response.status_code == 400
    assert "only this machine" in response.json()["detail"]


def test_host_allow_list_follows_the_environment(monkeypatch, tmp_path):
    from web.scan_manager import ScanManager

    with pytest.raises(ValueError):
        ScanManager.validate_target_url("http://host.docker.internal:8081")
    monkeypatch.setenv("CYBERFORGE_ALLOWED_HOSTS", "localhost,127.0.0.1,host.docker.internal")
    assert ScanManager.validate_target_url("http://host.docker.internal:8081/") == "http://host.docker.internal:8081"
    with pytest.raises(ValueError):
        ScanManager.validate_target_url("http://example.com:8081")


def test_custom_scan_refuses_source_outside_the_workspace(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    monkeypatch.setenv("CYBERFORGE_WORKSPACE", str(workspace))
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        absolute = client.post("/api/scans", json=custom_request(outside))
        dotdot = client.post("/api/scans", json=custom_request("../elsewhere"))
    assert absolute.status_code == 400 and "must be inside" in absolute.json()["detail"]
    assert dotdot.status_code == 400 and "must be inside" in dotdot.json()["detail"]


def test_custom_scan_refuses_a_symlink_that_leads_out_of_the_workspace(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    try:
        (workspace / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this machine can't create symlinks")
    monkeypatch.setenv("CYBERFORGE_WORKSPACE", str(workspace))
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.post("/api/scans", json=custom_request("link"))
    assert response.status_code == 400 and "must be inside" in response.json()["detail"]


def test_custom_scan_starts_and_remembers_what_it_scans(monkeypatch, tmp_path):
    from web.scan_manager import ScanManager

    seen = {}

    async def fake_run(self, scan_id, request, target, folder):
        seen.update(target=target, request=request)
        self.jobs[scan_id]["status"] = "complete"

    monkeypatch.setattr(ScanManager, "_run", fake_run)
    source = tmp_path / "shop"
    source.mkdir()
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.post("/api/scans", json=custom_request(source, language="php"))
    assert response.status_code == 200
    job = response.json()
    assert job["target_id"] == "custom" and job["target_name"] == "Custom application (shop)"
    assert job["target_url"] == "http://localhost:8081"
    assert job["target_spec"] == {"name": "Custom application (shop)", "source": str(source.resolve()), "language": "php",
                                  "url": "http://localhost:8081"}
    # no config file: DAST then limits itself to exactly this target
    assert seen["target"]["config"] is None and seen["target"]["language"] == "php" and seen["target"]["source"] == source.resolve()


def test_custom_scan_needs_a_real_source_folder_and_a_known_language(tmp_path):
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        missing = client.post("/api/scans", json=custom_request(tmp_path / "nope"))
        odd_language = client.post("/api/scans", json=custom_request(tmp_path, language="cobol"))
        nothing = client.post("/api/scans", json={"target_id": "custom", "run_sast": False, "run_dast": False})
    assert missing.status_code == 400 and "not found" in missing.json()["detail"]
    assert odd_language.status_code == 400 and "language" in odd_language.json()["detail"]
    assert nothing.status_code == 400


def test_built_in_targets_keep_their_port_lock():
    with TestClient(create_app(WEB / "example.issues.json", example=True)) as client:
        response = client.post("/api/scans", json={"target_id": "benchmark_shop", "target_url": "http://127.0.0.1:9999",
                                                   "run_sast": False, "run_dast": True})
    assert response.status_code == 400 and "configured local port 8088" in response.json()["detail"]


def test_a_custom_run_is_restored_and_its_target_found_again(tmp_path):
    from web import scan_manager
    from web.scan_manager import ScanManager

    folder = scan_manager.OUT / "cli-run"
    folder.mkdir(parents=True)
    (folder / "issues.json").write_text("{}")
    spec = {"name": "Custom application (shop)", "source": str(tmp_path), "language": "python", "url": "http://localhost:8081"}
    manifest = {"id": "cli-run", "target_id": "custom", "target_name": spec["name"], "target_url": spec["url"], "status": "complete",
                "stage": "Complete", "created_at": "2026-11-01T00:00:00+00:00", "completed_at": "2026-11-01T00:02:00+00:00",
                "elapsed_seconds": 120.0, "options": {"run_sast": True, "run_dast": True}, "error": None,
                "report_path": str(folder / "issues.json"), "gate": None, "target_spec": spec}
    (folder / "scan.json").write_text(json.dumps(manifest))
    manager = ScanManager()
    assert manager.get_job("cli-run")["target_spec"] == spec
    target = manager.target_for("custom")
    assert target["name"] == spec["name"] and target["config"] is None and str(target["source"]) == str(tmp_path)
    assert manager.target_for("no-such-target") is None
