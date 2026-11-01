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
