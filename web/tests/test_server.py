import json

from fastapi.testclient import TestClient

from web.server import WEB, create_app


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
