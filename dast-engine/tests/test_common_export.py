"""FR-3: the DAST engine's output in the common finding format."""
import json
from pathlib import Path

import jsonschema
import pytest

from core.models import Confidence, Evidence, Finding, Severity
from results.common_export import cwe_family, finding_to_common, to_common
from results.normalizer import build_output, write_output

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "common" / "finding.schema.json").read_text(encoding="utf-8"))


def sqli(**over) -> Finding:
    base = dict(
        cwe="CWE-89", title="SQL Injection", severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
        method="GET", url="http://localhost:8080/vulnerabilities/sqli/", route_template="/vulnerabilities/sqli/",
        param="id", param_location="query", payload="'", technique="error-based",
        evidence=Evidence(matched="You have an error in your SQL syntax", probe_status=200),
    )
    base.update(over)
    return Finding(**base)


def passive(**over) -> Finding:
    base = dict(
        cwe="CWE-1021", title="Missing Content-Security-Policy header", severity=Severity.MEDIUM,
        confidence=Confidence.FIRM, method="GET", url="http://localhost:8080/", route_template="/",
        param=None, param_location=None, scope="app",
        evidence=Evidence(extra={"affected_urls": ["http://localhost:8080/"], "affected_count": 1}),
    )
    base.update(over)
    return Finding(**base)


def output_for(*findings: Finding) -> dict:
    return build_output(list(findings), target="http://localhost:8080", started_at=0.0, finished_at=1.0,
                        request_count=10, injection_point_count=2, latencies=[0.01])


def test_export_validates_against_the_common_schema():
    common = to_common(output_for(sqli(), passive()))
    jsonschema.Draft202012Validator(SCHEMA).validate(common)
    assert common["source"] == "dast" and len(common["findings"]) == 2


def test_sql_injection_is_cwe_89_on_both_levels():
    """The FR-3 example: SQL injection is CWE-89."""
    f = finding_to_common(sqli().to_dict())
    assert f["cwe"] == "CWE-89" and f["cwe_family"] == "CWE-89"


def test_endpoint_finding_carries_param_route_and_runtime_proof():
    f = finding_to_common(sqli().to_dict())
    assert f["id"] == "dast:" + sqli().finding_id
    assert f["params"] == [{"name": "id", "location": "query"}]
    assert f["routes"] == [{"path": "/vulnerabilities/sqli/", "aliases": [], "selector": None, "methods": ["GET"]}]
    assert f["scope"] == "endpoint" and f["status"] == "open" and f["code"] is None
    assert f["runtime"]["payload"] == "'" and f["runtime"]["technique"] == "error-based"
    assert f["runtime"]["evidence"]["matched"].startswith("You have an error")


def test_app_scope_finding_has_no_route_or_param():
    f = finding_to_common(passive().to_dict())
    assert f["scope"] == "app" and f["routes"] == [] and f["params"] == []
    assert f["runtime"]["evidence"]["affected_urls"] == ["http://localhost:8080/"]


@pytest.mark.parametrize("native, common", [("confirmed", "high"), ("firm", "medium"), ("tentative", "low")])
def test_confidence_is_mapped_and_the_native_tier_is_kept(native, common):
    f = finding_to_common(sqli(confidence=Confidence(native)).to_dict())
    assert f["confidence"] == common and f["runtime"]["verification"] == native


@pytest.mark.parametrize("cwe, family", [
    ("CWE-89", "CWE-89"), ("CWE-79", "CWE-79"), ("CWE-78", "CWE-78"), ("CWE-22", "CWE-22"), ("CWE-601", "CWE-601"),
    ("CWE-98", "CWE-22"),    # ZAP's remote file inclusion is the same family as path traversal
    ("CWE-209", "CWE-489"),  # same grouping the SAST side uses, so a stack trace compares equal to debug-on
    ("CWE-200", "CWE-489"),
    ("CWE-1021", "CWE-1021"),  # runtime-only types are their own family
])
def test_cwe_family_matches_the_sast_side(cwe, family):
    assert cwe_family(cwe) == family


def test_tool_names():
    assert finding_to_common(sqli().to_dict())["tool"] == "cyberforge-dast"
    assert finding_to_common(sqli(tool="owasp-zap").to_dict())["tool"] == "owasp-zap"


def test_write_output_also_writes_the_common_file(tmp_path):
    out = output_for(sqli())
    write_output(out, tmp_path / "dast_results.json")
    common_file = tmp_path / "dast_results.common.json"
    assert common_file.exists()
    jsonschema.Draft202012Validator(SCHEMA).validate(json.loads(common_file.read_text(encoding="utf-8")))
    # the native file is unchanged
    native = json.loads((tmp_path / "dast_results.json").read_text(encoding="utf-8"))
    assert native["findings"][0]["finding_id"] == sqli().finding_id
