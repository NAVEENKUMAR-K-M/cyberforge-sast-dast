from core.models import Confidence, Evidence, Finding, Severity


def make_finding(payload="1'", confidence=Confidence.FIRM):
    return Finding(
        cwe="CWE-89",
        title="SQL injection",
        severity=Severity.HIGH,
        confidence=confidence,
        method="GET",
        url="http://localhost:8080/vulnerabilities/sqli/?id=1'",
        route_template="/vulnerabilities/sqli/",
        param="id",
        param_location="query",
        payload=payload,
        evidence=Evidence(matched="you have an error in your sql syntax"),
    )


def test_finding_id_stable_across_payload_changes():
    f1 = make_finding(payload="1'")
    f2 = make_finding(payload="1' OR '1'='1")
    assert f1.finding_id == f2.finding_id, "finding_id must not depend on the exact payload (FR-6)"


def test_finding_id_differs_by_param():
    f1 = make_finding()
    f2 = Finding(**{**f1.__dict__, "param": "name"})
    assert f1.finding_id != f2.finding_id


def test_to_dict_contains_required_schema_fields():
    f = make_finding()
    d = f.to_dict()
    for key in ("finding_id", "source", "cwe", "title", "severity", "confidence", "method", "url", "route_template", "scope"):
        assert key in d
    assert d["confidence"] == "firm"
