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


def test_app_scope_findings_with_same_cwe_but_different_title_do_not_collide():
    """Regression test: missing Referrer-Policy and missing SameSite are
    genuinely different checks that both happen to map to CWE-1275. Both
    are app-scope (route_template="/", param=None), so without `title` in
    the id basis they'd collide onto the same finding_id and one would
    silently vanish from dedupe."""
    common = dict(
        cwe="CWE-1275", severity=Severity.LOW, confidence=Confidence.FIRM,
        method="GET", url="http://localhost:8080/", route_template="/",
        param=None, param_location=None, scope="app",
    )
    f1 = Finding(title="Missing Referrer-Policy header", **common)
    f2 = Finding(title="Session cookie missing SameSite attribute", **common)
    assert f1.finding_id != f2.finding_id


def test_endpoint_scope_finding_id_ignores_title_for_stability():
    """XSS's title includes the reflection context classified that run
    (e.g. "(html_body context)" vs "(attribute context)"); for the SAME
    underlying bug that classification could vary slightly between runs,
    so endpoint-scope ids deliberately exclude title to stay stable."""
    common = dict(
        cwe="CWE-79", severity=Severity.HIGH, confidence=Confidence.FIRM,
        method="GET", url="http://localhost:8080/xss/?name=x", route_template="/xss/",
        param="name", param_location="query", scope="endpoint",
    )
    f1 = Finding(title="Reflected Cross-Site Scripting (html_body context)", **common)
    f2 = Finding(title="Reflected Cross-Site Scripting (attribute context)", **common)
    assert f1.finding_id == f2.finding_id


def test_to_dict_contains_required_schema_fields():
    f = make_finding()
    d = f.to_dict()
    for key in ("finding_id", "source", "cwe", "title", "severity", "confidence", "method", "url", "route_template", "scope"):
        assert key in d
    assert d["confidence"] == "firm"
