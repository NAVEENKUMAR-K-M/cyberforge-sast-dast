import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))

from score import _matches, score


def test_matches_handles_missing_method_and_param():
    """Regression test: a safe_decoy entry (or any key_entry) without a
    'method' or 'param' key must not crash -- it should match on
    whatever fields it does specify."""
    finding = {"cwe": "CWE-89", "method": "GET", "route_template": "/instructions.php", "param": None}
    key_entry = {"cwe": "CWE-89", "route_template": "/instructions.php"}  # no method, no param
    assert _matches(finding, key_entry) is True


def test_matches_respects_method_when_present():
    finding = {"cwe": "CWE-89", "method": "POST", "route_template": "/x", "param": "id"}
    key_entry = {"cwe": "CWE-89", "method": "GET", "route_template": "/x", "param": "id"}
    assert _matches(finding, key_entry) is False


def test_score_end_to_end_with_decoy_missing_method():
    results = {
        "findings": [
            {"cwe": "CWE-89", "method": "GET", "route_template": "/x/", "param": "id"},
            {"cwe": "CWE-89", "method": "GET", "route_template": "/docs", "param": None},
        ],
        "request_count": 10,
        "p95_latency_seconds": 0.1,
        "elapsed_seconds": 5,
    }
    answer_key = {
        "expected": [{"cwe": "CWE-89", "method": "GET", "route_template": "/x/", "param": "id"}],
        "safe_decoys": [{"cwe": "CWE-89", "route_template": "/docs"}],
    }
    report = score(results, answer_key)
    assert report["detected"] == 1
    assert report["false_alarm_count"] == 1
