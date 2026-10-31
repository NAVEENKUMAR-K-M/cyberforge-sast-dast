"""What a runtime finding shows, judged from its recorded payload and response, not its technique or tier."""
import pytest

from correlator.evidence import assess, check
from correlator.tests.test_correlate import dast


def level(cwe, payload, evidence, **kwargs):
    return check(dast("d1", cwe=cwe, payload=payload, evidence=evidence, **kwargs))["level"]


def test_a_computed_result_not_in_the_payload_is_validated():
    assert level("CWE-78", ";expr 1406 + 497", {"matched": "1903", "response_excerpt": "x\n1903\n"}) == "validated"


@pytest.mark.parametrize("payload,evidence", [
    (";expr 1406 + 497 # 1903", {"matched": "1903", "response_excerpt": "1903"}),            # echoed
    (";expr 1406 + 497", {"matched": "1903", "response_excerpt": "no result here"}),          # not in the excerpt
    (";expr 1406 + 497", {"matched": "9999", "response_excerpt": "9999"}),                    # not the sum
    (";id", {"matched": "uid=0", "response_excerpt": "uid=0"}),                               # nothing computed
], ids=["echo", "not recorded", "wrong sum", "no marker"])
def test_computed_results_that_prove_nothing_are_partial(payload, evidence):
    assert level("CWE-78", payload, evidence) == "partial"


def test_a_database_error_alone_is_partial_even_when_the_scanner_says_confirmed():
    result = check(dast("d1", payload="'", tier="confirmed", evidence={"matched": "SQL syntax", "response_excerpt": "SQL syntax error"}))
    assert result["level"] == "partial" and "not that it can be exploited" in result["reason"]


def test_a_sql_computed_result_is_validated():
    assert level("CWE-89", "' UNION SELECT 20 + 31--", {"matched": "51", "response_excerpt": "row: 51"}) == "validated"


@pytest.mark.parametrize("matched,expected", [
    ("delayed 6.2s / 6.1s vs baseline 0.10s", "validated"),
    ("delayed 2.0s / 6.1s vs baseline 0.10s", "partial"),     # one repeat was only slightly slow
    ("slow", "partial"),
], ids=["both delayed", "one repeat too close", "unreadable"])
def test_timing_needs_both_repeats_clear_of_the_baseline(matched, expected):
    assert level("CWE-89", "1 AND SLEEP(4)", {"matched": matched, "response_excerpt": ""}) == expected


def test_system_file_content_is_validated_but_an_echo_is_not():
    body = "root:x:0:0:root:/root:/bin/bash\n"
    assert level("CWE-22", "../../etc/passwd", {"matched": "root:x:0:0", "response_excerpt": body}) == "validated"
    assert level("CWE-22", "root:x:0:0", {"matched": "root:x:0:0", "response_excerpt": body}) == "partial"
    assert level("CWE-22", "../../etc/passwd", {"matched": "root:x:0:0", "response_excerpt": "Not found"}) == "partial"


def test_a_server_redirect_to_the_destination_the_test_chose_is_validated():
    ev = {"matched": "https://canary.invalid/", "probe_status": 302}
    assert level("CWE-601", "https://canary.invalid/", ev) == "validated"
    assert level("CWE-601", "https://canary.invalid/", {**ev, "probe_status": 200}) == "partial"          # not a server redirect
    assert level("CWE-601", "http://h/home", {"matched": "http://h/home", "probe_status": 302}) == "partial"  # stays inside the app


def test_reflection_is_validated_only_when_a_script_running_payload_survives():
    runs = "<img src=x onerror=alert(1)>"
    assert level("CWE-79", runs, {"response_excerpt": f"<p>{runs}</p>"}) == "validated"
    assert level("CWE-79", runs, {"response_excerpt": "<p>&lt;img src=x onerror=alert(1)&gt;</p>"}) == "partial"   # encoded
    assert level("CWE-79", '"dz1abc"', {"response_excerpt": "<input value='\"dz1abc\"'>"}) == "partial"            # inert marker


def test_a_weakness_without_a_check_is_unchecked_and_nothing_is_none():
    finding = dast("d1", cwe="CWE-1021", scope="app")
    assert check(finding)["level"] == "unchecked"
    assert assess([])["level"] == "none"


def test_a_group_takes_its_strongest_check():
    weak = dast("d1", evidence={"matched": "e", "response_excerpt": "e"})
    strong = dast("d2", cwe="CWE-89", payload="1 + 2", evidence={"matched": "3", "response_excerpt": "3"})
    assert assess([weak, strong])["level"] == "validated"
