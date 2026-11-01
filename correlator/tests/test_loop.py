"""The closed loop: investigate a case, run a supported test, take the result back into correlation, stop."""
import json

import jsonschema
import pytest

from correlator.correlate import correlate
from correlator.loop import MAX_ROUNDS, check_plan, default_plan, find_cases, run_loop
from correlator.tests.test_correlate import DB_ERROR, SCHEMA, dast, route, sast

COMPUTED_SQL = {"payload": "' UNION SELECT 20 + 31--", "evidence": {"matched": "51", "response_excerpt": "row: 51", "probe_status": 200}}


def docs(code, runtime=()):
    return ({"source": "sast", "target": "src", "findings": list(code)},
            {"source": "dast", "target": "http://h", "findings": list(runtime)})


class FakeExecutor:
    """Stands in for the DAST engine: answers each plan from a list and remembers what it was asked."""

    def __init__(self, *answers):
        self.answers, self.plans = list(answers), []

    def __call__(self, plan):
        self.plans.append(plan)
        return self.answers.pop(0) if self.answers else {"reproduced": False, "finding": None, "finding_common": None, "attempts": [sent(plan)]}


def sent(plan, status=200):
    return {"method": plan["method"], "url": f"http://h{plan['route']}", "query": {plan["param"]: "x"}, "body": {}, "status": status,
            "length": 10, "seconds": 0.1}


def issue(result, label):
    return next(i for i in result["issues"] if i["label"] == label)


# ---- which issues become cases ----

def test_cases_are_credible_code_only_issues_with_a_supported_test():
    code = [sast("ok"), sast("weak", file="b.php", confidence="low"), sast("noroute", file="c.php", routes=[]),
            sast("unnamed", file="d.php", params=(("*", "query"),)), sast("other", file="e.php", cwe="CWE-327")]
    result = correlate(*docs(code))
    assert [c["sast_ids"] for c in find_cases(result)] == [["sast:ok"]]


def test_an_ambiguous_runtime_bug_is_a_case_but_has_no_test():
    result = correlate(*docs([sast("s1", file="x.php"), sast("s2", file="y.php")], [dast("d1")]))
    cases = find_cases(result)
    attribute = next(c for c in cases if c["kind"] == "attribute")
    plan, why = default_plan(attribute)
    assert plan is None and "can't separate them" in why


# ---- the loop ----

def test_a_re_test_that_shows_the_weakness_confirms_the_issue():
    sast_doc, dast_doc = docs([sast("s1", cwe="CWE-78")])
    proof = dast("new1", cwe="CWE-78", payload=";expr 1406 + 497", evidence={"matched": "1903", "response_excerpt": "x\n1903\n"})
    ex = FakeExecutor({"reproduced": True, "finding": {}, "finding_common": proof, "attempts": [{"method": "GET", "url": "http://h/a.php",
                       "query": {"id": ";expr 1406 + 497"}, "body": {}, "status": 200, "length": 40, "seconds": 0.1}]})
    result, new_dast = run_loop(sast_doc, dast_doc, ex)
    confirmed = issue(result, "Confirmed")
    assert confirmed["runtime_verification"]["level"] == "validated" and "E:F" in confirmed["cvss"]["vector"]
    record = result["investigations"][0]
    assert record["outcome"] == "validated" and len(record["rounds"]) == 1 and len(ex.plans) == 1
    first = record["rounds"][0]
    assert first["requests_sent"][0]["query"] == {"id": ";expr 1406 + 497"}      # the actual request is kept
    assert first["effect"]["before"]["label"] == "Code only" and first["effect"]["after"]["label"] == "Confirmed"
    assert first["effect"]["linked"] is True and first["evidence"]["level"] == "validated"
    assert result["stats"]["upgraded"] == 1 and confirmed["investigation"]["outcome"] == "validated"
    assert confirmed["investigation"]["ai_assisted"] is False          # round 1 alone proved it, no planner involved
    assert [f["id"] for f in new_dast["findings"]] == ["dast:new1"]                 # the evidence is kept for the report


def test_the_result_is_matched_by_the_same_rules_as_any_finding():
    """A re-test that lands on another route doesn't become a link just because it was asked for."""
    stray = dast("stray", path="/elsewhere.php")
    result, _ = run_loop(*docs([sast("s1")]), FakeExecutor({"reproduced": True, "finding": {}, "finding_common": stray, "attempts": [{"method": "GET"}]}))
    record = result["investigations"][0]["rounds"][0]
    assert record["effect"]["linked"] is False and issue(result, "Code only")
    assert result["stats"]["upgraded"] == 0


def test_weak_evidence_keeps_the_case_open_and_the_next_round_uses_it():
    """A database error confirms the link but doesn't show exploitation, so the loop tries again, and the
    planner is shown what round 1 actually sent and got back."""
    seen = []

    def planner(case, history):
        seen.append(history)
        return {"fields": {"mode": "full"}, "reason": "the error shows the query is reached; the full mode returns rows"}

    first = dast("e1", **DB_ERROR)
    second = dast("e2", **COMPUTED_SQL)
    ex = FakeExecutor({"reproduced": True, "finding": {}, "finding_common": first, "attempts": [{"method": "GET", "url": "http://h/a.php", "query": {"id": "'"}, "body": {}, "status": 500, "length": 90, "seconds": 0.1}]},
                      {"reproduced": True, "finding": {}, "finding_common": second, "attempts": [{"method": "GET", "url": "http://h/a.php", "query": {"id": "x"}, "body": {}, "status": 200, "length": 40, "seconds": 0.1}]})
    result, _ = run_loop(*docs([sast("s1")]), ex, planner)
    record = result["investigations"][0]
    assert [r["evidence"]["level"] for r in record["rounds"]] == ["partial", "validated"]
    assert record["outcome"] == "validated" and len(record["rounds"]) == 2
    assert seen[0][0]["requests_sent"][0]["query"] == {"id": "'"} and seen[0][0]["outcome"] == "reproduced"
    assert ex.plans[1]["fields"] == {"mode": "full"} and ex.plans[1]["origin"] == "planner"
    confirmed = issue(result, "Confirmed")
    assert confirmed["runtime_verification"]["level"] == "validated"
    assert confirmed["investigation"]["ai_assisted"] is True          # round 2's planner-proposed test is what closed it


def test_not_reproduced_is_not_safe():
    result, _ = run_loop(*docs([sast("s1")]), FakeExecutor())
    record = result["investigations"][0]
    assert record["outcome"] == "unresolved" and "no planner" in record["stop_reason"]
    assert record["rounds"][0]["outcome"] == "not reproduced"
    still = issue(result, "Code only")
    assert still["runtime_verification"]["level"] == "none" and still["reportable"] is True


def test_no_requests_sent_means_blocked_not_negative():
    ex = FakeExecutor({"reproduced": False, "finding": None, "finding_common": None, "attempts": []})
    result, _ = run_loop(*docs([sast("s1")]), ex)
    record = result["investigations"][0]
    assert record["outcome"] == "blocked" and record["rounds"][0]["outcome"] == "blocked" and len(ex.plans) == 1


def test_an_engine_failure_is_recorded_and_stops_that_case():
    result, _ = run_loop(*docs([sast("s1")]), FakeExecutor({"error": "the DAST engine did not return a result (TimeoutExpired)"}))
    record = result["investigations"][0]
    assert record["outcome"] == "unresolved" and "TimeoutExpired" in record["stop_reason"]


def test_a_case_gets_at_most_two_tests():
    calls = []

    def planner(case, history):
        calls.append(len(history))
        return {"fields": {"try": str(len(history))}}

    ex = FakeExecutor()
    result, _ = run_loop(*docs([sast("s1")]), ex, planner)
    assert len(ex.plans) == MAX_ROUNDS == 2 and calls == [1]
    assert result["investigations"][0]["stop_reason"] == "round limit reached"


@pytest.mark.parametrize("raw,why", [
    (None, "nothing usable"),
    ({"hint": "line\nbreak"}, "printable"),
    ({"hint": "x" * 201}, "printable"),
    ({"fields": {"a": "b\nc"}}, "single-line"),
    ({"fields": {f"f{n}": "v" for n in range(11)}}, "single-line"),
    ({"method": "DELETE"}, "accepts GET"),
    ({"location": "body"}, "not body"),
    ({}, "already tried"),
])
def test_a_planner_can_shape_a_request_but_not_redirect_it(raw, why):
    case = find_cases(correlate(*docs([sast("s1")])))[0]
    plan = default_plan(case)[0]
    plan, reason = check_plan(raw, case, [{"plan": plan}])
    assert plan is None and why in reason


def test_what_a_planner_leaves_out_stays_as_the_last_round_had_it():
    case = find_cases(correlate(*docs([sast("s1", params=(("username", "body"),), routes=[route("/login.php", methods=("POST",))])])))[0]
    first = default_plan(case)[0]
    plan, reason = check_plan({"fields": {"password": "x"}}, case, [{"plan": first}])
    assert reason is None and (plan["method"], plan["location"], plan["fields"]) == ("POST", "body", {"password": "x"})


def test_a_planner_cannot_change_the_route_or_parameter():
    case = find_cases(correlate(*docs([sast("s1")])))[0]
    plan, _ = check_plan({"route": "/admin.php", "param": "other", "cwe": "CWE-78", "fields": {"x": "y"}}, case, [])
    assert (plan["route"], plan["param"], plan["cwe"]) == ("/a.php", "id", "CWE-89") and plan["fields"] == {"x": "y"}


def test_a_hint_is_refused_for_a_test_that_ignores_it_and_a_give_up_is_respected():
    case = find_cases(correlate(*docs([sast("s1")])))[0]
    assert "doesn't take a hint" in check_plan({"hint": "x"}, case, [])[1]
    assert "no further useful test: needs a write first" in check_plan({"give_up": True, "reason": "needs a write first"}, case, [])[1]


def test_stored_and_unsettable_inputs_have_no_test_and_are_still_reported():
    code = [sast("stored", stored_on=[route("/write.php", methods=("POST",))], params=(("body", "body"),)),
            sast("file", file="u.php", params=(("upload", "file"),), cwe="CWE-22")]
    ex = FakeExecutor()
    result, _ = run_loop(*docs(code), ex)
    assert ex.plans == []
    assert sorted(r["outcome"] for r in result["investigations"]) == ["no supported test", "no supported test"]
    assert all(r["stop_reason"] for r in result["investigations"])


def test_the_request_shape_follows_the_code():
    def plan_for(**kw):
        return default_plan(find_cases(correlate(*docs([sast("s1", **kw)])))[0])[0]
    post = plan_for(params=(("username", "body"),), routes=[route("/login.php", methods=("POST",))])
    assert (post["method"], post["location"]) == ("POST", "body")
    both = plan_for(params=(("next", "any"),), routes=[route("/go.php", methods=("GET", "POST"))])
    assert (both["method"], both["location"]) == ("GET", "query")


def test_the_budget_stops_the_loop():
    ticks = iter([0, 1000, 2000, 3000, 4000])
    ex = FakeExecutor()
    result, _ = run_loop(*docs([sast("s1")]), ex, budget_seconds=10, clock=lambda: next(ticks))
    assert ex.plans == [] and result["investigations"][0]["stop_reason"] == "budget exhausted"


def test_only_the_most_severe_cases_are_tested_when_there_are_many():
    code = [sast(f"s{n}", file=f"f{n}.php", routes=[route(f"/p{n}.php")]) for n in range(6)]
    ex = FakeExecutor()
    result, _ = run_loop(*docs(code), ex, max_cases=3)
    assert len(ex.plans) == 3 and result["stats"]["investigated"] == 3


def test_without_cases_the_result_is_the_plain_correlation():
    sast_doc, dast_doc = docs([sast("s1")], [dast("d1", **DB_ERROR)])
    result, _ = run_loop(sast_doc, dast_doc, FakeExecutor())
    plain = correlate(sast_doc, dast_doc)
    assert result["investigations"] == [] and [i["issue_id"] for i in result["issues"]] == [i["issue_id"] for i in plain["issues"]]


def test_the_investigated_report_matches_the_schema():
    proof = dast("new1", cwe="CWE-78", payload=";expr 1406 + 497", evidence={"matched": "1903", "response_excerpt": "1903"})
    result, _ = run_loop(*docs([sast("s1", cwe="CWE-78"), sast("s2", file="b.php", cwe="CWE-22", routes=[route("/b.php")])]),
                         FakeExecutor({"reproduced": True, "finding": {}, "finding_common": proof, "attempts": [{"method": "GET"}]}))
    jsonschema.Draft202012Validator(SCHEMA).validate(json.loads(json.dumps(result)))
    assert {r["outcome"] for r in result["investigations"]} == {"validated", "unresolved"}


def test_the_page_shows_each_round_with_the_requests_actually_sent():
    from correlator.report import render
    attack = "<script>alert(1)</script>"
    proof = dast("new1", cwe="CWE-78", payload=";expr 1406 + 497", evidence={"matched": "1903", "response_excerpt": "1903"})
    ex = FakeExecutor({"reproduced": True, "finding": {}, "finding_common": proof,
                       "attempts": [{"method": "GET", "url": "http://h/a.php", "query": {"id": attack}, "body": {}, "status": 200, "length": 4, "seconds": 0.1}]})
    result, _ = run_loop(*docs([sast("s1", cwe="CWE-78")]), ex)
    page = render(result)
    assert "Re-test" in page and "validated" in page and "Code only → Confirmed" in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and attack not in page      # attack strings are escaped
