"""FR-5 (link), FR-6 (merge) and FR-7 (label), one behaviour per test."""
import copy
import json
import random
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from correlator.correlate import InputError, correlate, load_report

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "common" / "examples"
SCHEMA = json.loads((ROOT / "correlator" / "issues.schema.json").read_text())


def route(path="/a.php", selector=None, aliases=(), methods=("GET",)):
    return {"path": path, "aliases": list(aliases), "selector": selector, "methods": list(methods)}


def sast(id, cwe="CWE-89", status="open", params=(("id", "query"),), routes=None, file="a.php", function="<top-level>",
         stored_on=None, confidence="high", reason=None):
    return {
        "id": f"sast:{id}", "source": "sast", "tool": "cyberforge-sast", "cwe": cwe, "cwe_family": cwe, "title": "Bug",
        "severity": "critical", "confidence": confidence, "status": status, "scope": "endpoint",
        "params": [{"name": n, "location": loc} for n, loc in params],
        "routes": [route()] if routes is None else routes,
        "code": {"file": file, "line": 1, "snippet": "", "function": function, "sink": "query", "trace": [], "conditions": [],
                 "stored_flow": {"store": "db:t", "write_routes": stored_on} if stored_on else None,
                 "suppression_reason": reason, "engines": ["taint"]},
        "runtime": None,
    }


def dast(id, cwe="CWE-89", path="/a.php", selector=None, param="id", location="query", method="GET", url=None, scope="endpoint"):
    endpoint = scope == "endpoint"
    return {
        "id": f"dast:{id}", "source": "dast", "tool": "cyberforge-dast", "cwe": cwe, "cwe_family": cwe, "title": "Bug",
        "severity": "high", "confidence": "high", "status": "open", "scope": scope,
        "params": [{"name": param, "location": location}] if endpoint else [],
        "routes": [route(path, selector, methods=(method,))] if endpoint else [],
        "code": None,
        "runtime": {"method": method, "url": url or f"http://h{path}", "payload": "x", "technique": "t",
                    "verification": "confirmed", "evidence": {}},
    }


def run(code, runtime, **kwargs):
    return correlate({"source": "sast", "target": "src", "findings": code},
                     {"source": "dast", "target": "http://h", "findings": runtime}, **kwargs)


def labels(result):
    return sorted(i["label"] for i in result["issues"])


# ---- FR-5: when a runtime finding links to code ----

def test_exact_route_and_parameter_link():
    result = run([sast("s1")], [dast("d1")])
    assert labels(result) == ["Confirmed"]
    assert result["links"][0]["match_basis"]["kind"] == "exact"


@pytest.mark.parametrize("runtime", [
    dast("d1", path="/b.php"),
    dast("d1", param="name"),
    dast("d1", cwe="CWE-79"),
    dast("d1", location="body"),
], ids=["wrong route", "wrong parameter", "wrong CWE", "body test of a query input"])
def test_near_misses_dont_link(runtime):
    assert labels(run([sast("s1")], [runtime])) == ["Code only", "Runtime only"]


def test_folder_alias_links():
    code = sast("s1", routes=[route("/shop/index.php", aliases=["/shop/"])])
    result = run([code], [dast("d1", path="/shop/")])
    assert labels(result) == ["Confirmed"] and result["links"][0]["match_basis"]["kind"] == "alias"


@pytest.mark.parametrize("code_path,runtime_path", [("/orders/{oid}", "/orders/{id}"), ("/orders/{oid}", "/orders/7")])
def test_path_templates_link(code_path, runtime_path):
    result = run([sast("s1", routes=[route(code_path)])], [dast("d1", path=runtime_path)])
    assert labels(result) == ["Confirmed"] and result["links"][0]["match_basis"]["kind"] == "template"


def test_template_needs_the_same_number_of_segments():
    assert labels(run([sast("s1", routes=[route("/orders/{oid}")])], [dast("d1", path="/orders/7/x")])) == ["Code only", "Runtime only"]


def test_selector_must_match():
    code = sast("s1", routes=[route("/s.php", "action=view")])
    assert labels(run([code], [dast("d1", path="/s.php", selector="action=track")])) == ["Code only", "Runtime only"]
    assert labels(run([code], [dast("d1", path="/s.php", selector="action=view")])) == ["Confirmed"]


def test_selector_can_come_from_the_tested_url():
    code = sast("s1", routes=[route("/s.php", "action=view")])
    assert labels(run([code], [dast("d1", path="/s.php", url="http://h/s.php?action=view")])) == ["Confirmed"]


def test_any_location_accepts_query_and_body():
    code = sast("s1", params=(("q", "any"),))
    assert labels(run([code], [dast("d1", param="q", location="body", method="POST")])) == ["Confirmed"]


def test_method_isnt_a_gate():
    """Location already says how the input travels; the method on a route list can be incomplete."""
    assert labels(run([sast("s1")], [dast("d1", method="POST")])) == ["Confirmed"]


def test_stored_bug_found_on_its_write_route():
    code = sast("s1", cwe="CWE-79", params=(("body", "body"),), routes=[route("/show.php")], stored_on=[route("/add.php", methods=("POST",))])
    result = run([code], [dast("d1", cwe="CWE-79", path="/add.php", param="body", location="body", method="POST")])
    assert labels(result) == ["Confirmed"] and result["links"][0]["match_basis"]["kind"] == "stored-write"
    assert result["issues"][0]["stored"] is True


def test_base_path_is_stripped_from_runtime_routes():
    runtime = dast("d1", path="/app/a.php", url="http://h/app/a.php")
    result = correlate({"source": "sast", "findings": [sast("s1")]}, {"source": "dast", "target": "http://h/app", "findings": [runtime]})
    assert labels(result) == ["Confirmed"] and result["base_path"] == "/app"
    assert labels(run([sast("s1")], [runtime], base_path="/app")) == ["Confirmed"]


def test_no_shared_routes_is_reported():
    result = run([sast("s1")], [dast("d1", path="/elsewhere.php")])
    assert result["diagnostics"] and "base path" in result["diagnostics"][0]


# ---- ambiguity and suppressed code ----

def test_two_different_handlers_mean_no_link():
    result = run([sast("s1", file="x.php"), sast("s2", file="y.php")], [dast("d1")])
    assert result["links"] == []
    runtime = next(i for i in result["issues"] if i["label"] == "Runtime only")
    assert runtime["ambiguous"] is True and len(runtime["candidates"]) == 2
    assert labels(result) == ["Code only", "Code only", "Runtime only"]


def test_only_a_suppressed_match_is_a_conflict_not_an_issue():
    result = run([sast("s1", status="suppressed", reason="bound query parameter")], [dast("d1")])
    assert result["issues"] == []
    assert result["conflicts"][0]["sast_ids"] == ["sast:s1"] and "bound query parameter" in result["conflicts"][0]["reason"]
    assert result["suppressed"][0]["sast_id"] == "sast:s1"


def test_open_code_wins_over_suppressed():
    result = run([sast("s1"), sast("s2", status="suppressed", file="safe.php")], [dast("d1")])
    assert labels(result) == ["Confirmed"] and result["conflicts"] == []


def test_unnamed_code_input_is_a_candidate_not_a_link():
    result = run([sast("s1", params=(("*", "query"),))], [dast("d1")])
    assert labels(result) == ["Code only", "Runtime only"]
    runtime = next(i for i in result["issues"] if i["label"] == "Runtime only")
    assert runtime["candidates"] and runtime["ambiguous"] is False


# ---- FR-6: one issue per real bug ----

def test_alternative_sinks_of_one_bug_are_one_issue():
    result = run([sast("s1"), sast("s2")], [dast("d1")])
    assert labels(result) == ["Confirmed"] and result["issues"][0]["sast_ids"] == ["sast:s1", "sast:s2"]


def test_two_bugs_in_one_handler_stay_two():
    code = [sast("s1", params=(("pid", "query"),), routes=[route("/s.php", "action=view")]),
            sast("s2", params=(("code", "query"),), routes=[route("/s.php", "action=track")])]
    runtime = [dast("d1", path="/s.php", selector="action=view", param="pid"),
               dast("d2", path="/s.php", selector="action=track", param="code")]
    assert labels(run(code, runtime)) == ["Confirmed", "Confirmed"]


def test_every_sighting_of_one_bug_is_one_issue():
    """The PRD's example: three scanner findings on the same bug are one issue."""
    runtime = [dast("d1", param="q"), dast("d2", param="q", location="body", method="POST")]
    result = run([sast("s1", params=(("q", "any"),))], runtime)
    assert labels(result) == ["Confirmed"]
    assert result["issues"][0]["sast_ids"] == ["sast:s1"] and result["issues"][0]["dast_ids"] == ["dast:d1", "dast:d2"]
    assert result["issues"][0]["evidence"]["runtime"][1]["id"] == "dast:d2"


def test_sightings_without_code_are_still_one_issue():
    runtime = [dast("d1", param="q"), dast("d2", param="q", location="body", method="POST")]
    assert labels(run([], runtime)) == ["Runtime only"]


def test_two_inputs_of_one_code_bug_found_separately_are_one_issue():
    result = run([sast("s1", params=(("id", "query"), ("name", "query")))], [dast("d1"), dast("d2", param="name")])
    assert labels(result) == ["Confirmed"] and len(result["links"]) == 2


def test_shared_helper_reached_from_many_routes_is_one_issue():
    code = sast("s1", routes=[route(f"/p{n}.php") for n in range(5)])
    runtime = [dast(f"d{n}", path=f"/p{n}.php") for n in range(5)]
    result = run([code], runtime)
    assert labels(result) == ["Confirmed"] and len(result["issues"][0]["dast_ids"]) == 5


# ---- FR-7: labels ----

def test_hard_coded_secret_is_code_only():
    secret = sast("s1", cwe="CWE-798", params=(), routes=[])
    assert labels(run([secret], [])) == ["Code only"]


def test_app_wide_finding_is_runtime_only():
    assert labels(run([], [dast("d1", cwe="CWE-1021", scope="app")])) == ["Runtime only"]


def test_low_confidence_code_only_is_kept_but_not_reported():
    result = run([sast("s1", confidence="low")], [])
    assert result["issues"][0]["reportable"] is False and result["stats"]["reportable"] == 0


def test_low_confidence_code_proven_at_runtime_is_reported():
    result = run([sast("s1", confidence="low")], [dast("d1")])
    assert result["issues"][0]["label"] == "Confirmed" and result["issues"][0]["reportable"] is True


def test_severity_is_the_highest_of_the_members():
    assert run([sast("s1")], [dast("d1")])["issues"][0]["severity"] == "critical"


# ---- determinism and re-scans ----

def mixed_inputs():
    code = [sast("s1"), sast("s2"), sast("s3", cwe="CWE-79", params=(("q", "any"),), file="b.php"),
            sast("s4", cwe="CWE-798", params=(), routes=[]), sast("s5", status="suppressed", file="c.php")]
    runtime = [dast("d1"), dast("d2", cwe="CWE-79", param="q"), dast("d3", cwe="CWE-79", param="q", location="body", method="POST"),
               dast("d4", cwe="CWE-1021", scope="app"), dast("d5", path="/z.php")]
    return code, runtime


def test_input_order_doesnt_change_the_output():
    code, runtime = mixed_inputs()
    expected = json.dumps(run(code, runtime))
    for seed in range(5):
        random.Random(seed).shuffle(code)
        random.Random(seed + 10).shuffle(runtime)
        assert json.dumps(run(code, runtime)) == expected


def test_rescanning_creates_no_copies():
    code, runtime = mixed_inputs()
    first = run(code, runtime)
    second = run(copy.deepcopy(code), copy.deepcopy(runtime))
    assert [i["issue_id"] for i in first["issues"]] == [i["issue_id"] for i in second["issues"]]


def test_output_matches_its_schema():
    jsonschema.Draft202012Validator(SCHEMA).validate(run(*mixed_inputs()))


# ---- the PRD's example, on real committed scanner output ----

def test_committed_examples_give_one_confirmed_issue(tmp_path):
    dast_doc = json.loads((EXAMPLES / "dast_sqli.common.json").read_text())
    dast_doc["findings"] += json.loads((EXAMPLES / "dast_passive.common.json").read_text())["findings"]
    (tmp_path / "dast.json").write_text(json.dumps(dast_doc))
    result = correlate(load_report(EXAMPLES / "sast_sqli.common.json", "sast"), load_report(tmp_path / "dast.json", "dast"))
    confirmed = [i for i in result["issues"] if i["label"] == "Confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0]["cwe"] == "CWE-89" and confirmed[0]["evidence"]["code"][0]["code"]["file"] == "app/lib/repositories.php"
    assert confirmed[0]["evidence"]["runtime"][0]["runtime"]["payload"]
    assert sum(i["label"] == "Runtime only" for i in result["issues"]) == 2


# ---- input checks ----

def write(tmp_path, doc, name="r.json"):
    path = tmp_path / name
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return path


@pytest.mark.parametrize("doc,message", [
    ("{not json", "can't read"),
    ({"schema_version": "1.0", "source": "sast"}, "common finding format"),
    ({"schema_version": "1.0", "source": "dast", "tool": "t", "findings": []}, "expected a sast report"),
])
def test_bad_reports_are_refused(tmp_path, doc, message):
    with pytest.raises(InputError, match=message):
        load_report(write(tmp_path, doc), "sast")


def test_duplicate_ids_are_refused(tmp_path):
    doc = {"schema_version": "1.0", "source": "sast", "tool": "t", "findings": [sast("ab"), sast("ab")]}
    with pytest.raises(InputError, match="unique"):
        load_report(write(tmp_path, doc), "sast")


def test_a_wrong_cwe_family_is_refused(tmp_path):
    finding = sast("ab", cwe="CWE-98")  # family should be CWE-22
    doc = {"schema_version": "1.0", "source": "sast", "tool": "t", "findings": [finding]}
    with pytest.raises(InputError, match="disagrees"):
        load_report(write(tmp_path, doc), "sast")


# ---- command line ----

def test_cli_writes_valid_issues(tmp_path):
    out = tmp_path / "issues.json"
    done = subprocess.run([sys.executable, "-m", "correlator.cli", "--sast", str(EXAMPLES / "sast_sqli.common.json"),
                           "--dast", str(EXAMPLES / "dast_sqli.common.json"), "--out", str(out)],
                          capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stderr
    assert "1 Confirmed" in done.stdout
    jsonschema.Draft202012Validator(SCHEMA).validate(json.loads(out.read_text()))


def test_cli_exits_2_on_bad_input(tmp_path):
    done = subprocess.run([sys.executable, "-m", "correlator.cli", "--sast", str(EXAMPLES / "dast_sqli.common.json"),
                           "--dast", str(EXAMPLES / "dast_sqli.common.json"), "--out", str(tmp_path / "o.json")],
                          capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 2 and "expected a sast report" in done.stderr


# ---- FR-9: prioritised list ----

def test_confirmed_sql_injection_ranks_above_a_code_only_weak_hash():
    """The PRD's example."""
    weak_hash = sast("hash", cwe="CWE-327", params=(), routes=[])
    weak_hash["severity"] = "critical"  # even when its severity is just as high
    result = run([sast("s1"), weak_hash], [dast("d1")])
    assert [(i["rank"], i["label"], i["cwe"]) for i in result["issues"]] == [(1, "Confirmed", "CWE-89"), (2, "Code only", "CWE-327")]


def test_within_a_label_higher_risk_comes_first():
    medium = sast("m", cwe="CWE-79", params=(("q", "query"),), file="m.php")
    medium["severity"] = "medium"
    result = run([medium, sast("c", file="c.php")], [])
    assert [i["cwe"] for i in result["issues"]] == ["CWE-89", "CWE-79"]
    assert result["issues"][0]["risk_score"] > result["issues"][1]["risk_score"]


# ---- CVSS v3.0 ----

@pytest.mark.parametrize("vector,expected", [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # the spec's reflected XSS example
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),   # scope changed raises the low-privilege weight
    ("AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
    ("AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4),
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss_base_scores_match_the_specification(vector, expected):
    from correlator import cvss
    assert cvss.base_score(cvss.parse(vector)) == expected


def test_cvss_temporal_score_and_rounding():
    from correlator import cvss
    metrics = cvss.parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
    assert cvss.temporal_score(cvss.base_score(metrics), metrics) == 9.1
    assert cvss.roundup(4.0) == 4.0 and cvss.roundup(4.02) == 4.1 and cvss.roundup(4.000000001) == 4.0
    assert [cvss.rating(s) for s in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)] == ["none", "low", "medium", "medium", "high", "high", "critical"]


def test_confirmed_sql_injection_gets_its_cvss_and_reasons():
    issue = run([sast("s1")], [dast("d1")])["issues"][0]
    assert issue["cvss"] == {"version": "3.0", "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RC:C",
                             "base_score": 9.8, "temporal_score": 9.6, "rating": "critical"}
    assert issue["risk_score"] == 9.6
    assert any("E:F" in f and "exploited" in f for f in issue["risk_factors"])
    assert any("RC:C" in f for f in issue["risk_factors"])


def test_code_only_scores_lower_than_the_same_bug_proven():
    proven = run([sast("a")], [dast("d1")])["issues"][0]["risk_score"]
    unproven = run([sast("a")], [])["issues"][0]
    assert unproven["risk_score"] < proven and "E:U" in unproven["cvss"]["vector"] and "RC:R" in unproven["cvss"]["vector"]


def test_no_known_url_and_low_confidence_lower_the_score():
    reachable = run([sast("a")], [])["issues"][0]["risk_score"]
    no_route = run([sast("a", routes=[])], [])["issues"][0]
    low = run([sast("a", confidence="low")], [])["issues"][0]
    assert no_route["risk_score"] < reachable and "AV:L" in no_route["cvss"]["vector"]
    assert low["risk_score"] < reachable and "RC:U" in low["cvss"]["vector"]


def test_hard_coded_secret_keeps_network_access_without_a_route():
    """A leaked password is usable from anywhere, so no known URL doesn't lower it."""
    issue = run([sast("k", cwe="CWE-798", params=(), routes=[])], [])["issues"][0]
    assert "AV:N" in issue["cvss"]["vector"]


def test_xss_through_a_header_is_harder_to_exploit():
    via_query = run([], [dast("d1", cwe="CWE-79", param="q")])["issues"][0]
    via_header = run([], [dast("d1", cwe="CWE-79", param="User-Agent", location="header")])["issues"][0]
    assert "AC:H" in via_header["cvss"]["vector"] and via_header["risk_score"] < via_query["risk_score"]


def test_unknown_weakness_falls_back_to_the_scanner_severity():
    issue = run([sast("z", cwe="CWE-9999", params=(), routes=[])], [])["issues"][0]
    assert issue["cvss"]["base_score"] == 9.8 and "from critical severity" in issue["risk_factors"][0]


def test_held_back_issues_rank_last():
    result = run([sast("low", confidence="low", file="z.php"), sast("x", cwe="CWE-1021", params=(), routes=[], file="y.php")], [])
    assert result["issues"][-1]["reportable"] is False


def test_ranks_are_consecutive_and_stable():
    code, runtime = mixed_inputs()
    ranks = [i["rank"] for i in run(code, runtime)["issues"]]
    assert ranks == list(range(1, len(ranks) + 1))


# ---- FR-8: one page that tells a developer where to look ----

def test_page_shows_where_to_look_for_a_confirmed_issue():
    from correlator.report import render
    code = sast("s1")
    code["code"].update({"file": "app/orders.php", "line": 88, "snippet": "$db->query('SELECT ' . $id);"})
    runtime = dast("d1", path="/api/orders", url="http://h/api/orders?id=1")
    runtime["runtime"]["payload"] = "1'"
    page = render(run([code], [runtime]))
    for expected in ("http://h/api/orders?id=1", "id (query)", "1&#x27;", "app/orders.php:88", "$db-&gt;query(", "CWE-89", "critical", "Confirmed"):
        assert expected in page, expected


def test_page_escapes_attack_strings():
    from correlator.report import render
    runtime = dast("d1", cwe="CWE-79", param="q")
    runtime["runtime"]["payload"] = "<script>alert(1)</script>"
    page = render(run([], [runtime]))
    assert "<script>alert" not in page and "&lt;script&gt;alert" in page


def test_page_lists_issues_in_rank_order_and_links_to_each():
    from correlator.report import render
    result = run(*mixed_inputs())
    page = render(result)
    ids = [i["issue_id"] for i in result["issues"] if i["reportable"]]
    positions = [page.index(f'href="#{i}"') for i in ids]
    assert positions == sorted(positions)
    assert all(f'id="{i}"' in page for i in ids)


def test_cli_writes_the_page_next_to_the_json(tmp_path):
    out = tmp_path / "issues.json"
    subprocess.run([sys.executable, "-m", "correlator.cli", "--sast", str(EXAMPLES / "sast_sqli.common.json"),
                    "--dast", str(EXAMPLES / "dast_sqli.common.json"), "--out", str(out)], check=True, capture_output=True, cwd=ROOT)
    page = (tmp_path / "issues.html").read_text()
    assert "app/lib/repositories.php:4" in page and "/search.php" in page
