"""FR-3 contract: both scanners' output fits one schema and agrees on the CWE.

Run from the repo root:  python -m pytest common/tests
Needs only pytest and jsonschema. Does not run either scanner; it checks the
committed examples (real output from both sides on the benchmark shop) and the
shared CWE table.
"""
import copy
import json
import sys
from pathlib import Path

import jsonschema
import pytest

COMMON = Path(__file__).resolve().parents[1]
EXAMPLES = COMMON / "examples"
sys.path.insert(0, str(COMMON.parent / "sast-engine"))

SCHEMA = json.loads((COMMON / "finding.schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def only(name):
    findings = load(name)["findings"]
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.common.json")), ids=lambda p: p.name)
def test_every_example_matches_the_schema(path):
    VALIDATOR.validate(json.loads(path.read_text(encoding="utf-8")))


def test_there_is_one_example_per_side():
    assert load("sast_sqli.common.json")["source"] == "sast"
    assert load("dast_sqli.common.json")["source"] == "dast"


def test_sql_injection_is_cwe_89_on_both_sides():
    """The FR-3 example, on real findings from the same app."""
    sast, dast = only("sast_sqli.common.json"), only("dast_sqli.common.json")
    assert sast["cwe"] == dast["cwe"] == "CWE-89"
    assert sast["cwe_family"] == dast["cwe_family"] == "CWE-89"


def test_the_pair_can_be_matched_on_route_and_parameter():
    sast, dast = only("sast_sqli.common.json"), only("dast_sqli.common.json")
    sast_paths = {r["path"] for r in sast["routes"]} | {a for r in sast["routes"] for a in r["aliases"]}
    assert dast["routes"][0]["path"] in sast_paths
    assert dast["params"][0]["name"] in {p["name"] for p in sast["params"]}


def test_each_side_fills_only_its_own_block():
    sast, dast = only("sast_sqli.common.json"), only("dast_sqli.common.json")
    assert sast["code"]["file"] and sast["runtime"] is None
    assert dast["runtime"]["payload"] and dast["code"] is None


def test_ids_are_namespaced_so_the_two_sources_cannot_collide():
    assert only("sast_sqli.common.json")["id"].startswith("sast:")
    assert only("dast_sqli.common.json")["id"].startswith("dast:")


def test_cwe_family_of_every_example_comes_from_the_shared_table():
    table = {int(k): v for k, v in json.loads((COMMON / "cwe_families.json").read_text(encoding="utf-8"))["families"].items()}
    for path in EXAMPLES.glob("*.common.json"):
        for f in json.loads(path.read_text(encoding="utf-8"))["findings"]:
            number = int(f["cwe"].split("-")[1])
            assert f["cwe_family"] == f"CWE-{table.get(number, number)}", f"{path.name}: {f['cwe']}"


def test_shared_cwe_table_has_not_drifted_from_the_sast_engine():
    """sast-engine's FAMILY is the source of truth; the shared copy must equal it."""
    from sast.core.cwe import FAMILY

    shared = {int(k): v for k, v in json.loads((COMMON / "cwe_families.json").read_text(encoding="utf-8"))["families"].items()}
    assert shared == FAMILY


# The schema must actually reject bad output, or the checks above prove nothing.

def invalid(mutate, name="sast_sqli.common.json"):
    doc = copy.deepcopy(load(name))
    mutate(doc["findings"][0])
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(doc)


def test_schema_rejects_a_malformed_cwe():
    invalid(lambda f: f.update(cwe="89"))


def test_schema_rejects_a_missing_cwe_family():
    invalid(lambda f: f.pop("cwe_family"))


def test_schema_rejects_a_sast_finding_that_carries_runtime_proof():
    invalid(lambda f: f.update(runtime=load("dast_sqli.common.json")["findings"][0]["runtime"]))


def test_schema_rejects_a_dast_finding_with_no_runtime_proof():
    invalid(lambda f: f.update(runtime=None), name="dast_sqli.common.json")


def test_schema_rejects_native_confidence_words():
    invalid(lambda f: f.update(confidence="confirmed"), name="dast_sqli.common.json")


def test_schema_rejects_an_unknown_extra_field():
    invalid(lambda f: f.update(finding_id="abc"))
