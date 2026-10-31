"""FR-3: the SAST engine's output in the common finding format (common/FORMAT.md)."""
import json
import os
import subprocess
import sys

import jsonschema
import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
SHOP = os.path.join(ROOT, "benchmarks", "shop")
SCHEMA_PATH = os.path.join(os.path.dirname(ROOT), "common", "finding.schema.json")


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    out = tmp_path_factory.mktemp("common")
    done = subprocess.run([sys.executable, "-m", "sast.cli", "scan", SHOP, "--out", str(out), "--no-semgrep"],
                          capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stderr
    load = lambda name: json.load(open(out / name))
    return {"common": load("findings.common.json"), "native": load("findings.json"), "routes": load("routes.json")}


def test_output_matches_the_common_schema(scan):
    schema = json.load(open(SCHEMA_PATH))
    jsonschema.Draft202012Validator(schema).validate(scan["common"])


def test_every_native_finding_is_exported_including_suppressed_ones(scan):
    native, common = scan["native"]["findings"], scan["common"]["findings"]
    assert len(common) == len(native) > 0
    assert sorted(f["id"] for f in common) == sorted("sast:" + f["fingerprint"] for f in native)
    assert sum(f["status"] == "suppressed" for f in common) == sum(f["status"] == "suppressed" for f in native)


def test_sql_injection_is_cwe_89_on_both_levels(scan):
    """The FR-3 example: SQL injection is CWE-89."""
    found = [f for f in scan["common"]["findings"] if f["cwe"] == "CWE-89" and f["status"] == "open"]
    assert found and all(f["cwe_family"] == "CWE-89" for f in found)
    orders = next(f for f in found if f["code"]["file"].endswith("api/orders.php"))
    assert [p["name"] for p in orders["params"]] == ["id"]
    assert orders["routes"][0]["path"] == "/api/orders.php"


def test_route_aliases_are_filled_in_from_the_route_map(scan):
    cart = next(f for f in scan["common"]["findings"] if f["code"]["file"].endswith("cart/index.php") and f["status"] == "open")
    assert cart["routes"][0]["path"] == "/cart/index.php" and cart["routes"][0]["aliases"] == ["/cart/"]


def test_code_fields_move_under_code_and_runtime_is_empty(scan):
    f = scan["common"]["findings"][0]
    assert f["source"] == "sast" and f["runtime"] is None
    assert {"file", "line", "snippet", "function", "sink", "trace"} <= set(f["code"])
