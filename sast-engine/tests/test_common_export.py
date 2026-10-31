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


def test_stored_flow_write_routes_carry_aliases():
    """A correlator matches a runtime finding on the write route too, including by alias."""
    from sast.common_export import to_common
    from sast.core.model import ScanResult
    ref = {"id": "w", "path": "/notes/index.php", "selector": None, "methods": ["POST"]}
    finding = {
        "fingerprint": "ab12", "cwe": "CWE-79", "cwe_family": "CWE-79", "title": "Cross-site scripting", "severity": "high",
        "confidence": "medium", "status": "open", "source_params": [{"name": "body", "location": "body"}], "routes": [],
        "file": "show.php", "line": 3, "snippet": "", "function": "<top-level>", "sink": "echo", "trace": [], "conditions": [],
        "suppression_reason": None, "engines": ["taint"],
        "stored_flow": {"store": "db:notes", "write_file": "add.php", "write_line": 2, "write_routes": [ref],
                        "read_file": "show.php", "read_line": 3},
    }
    result = ScanResult("php", "/src", "", [{"id": "w", "aliases": ["/notes/"]}], [finding])
    flow = to_common(result)["findings"][0]["code"]["stored_flow"]
    assert flow["write_routes"] == [{"path": "/notes/index.php", "aliases": ["/notes/"], "selector": None, "methods": ["POST"]}]
