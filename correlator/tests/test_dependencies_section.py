"""--sca adds a separate dependencies section and changes nothing about the issues."""
import json
import subprocess
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "common" / "examples"
SCHEMA = json.loads((ROOT / "correlator" / "issues.schema.json").read_text())
BENCH = ROOT / "sca" / "benchmarks" / "composer-app"


def correlate(tmp_path, name, *extra):
    out = tmp_path / name / "issues.json"
    done = subprocess.run([sys.executable, "-m", "correlator.cli", "--sast", str(EXAMPLES / "sast_sqli.common.json"),
                           "--dast", str(EXAMPLES / "dast_sqli.common.json"), "--out", str(out), *extra],
                          capture_output=True, text=True, cwd=ROOT)
    return done, out


def sca_report(tmp_path):
    out = tmp_path / "sca"
    done = subprocess.run([sys.executable, "-m", "sca.cli", "scan", str(BENCH), "--out", str(out),
                           "--cache-dir", str(BENCH / "snapshot"), "--offline"], capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stderr
    return out / "sca.json"


def test_the_section_is_added_valid_and_separate(tmp_path):
    plain, plain_out = correlate(tmp_path, "plain")
    with_sca, sca_out = correlate(tmp_path, "sca", "--sca", str(sca_report(tmp_path)))
    assert plain.returncode == with_sca.returncode == 0, with_sca.stderr
    a, b = json.loads(plain_out.read_text()), json.loads(sca_out.read_text())
    jsonschema.Draft202012Validator(SCHEMA).validate(b)
    assert "dependencies" not in a
    assert {k: v for k, v in b.items() if k not in ("dependencies", "inputs")} == {k: v for k, v in a.items() if k != "inputs"}
    statuses = {r["package"]: r["status"] for r in b["dependencies"]["rows"]}
    assert statuses == {"symfony/http-foundation": "Reachable", "symfony/yaml": "Unknown", "league/flysystem": "Present-only"}
    assert "Dependencies: 1 Reachable, 1 Unknown" in with_sca.stdout


def test_the_page_shows_the_section_escaped(tmp_path):
    report = json.loads(sca_report(tmp_path).read_text())
    report["dependencies"][0]["reason"] = "<script>alert(1)</script>"
    poisoned = tmp_path / "poisoned.json"
    poisoned.write_text(json.dumps(report))
    done, out = correlate(tmp_path, "page", "--sca", str(poisoned))
    page = out.with_suffix(".html").read_text()
    assert done.returncode == 0 and "<h2>Dependencies</h2>" in page
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "HeaderUtils::split" in page


def test_a_file_that_isnt_an_sca_report_exits_2(tmp_path):
    done, _ = correlate(tmp_path, "bad", "--sca", str(EXAMPLES / "dast_sqli.common.json"))
    assert done.returncode == 2 and "isn't an SCA report" in done.stderr
