"""The hand-off: output must always match the format the correlator was promised."""
import json
import os
import subprocess
import sys

import jsonschema
import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
SHOP = os.path.join(ROOT, "benchmarks", "shop")


def cli(tmp_path, *extra):
    return subprocess.run([sys.executable, "-m", "sast.cli", "scan", SHOP, "--out", str(tmp_path), *extra],
                          capture_output=True, text=True, cwd=ROOT)


def test_output_matches_the_schema(tmp_path):
    done = cli(tmp_path, "--sarif")
    assert done.returncode == 0, done.stderr
    with open(os.path.join(ROOT, "docs", "sast-output.schema.json")) as handle:
        schema = json.load(handle)
    for name in ("findings.json", "routes.json"):
        with open(tmp_path / name) as handle:
            jsonschema.validate(json.load(handle), schema)


def test_sarif_has_every_finding_and_marks_safe_ones(tmp_path):
    cli(tmp_path, "--sarif")
    findings = json.load(open(tmp_path / "findings.json"))["findings"]
    sarif = json.load(open(tmp_path / "findings.sarif"))
    results = sarif["runs"][0]["results"]
    assert sarif["version"] == "2.1.0" and len(results) == len(findings)
    assert sum("suppressions" in r for r in results) == sum(f["status"] == "suppressed" for f in findings)


def test_missing_source_is_a_clear_error(tmp_path):
    done = subprocess.run([sys.executable, "-m", "sast.cli", "scan", str(tmp_path / "nope")], capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 2 and "not found" in done.stderr


def test_shop_scores_stay_perfect_on_the_key(tmp_path):
    """Guards against regressions. A failure here means something that used to be found was lost."""
    from eval.score import score
    cli(tmp_path)
    findings = json.load(open(tmp_path / "findings.json"))["findings"]
    result = score(findings, json.load(open(os.path.join(ROOT, "eval", "keys", "shop.json"))))
    assert not result["missed"] and not result["false_alarms"] and not result["wrong_route_or_param"]


def test_running_twice_gives_the_same_fingerprints(tmp_path):
    cli(tmp_path / "a")
    cli(tmp_path / "b")
    read = lambda d: sorted(f["fingerprint"] for f in json.load(open(tmp_path / d / "findings.json"))["findings"])
    assert read("a") == read("b") and len(read("a")) == len(set(read("a")))


def _fingerprints_with_seed(path, seed, tmp_path):
    env = dict(os.environ, PYTHONHASHSEED=str(seed))
    out = tmp_path / str(seed)
    subprocess.run([sys.executable, "-m", "sast.cli", "scan", path, "--out", str(out), "--no-semgrep"],
                   capture_output=True, text=True, cwd=ROOT, env=env, check=True)
    with open(out / "findings.json") as handle:
        findings = json.load(handle)["findings"]
    return sorted((f["fingerprint"], f["status"], f["confidence"], str(f["source_params"]), str(f["routes"])) for f in findings)


def test_results_dont_depend_on_set_ordering(tmp_path):
    """Python randomises set order per process, which once changed DVWA's finding count between runs."""
    app = tmp_path / "app"
    (app / "source").mkdir(parents=True)
    (app / "index.php").write_text("""<?php
        require_once 'lib.php';
        switch ($_COOKIE['level']) { case 'a': $f = 'a.php'; break; case 'b': $f = 'b.php'; break; default: $f = 'c.php'; }
        require_once "source/{$f}";
        render($html);
    """)
    (app / "lib.php").write_text("<?php function render($h) { echo '<div>' . $h . '</div>'; }")
    for name, code in {"a": "$_GET['x']", "b": "$_POST['y']", "c": "htmlspecialchars($_GET['z'])"}.items():
        (app / "source" / f"{name}.php").write_text(f"<?php require_once __DIR__ . '/../shared.php'; $html = '<p>' . {code} . '</p>';")
    (app / "shared.php").write_text("<?php $row = mysqli_fetch_assoc(mysqli_query($c, 'SELECT * FROM t')); $v = $_GET['q'];")
    results = [_fingerprints_with_seed(str(app), seed, tmp_path) for seed in (1, 2, 3, 4, 5)]
    assert results[0] and all(r == results[0] for r in results)


DVWA = os.path.join(ROOT, "benchmarks", "external", "dvwa")


@pytest.mark.skipif(not os.path.isdir(DVWA), reason="run benchmarks/fetch.sh first")
def test_dvwa_results_dont_depend_on_set_ordering(tmp_path):
    results = [_fingerprints_with_seed(DVWA, seed, tmp_path) for seed in (1, 2, 3)]
    assert results[0] and all(r == results[0] for r in results)
