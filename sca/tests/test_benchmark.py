"""The real benchmark (sca/benchmarks/composer-app), offline from its committed snapshot of advisory data."""
import json
import os

from sca.eval.score import score
from sca.http import Fetcher
from sca.scan import run

BENCH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmarks", "composer-app")


def scan():
    return run(BENCH, Fetcher(os.path.join(BENCH, "snapshot"), offline=True))


def test_the_benchmark_meets_its_key():
    report, _ = scan()
    with open(os.path.join(BENCH, "key.json")) as handle:
        result = score(report, json.load(handle))
    assert result["status_matches"] == "3/3"
    assert result["false_reachable"] == [] and result["unsafe_reassurance"] == []


def test_the_reachable_path_goes_through_the_bridge_to_headerutils():
    report, _ = scan()
    row = next(r for r in report["dependencies"] if r["package"] == "symfony/http-foundation")
    functions = [step["function"].split("\\")[-1] for step in row["path"]]
    assert functions == ["<public/index.php>", "HttpFoundationFactory::createRequest", "Request::__construct",
                         "Request::initialize", "HeaderBag::__construct", "HeaderBag::set", "HeaderBag::parseCacheControl",
                         "HeaderUtils::split"]
    assert row["path"][1]["package"] == "symfony/psr-http-message-bridge"
    assert all(step["called_from"]["exact"] for step in row["path"][1:])


def test_only_the_real_fix_commit_contributes_to_the_function_map():
    """GHSA-2v3c-qxhr-7vpv lists four fix commits; three are forward-port merges whose patch series also carries
    HeaderUtils, ExpressionLanguage and Kernel changes. Only the plain commit may map functions."""
    report, _ = scan()
    row = next(r for r in report["dependencies"] if r["package"] == "symfony/yaml")
    assert [a["symbol"] for a in row["symbols"]["affected"]] == ["Symfony\\Component\\Yaml\\Parser::lexInlineStructure"]
    assert row["symbols"]["candidates"] == []
    merges = [p for p in row["patches"] if "merge" in p]
    assert len(merges) == 3 and all(p["mapped"] == [] for p in merges)
    plain = [p for p in row["patches"] if "merge" not in p]
    assert [m["symbol"] for p in plain for m in p["mapped"]] == ["Symfony\\Component\\Yaml\\Parser::lexInlineStructure"]


def test_reruns_are_identical():
    first, sbom1 = scan()
    second, sbom2 = scan()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True) and sbom1 == sbom2


def test_packages_without_advisories_say_no_known_advisories():
    report, _ = scan()
    lookup = report["advisory_lookup"]
    assert "nyholm/psr7" in lookup["no_known_advisories"]["packages"]
    assert lookup["no_known_advisories"]["note"].startswith("no known advisories returned by OSV at ")
