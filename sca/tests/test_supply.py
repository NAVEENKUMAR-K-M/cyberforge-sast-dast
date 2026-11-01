import json
import os

from helpers import FakeFetcher, package, project, write

from sca import inventory as inv
from sca import supply

BENCH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmarks", "composer-app")


def test_content_hash_matches_what_composer_wrote():
    with open(os.path.join(BENCH, "composer.json")) as a, open(os.path.join(BENCH, "composer.lock")) as b:
        manifest, lock = json.load(a), json.load(b)
    assert lock["content-hash"] in supply.content_hashes(manifest)


def test_an_edited_composer_json_makes_the_lock_out_of_date(tmp_path):
    root = project(str(tmp_path), [package("a/web")], {})
    manifest = json.loads((tmp_path / "composer.json").read_text())
    manifest["require"]["b/new"] = "^1"
    write(root, "composer.json", json.dumps(manifest))
    kinds = [f["kind"] for f in supply.check(inv.load(root), {}, FakeFetcher(), popular=set())]
    assert kinds.count("lockfile out of date") == 2      # the hash, and b/new missing from the lock


def test_no_lockfile_and_branch_versions(tmp_path):
    write(str(tmp_path / "unlocked"), "composer.json", json.dumps({"require": {"a/web": "^1"}}))
    assert [f["kind"] for f in supply.check(inv.load(str(tmp_path / "unlocked")), {}, FakeFetcher(), popular=set())] == ["unlocked"]
    root = project(str(tmp_path / "branch"), [package("a/web", "dev-main")], {})
    found = supply.check(inv.load(root), {}, FakeFetcher(), popular=set())
    assert [f["kind"] for f in found] == ["unpinned"] and "dev-main" in found[0]["title"]


def test_a_malicious_record_is_a_finding(tmp_path):
    root = project(str(tmp_path), [package("a/web")], {})
    matches = {"a/web": [{"id": "MAL-2026-1", "malicious": True, "url": "https://osv.dev/vulnerability/MAL-2026-1"}]}
    found = supply.check(inv.load(root), matches, FakeFetcher(), popular=set())
    assert found[0]["kind"] == "malicious package" and found[0]["cwe"] == "CWE-506"


def test_a_canonical_custom_repository_is_not_a_confusion_finding(tmp_path):
    repo = {"type": "composer", "url": "https://repo.acme.test"}
    p = package("acme/internal")
    p["dist"]["url"] = "https://repo.acme.test/dists/acme-internal.zip"
    root = project(str(tmp_path), [p], {}, repositories=[repo])
    assert supply.check(inv.load(root), {}, FakeFetcher(), popular=set()) == []


def test_a_non_canonical_repository_with_the_name_on_packagist_is_a_risk(tmp_path):
    repo = {"type": "composer", "url": "https://repo.acme.test", "canonical": False}
    p = package("acme/internal")
    p["dist"]["url"] = "https://repo.acme.test/dists/acme-internal.zip"
    root = project(str(tmp_path), [p], {}, repositories=[repo])
    on_packagist = FakeFetcher({"https://repo.packagist.org/p2/acme/internal.json": (200, {"packages": {}})})
    found = supply.check(inv.load(root), {}, on_packagist, popular=set())
    assert [f["kind"] for f in found] == ["dependency-confusion risk"]
    unchecked = supply.check(inv.load(root), {}, FakeFetcher(), popular=set())
    assert [f["kind"] for f in unchecked] == ["dependency confusion (not checked)"]
    assert supply.check(inv.load(root), {}, FakeFetcher({"https://repo.packagist.org/p2/acme/internal.json": (404, None)}),
                        popular=set()) == []


def test_name_similarity_only_across_vendors(tmp_path):
    popular = {"symfony/http-foundation", "monolog/monolog", "symfony/polyfill-php80"}
    root = project(str(tmp_path), [package("symfonny/http-foundation"), package("symfony/polyfill-php81"),
                                   package("monolog/monolog")], {})
    found = supply.check(inv.load(root), {}, FakeFetcher(), popular=popular)
    assert [(f["kind"], f["package"]) for f in found] == [("name similarity", "symfonny/http-foundation")]
    assert "not evidence of typosquatting" in found[0]["evidence"]


def test_distance_counts_swaps_as_one():
    assert supply.distance("monolog", "monlog") == 1 and supply.distance("abcd", "abdc") == 1
