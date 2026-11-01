import json

from helpers import package, project, write

from sca import inventory as inv


def test_lock_gives_versions_edges_and_shortest_paths(tmp_path):
    root = project(str(tmp_path), [package("a/web", requires=["b/core"]), package("b/core", requires=["c/util"]),
                                   package("c/util"), package("d/tool", dev=True)], {}, requires=["a/web"])
    data = inv.load(root)
    assert data["edges"][inv.ROOT] == ["a/web"]
    assert data["paths"]["c/util"] == [inv.ROOT, "a/web", "b/core", "c/util"]
    assert inv.display_path(data, "c/util") == ["test/app", "a/web", "b/core", "c/util"]
    assert data["packages"]["d/tool"]["dev"] is True
    assert inv.ancestors(data, "c/util") == {inv.ROOT, "a/web", "b/core"}


def test_replace_and_provide_resolve_edges_to_the_providing_package(tmp_path):
    poly = package("x/polyfill")
    poly["replace"] = {"x/mbstring": "*"}
    root = project(str(tmp_path), [package("a/web", requires=["x/mbstring"]), poly], {}, requires=["a/web"])
    assert inv.load(root)["edges"]["a/web"] == ["x/polyfill"]


def test_platform_requirements_are_not_packages(tmp_path):
    root = project(str(tmp_path), [package("a/web")], {})
    data = inv.load(root)
    assert "php" not in data["edges"][inv.ROOT] and data["edges"]["a/web"] == []


def test_identity_and_integrity_are_reported_separately(tmp_path):
    root = project(str(tmp_path), [package("a/web")], {}, sources={"a/web/src/A.php": "<?php"})
    found = inv.locate_sources(inv.load(root), str(tmp_path / "vendor"))["a/web"]
    assert found["present"] and found["matches_lock"]
    assert found["integrity"].startswith("not verified")


def test_an_install_record_that_differs_from_the_lock_is_not_a_match(tmp_path):
    root = project(str(tmp_path), [package("a/web")], {}, sources={"a/web/src/A.php": "<?php"})
    record = json.loads((tmp_path / "vendor/composer/installed.json").read_text())
    record["packages"][0]["version"] = "9.9.9"
    write(root, "vendor/composer/installed.json", json.dumps(record))
    found = inv.locate_sources(inv.load(root), str(tmp_path / "vendor"))["a/web"]
    assert not found["matches_lock"] and found["identity"].startswith("install record differs")


def test_missing_source_is_not_present(tmp_path):
    root = project(str(tmp_path), [package("a/web")], {})
    assert inv.locate_sources(inv.load(root), str(tmp_path / "vendor"))["a/web"]["present"] is False


def test_cyclonedx_has_purls_and_the_dependency_graph(tmp_path):
    root = project(str(tmp_path), [package("a/web", requires=["b/core"]), package("b/core", "v2.0.1")], {}, requires=["a/web"])
    bom = inv.cyclonedx(inv.load(root))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    refs = {c["purl"] for c in bom["components"]}
    assert refs == {"pkg:composer/a/web@1.0.0", "pkg:composer/b/core@v2.0.1"}
    graph = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert graph["root"] == ["pkg:composer/a/web@1.0.0"] and graph["pkg:composer/a/web@1.0.0"] == ["pkg:composer/b/core@v2.0.1"]


def test_no_lockfile_gives_an_empty_inventory(tmp_path):
    write(str(tmp_path), "composer.json", json.dumps({"require": {"a/web": "^1"}}))
    data = inv.load(str(tmp_path))
    assert data["lockfile"] is None and data["packages"] == {}
