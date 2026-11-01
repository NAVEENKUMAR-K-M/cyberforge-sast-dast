"""The status rules, end to end on small Composer projects: each test is one claim the statuses must keep."""
import pytest
from helpers import FakeFetcher, osv_record, osv_replies, package, project

from sca.assess import order
from sca.scan import run

VULN = {"vuln/lib/src/Core.php": """<?php
namespace Vuln;
class Core {
    public static function unsafe($x) { return $x; }
    public static function safe($x) { return $x; }
    public function changed($x) { return $x; }
}
"""}
WRAP = {"wrap/lib/src/Wrapper.php": """<?php
namespace Wrap;
use Vuln\\Core;
class Wrapper {
    public function handle($x) { return Core::unsafe($x); }
    public function harmless($x) { return Core::safe($x); }
}
"""}
DIFF = """diff --git a/src/Core.php b/src/Core.php
--- a/src/Core.php
+++ b/src/Core.php
@@ -4,3 +4,3 @@ class Core {
     public static function unsafe($x) { return $x; }
     public static function safe($x) { return $x; }
-    public function changed($x) { return $x; }
+    public function changed($x) { return trim($x); }
"""
COMMIT = "vuln/lib/commit/0123456789abcdef0123456789abcdef01234567"
DIFF_URL = "https://github.com/vuln/lib/commit/0123456789abcdef0123456789abcdef01234567.patch"
DIFF = ("From 0123456789abcdef0123456789abcdef01234567 Mon Sep 17 00:00:00 2001\nSubject: [PATCH] Fix changed()\n\n---\n\n"
        + DIFF + "-- \n2.43.0\n")


def scan(tmp_path, app_code, *, ghsa_functions=("Vuln\\Core::unsafe",), summary="", commits=(), extra_replies=None,
         packages=None, sources=None, epss=(), kev=(), requires=None, **caps):
    packages = packages or [package("vuln/lib", "1.0.0", psr4={"Vuln\\": "src/"}),
                            package("wrap/lib", "1.0.0", requires=["vuln/lib"], psr4={"Wrap\\": "src/"})]
    root = project(str(tmp_path), packages, {"public/index.php": "<?php\nrequire __DIR__ . '/../vendor/autoload.php';\n" + app_code},
                   sources=sources if sources is not None else {**VULN, **WRAP},
                   requires=requires if requires is not None else ["wrap/lib"])
    record = osv_record("GHSA-vvvv-vvvv-vvvv", "vuln/lib", "0", "1.0.1", summary=summary, commits=commits, aliases=["CVE-2026-9"])
    ghsa = {"GHSA-vvvv-vvvv-vvvv": {"vulnerabilities": [{"package": {"name": "vuln/lib"}, "vulnerable_functions": list(ghsa_functions)}],
                                    "cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:N", "score": 7.5}}}}
    replies = osv_replies({"vuln/lib": ["GHSA-vvvv-vvvv-vvvv"]}, {"GHSA-vvvv-vvvv-vvvv": record},
                          epss=[{"cve": "CVE-2026-9", "epss": "0.5", "percentile": "0.9"}] if epss is not None else None,
                          kev=list(kev) if kev is not None else None, ghsa=ghsa)
    replies.update(extra_replies or {})
    report, _ = run(root, FakeFetcher(replies), **caps)
    return report["dependencies"][0]


def test_a_transitive_exact_path_is_reachable_with_its_steps(tmp_path):
    row = scan(tmp_path, "$w = new \\Wrap\\Wrapper();\n$w->handle($_GET['x']);\n")
    assert row["status"] == "Reachable"
    assert [s["function"] for s in row["path"]] == ["<public/index.php>", "Wrap\\Wrapper::handle", "Vuln\\Core::unsafe"]
    assert [s["package"] for s in row["path"][1:]] == ["wrap/lib", "vuln/lib"]
    assert row["assumptions"]


def test_used_without_reaching_the_affected_function_is_imported_only(tmp_path):
    row = scan(tmp_path, "$w = new \\Wrap\\Wrapper();\n$w->harmless($_GET['x']);\n")
    assert row["status"] == "Imported-only" and "Vuln\\Core::unsafe" in row["reason"]


def test_not_used_at_all_is_present_only(tmp_path):
    row = scan(tmp_path, "echo 'hello';\n")
    assert row["status"] == "Present-only" and row["path"] is None


def test_a_patch_candidate_alone_never_makes_reachable(tmp_path):
    code = "$c = new \\Vuln\\Core();\n$c->changed($_GET['x']);\n"
    row = scan(tmp_path, code, ghsa_functions=(), summary="Something in the core is unsafe.", commits=[COMMIT],
               extra_replies={DIFF_URL: (200, DIFF)}, requires=["vuln/lib"])
    assert row["status"] == "Unknown" and "only a function the fix commit changed" in row["reason"]
    assert row["path"] and row["path"][-1]["function"] == "Vuln\\Core::changed"
    named = scan(tmp_path / "named", code, ghsa_functions=(), summary="Core::changed() is unsafe.", commits=[COMMIT],
                 extra_replies={DIFF_URL: (200, DIFF)}, requires=["vuln/lib"])
    assert named["status"] == "Reachable"


def test_unavailable_epss_or_kev_never_changes_reachability(tmp_path):
    code = "$w = new \\Wrap\\Wrapper();\n$w->handle($_GET['x']);\n"
    with_enrichment = scan(tmp_path / "a", code)
    without = scan(tmp_path / "b", code, epss=None, kev=None)
    assert with_enrichment["status"] == without["status"] == "Reachable"
    assert without["advisory"]["epss"]["status"] == without["advisory"]["kev"]["status"] == "unavailable"


def test_a_relevant_unresolved_call_blocks_reassurance(tmp_path):
    row = scan(tmp_path, "$f = $_GET['f'];\n$f();\n")
    assert row["status"] == "Unknown" and "can't resolve" in row["reason"]


def test_the_unresolved_call_count_is_distinct_call_sites(tmp_path):
    """Base::run() has one unresolved call and runs under two different objects (A and B); three more are written
    out in the page. That is four call sites, however many ways the graph reaches them."""
    code = """class Base { public function run($f) { return $f(); } }
class A extends Base {}
class B extends Base {}
$a = new A(); $a->run($_GET['f']);
$b = new B(); $b->run($_GET['f']);
$g1 = $_GET['g1']; $g1();
$g2 = $_GET['g2']; $g2();
$g3 = $_GET['g3']; $g3();
"""
    row = scan(tmp_path, code)
    assert row["status"] == "Unknown"
    assert "4 call(s) the analysis can't resolve" in row["reason"] and "dynamic function call ×4" in row["reason"]
    assert any("4 call(s)" in limit and "first at public/index.php" in limit for limit in row["limits"])


def test_a_candidate_path_says_which_call_is_a_guess_and_doesnt_claim_the_function_is_reached(tmp_path):
    """The receiver's class isn't known, so `$x->changed()` is found by method name alone: a guess, not a resolved call."""
    code = "$x = $GLOBALS['service'];\n$x->changed($_GET['x']);\n"
    row = scan(tmp_path, code, ghsa_functions=(), summary="Something in the core is unsafe.", commits=[COMMIT],
               extra_replies={DIFF_URL: (200, DIFF)}, requires=["vuln/lib"])
    assert row["status"] == "Unknown"
    # scan() puts `<?php` and the autoload require above the code, so the call on its second line is line 4
    assert "method found by name only" in row["reason"] and "public/index.php:4" in row["reason"]
    assert "only a function the fix commit changed" in row["reason"]
    assert row["path"][-1]["function"] == "Vuln\\Core::changed" and not row["path"][-1]["called_from"]["exact"]


@pytest.mark.parametrize("code,uncapped", [
    ("$w = new \\Wrap\\Wrapper();\n$w->harmless($_GET['x']);\n", "Imported-only"),
    ("class Local { function a() { return $this->b(); } function b() { return 1; } }\n(new Local())->a();\n", "Present-only"),
])
def test_a_call_graph_cap_turns_a_reassuring_status_into_unknown(tmp_path, code, uncapped):
    """With the graph cut short, "nothing reaches it" can't be said: the part that wasn't explored may."""
    assert scan(tmp_path / "full", code)["status"] == uncapped
    capped = scan(tmp_path / "capped", code, max_states=1)
    assert capped["status"] == "Unknown" and "incomplete" in capped["reason"]
    assert any("call graph incomplete: stopped after" in limit for limit in capped["limits"])


def test_a_cap_larger_than_the_graph_changes_nothing(tmp_path):
    """The cap only matters when it cuts something off: a one-function app is explored in full under a cap of 1."""
    assert scan(tmp_path, "echo 'hello';\n", max_states=1)["status"] == "Present-only"


def test_a_call_graph_timeout_is_recorded_and_never_reassures(tmp_path):
    row = scan(tmp_path, "echo 'hello';\n", timeout=-1)      # already past
    assert row["status"] == "Unknown" and "stopped after -1 seconds" in row["reason"]


def test_a_short_timeout_is_reported_as_given(tmp_path):
    row = scan(tmp_path, "echo 'hello';\n", timeout=-0.25)
    assert "stopped after -0.25 seconds" in row["reason"]


def test_an_unresolved_call_in_code_that_cant_see_the_package_doesnt_block(tmp_path):
    sources = {**VULN, **WRAP, "other/lib/src/Other.php": "<?php\nnamespace Other;\nclass Other {\n"
                                                          "    public function go($f) { return $f(); }\n}\n"}
    packages = [package("vuln/lib", "1.0.0", psr4={"Vuln\\": "src/"}),
                package("wrap/lib", "1.0.0", requires=["vuln/lib"], psr4={"Wrap\\": "src/"}),
                package("other/lib", "1.0.0", psr4={"Other\\": "src/"})]
    row = scan(tmp_path, "echo 'hello';\n", packages=packages, sources=sources, requires=["wrap/lib", "other/lib"])
    assert row["status"] == "Present-only"     # other/lib isn't analysed: it has no path to vuln/lib


def test_a_bin_entry_is_an_uncertainty_not_a_launch(tmp_path):
    packages = [package("vuln/lib", "1.0.0", psr4={"Vuln\\": "src/"}, bin=["bin/vuln-tool"]),
                package("wrap/lib", "1.0.0", requires=["vuln/lib"], psr4={"Wrap\\": "src/"})]
    row = scan(tmp_path, "echo 'hello';\n", packages=packages)
    assert row["status"] == "Present-only"
    assert any("bin/vuln-tool" in limit and "not known" in limit for limit in row["limits"])


def test_missing_dependency_source_is_unknown(tmp_path):
    row = scan(tmp_path, "$w = new \\Wrap\\Wrapper();\n$w->handle(1);\n", sources=WRAP)
    assert row["status"] == "Unknown" and "wasn't supplied" in row["reason"]


def test_an_unidentified_affected_function_on_a_used_package_is_unknown(tmp_path):
    row = scan(tmp_path, "$w = new \\Wrap\\Wrapper();\n$w->harmless(1);\n", ghsa_functions=())
    assert row["status"] == "Unknown" and "isn't identified" in row["reason"]


def test_an_unidentified_affected_function_on_an_unused_package_is_still_present_only(tmp_path):
    row = scan(tmp_path, "echo 'hello';\n", ghsa_functions=())
    assert row["status"] == "Present-only"


def test_a_kev_listed_unknown_ranks_above_an_unlisted_reachable():
    def row(status, kev, epss, pkg):
        return {"status": status, "package": pkg, "advisory": {"id": pkg, "kev": {"status": kev}, "epss": {"epss": epss},
                                                              "cvss": {"score": 5.0}}}
    ranked = order([row("Reachable", "not listed", 0.9, "a"), row("Unknown", "listed", 0.1, "b"),
                    row("Present-only", "listed", 0.9, "c"), row("Imported-only", "not listed", 0.9, "d")])
    assert [r["package"] for r in ranked] == ["b", "a", "d", "c"] and ranked[0]["rank"] == 1


def test_the_assumptions_shown_to_people_are_plain_text():
    """They appear on the issue page and in the dashboard, which don't render markdown."""
    from sca.callgraph import ASSUMPTIONS
    assert ASSUMPTIONS and all("`" not in text for text in ASSUMPTIONS.values())
