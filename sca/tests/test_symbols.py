import pytest
from helpers import FakeFetcher, write

from sca.phpindex import Index
from sca.symbols import commit_count, function_map, map_hunk, named_in, parse_diff

SOURCE = """<?php
namespace Acme\\Text;
class Splitter {
    public static function split(string $s): array
    {
        $parts = preg_split('/,/', $s);
        return $parts;
    }

    private function lexStructure(int $cursor, bool $extra = true): string
    {
        $value = $cursor;
        ++$cursor;
        return (string) $value;
    }

    public function helper() { return 1; }
}
"""

DIFF_SPLIT = """diff --git a/src/Text/Splitter.php b/src/Text/Splitter.php
index 1..2 100644
--- a/src/Text/Splitter.php
+++ b/src/Text/Splitter.php
@@ -4,6 +4,6 @@ class Splitter {
     public static function split(string $s): array
     {
-        $parts = preg_split('/,/', $s);
+        $parts = preg_split('/,/', $s, 100);
         return $parts;
     }

diff --git a/src/Text/Tests/SplitterTest.php b/src/Text/Tests/SplitterTest.php
--- a/src/Text/Tests/SplitterTest.php
+++ b/src/Text/Tests/SplitterTest.php
@@ -1,1 +1,2 @@
 <?php
+// test
"""

# A change to an unrelated function in the same file, as a merge brings in alongside the real fix.
DIFF_HELPER = """diff --git a/src/Text/Splitter.php b/src/Text/Splitter.php
--- a/src/Text/Splitter.php
+++ b/src/Text/Splitter.php
@@ -14,3 +14,3 @@ class Splitter {

-    public function helper() { return 1; }
+    public function helper() { return 2; }
 }
"""

# Written against an older branch: the signature differs, so only the declaration in the context can place it.
DIFF_OTHER_BRANCH = """diff --git a/src/Text/Splitter.php b/src/Text/Splitter.php
--- a/src/Text/Splitter.php
+++ b/src/Text/Splitter.php
@@ -100,4 +100,6 @@ private function somethingElse()
     }

     private function lexStructure(int $cursor): string
+    {
+        return $this->guard();
+    }
     {
"""


def mbox(diff, subject="Fix it", n=None, total=None):
    """One commit as `git format-patch` writes it, which is what GitHub serves at <commit>.patch."""
    tag = f"[PATCH {n}/{total}]" if n else "[PATCH]"
    head = (f"From {'0123456789abcdef' * 2 + '01234567'} Mon Sep 17 00:00:00 2001\nFrom: A Dev <dev@example.test>\n"
            f"Date: Thu, 27 Aug 2026 19:51:28 +0200\nSubject: {tag} {subject}\n\nWhy this changed.\n---\n"
            " src/Text/Splitter.php | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)\n\n")
    return head + diff + "-- \n2.43.0\n\n"


@pytest.fixture
def index(tmp_path):
    write(str(tmp_path), "vendor/acme/text/src/Text/Splitter.php", SOURCE)
    idx = Index(str(tmp_path))
    idx.add_tree(str(tmp_path / "vendor/acme/text"), "acme/text", "vendor/acme/text")
    return idx


def test_parse_diff_reads_files_and_hunks():
    files = parse_diff(DIFF_SPLIT)
    assert [f["old"] for f in files] == ["src/Text/Splitter.php", "src/Text/Tests/SplitterTest.php"]
    assert files[0]["hunks"][0]["old_start"] == 4


def test_the_patch_trailer_is_not_read_as_a_removed_line():
    hunk = parse_diff(mbox(DIFF_SPLIT))[0]["hunks"][0]
    assert ("-", "- ") not in hunk["lines"] and not any("2.43.0" in text for _, text in hunk["lines"])
    assert [kind for kind, _ in hunk["lines"]] == [" ", " ", "-", "+", " ", " ", " "]


def test_a_removed_line_that_looks_like_the_trailer_is_kept():
    diff = ("diff --git a/a.php b/a.php\n--- a/a.php\n+++ b/a.php\n@@ -1,3 +1,2 @@\n keep\n-- \n-gone\n keep too\n")
    hunk = parse_diff(diff)[0]["hunks"][0]
    assert ("-", "- ") in hunk["lines"] and ("-", "gone") in hunk["lines"]


def test_a_hunk_is_located_in_this_versions_own_file(index):
    hunk = parse_diff(DIFF_SPLIT)[0]["hunks"][0]
    found = map_hunk(index, "vendor/acme/text/src/Text/Splitter.php", hunk)
    assert [(f.label, how.startswith("patch located")) for f, how in found] == [("Acme\\Text\\Splitter::split", True)]


def test_a_hunk_from_another_branch_falls_back_to_the_declaration_in_its_context(index):
    hunk = parse_diff(DIFF_OTHER_BRANCH)[0]["hunks"][0]
    (fn, how), = map_hunk(index, "vendor/acme/text/src/Text/Splitter.php", hunk)
    assert fn.label == "Acme\\Text\\Splitter::lexStructure" and "declares this function" in how


def test_a_hunk_that_matches_nothing_is_unresolved(index):
    hunk = {"old_start": 1, "lines": [(" ", "nothing like this"), ("-", "anywhere in the file")]}
    assert map_hunk(index, "vendor/acme/text/src/Text/Splitter.php", hunk) == [(None, "the patch doesn't match this version's file")]


def test_naming_needs_the_class_and_the_method(index):
    split = index.funcs["acme\\text\\splitter::split"]
    assert named_in("ReDoS in Splitter::split()", split)
    assert named_in("The Splitter class: its split() method backtracks", split)
    assert not named_in("a string is split() badly", split)           # the method alone isn't enough
    assert not named_in("ReDoS in splitter handling", split)


def advisory(text="", commits=(), listed=()):
    return {"summary": text, "details": "", "fix_commits": [tuple(c.split("/")) for c in commits],
            "ghsa": {"vulnerable_functions": list(listed)}, "osv_listed_functions": []}


PATCH_URL = "https://github.com/acme/text/commit/abc1234.patch"
OTHER_URL = "https://github.com/acme/text/commit/def5678.patch"


def test_a_patch_candidate_is_promoted_only_when_the_advisory_names_it(index):
    fetcher = FakeFetcher({PATCH_URL: (200, mbox(DIFF_SPLIT))})
    unnamed = function_map(advisory("Denial of service.", ["acme/text/abc1234"]), "acme/text", index, fetcher)
    assert unnamed["affected"] == [] and [c["symbol"] for c in unnamed["candidates"]] == ["Acme\\Text\\Splitter::split"]
    named = function_map(advisory("ReDoS in Splitter::split().", ["acme/text/abc1234"]), "acme/text", index, fetcher)
    assert [a["symbol"] for a in named["affected"]] == ["Acme\\Text\\Splitter::split"]
    assert "named in the advisory text" in named["affected"][0]["provenance"]
    skipped = named["patches"][0]["skipped"]
    assert len(skipped) == 1 and skipped[0].startswith("src/Text/Tests/SplitterTest.php: ")    # the test file, with a reason


def advisory_with_files(files):
    """A fix commit that changes the given files (only their paths matter) and no PHP function of the package."""
    body = "".join(f"diff --git a/{f} b/{f}\n--- a/{f}\n+++ b/{f}\n@@ -1,1 +1,1 @@\n-old\n+new\n" for f in files)
    return FakeFetcher({PATCH_URL: (200, mbox(body))})


@pytest.mark.parametrize("files,expected_in_reason", [
    (["resources/js/scripts.js"], "not PHP (.js)"),
    (["src/views/error.blade.php"], "a Blade template"),
    (["resources/js/a.js", "src/views/e.blade.php"], "a Blade template"),
])
def test_a_fix_that_changes_no_php_function_says_what_it_changed(index, files, expected_in_reason):
    result = function_map(advisory("x", ["acme/text/abc1234"]), "acme/text", index, advisory_with_files(files))
    assert result["affected"] == result["candidates"] == []
    assert result["unresolved"][0].startswith("the fix changes no PHP function") and expected_in_reason in result["unresolved"][0]


def test_a_fix_that_touches_only_tests_is_not_blamed_on_other_files(index):
    result = function_map(advisory("x", ["acme/text/abc1234"]), "acme/text", index,
                          advisory_with_files(["src/Text/Tests/SplitterTest.php"]))
    assert result["unresolved"] == ["the fix commits changed no function in this version's source"]


def test_commit_count_tells_a_plain_commit_from_a_merge_series():
    assert commit_count(mbox(DIFF_SPLIT)) == 1
    assert commit_count(DIFF_SPLIT) == 1                     # a bare diff has no mbox header
    assert commit_count(mbox(DIFF_SPLIT, n=1, total=2) + mbox(DIFF_HELPER, "Other change", n=2, total=2)) == 2


def test_a_merge_commit_contributes_no_candidates(index):
    """A forward-port merge is served as the series it brought in; the unrelated change it carries must not become a
    candidate, while the plain fix commit next to it still maps."""
    series = mbox(DIFF_SPLIT, "Fix split", 1, 2) + mbox(DIFF_HELPER, "Unrelated helper tweak", 2, 2)
    fetcher = FakeFetcher({PATCH_URL: (200, mbox(DIFF_SPLIT)), OTHER_URL: (200, series)})
    result = function_map(advisory("Splitter::split() is slow.", ["acme/text/abc1234", "acme/text/def5678"]), "acme/text",
                          index, fetcher)
    assert [a["symbol"] for a in result["affected"]] == ["Acme\\Text\\Splitter::split"]
    assert result["candidates"] == []
    merges = [p for p in result["patches"] if "merge" in p]
    assert len(merges) == 1 and merges[0]["commit"] == "acme/text@def5678"
    assert merges[0]["merge"].startswith("a merge of 2 commits") and merges[0]["mapped"] == []


def test_only_a_merge_leaves_the_function_unresolved(index):
    series = mbox(DIFF_SPLIT, "Fix split", 1, 2) + mbox(DIFF_HELPER, "Unrelated", 2, 2)
    result = function_map(advisory("Splitter::split() is slow.", ["acme/text/def5678"]), "acme/text", index,
                          FakeFetcher({OTHER_URL: (200, series)}))
    assert result["affected"] == result["candidates"] == []
    assert "merges" in result["unresolved"][0]


def test_listed_functions_are_checked_against_this_versions_source(index):
    result = function_map(advisory(listed=["Acme\\Text\\Splitter::split", "Acme\\Text\\Splitter::gone"]), "acme/text", index,
                          FakeFetcher())
    assert [(a["symbol"], a["exists"]) for a in result["affected"]] == [("Acme\\Text\\Splitter::split", True),
                                                                        ("Acme\\Text\\Splitter::gone", False)]
    assert result["unresolved"] == ["the advisory references no fix commit"]


def test_an_unavailable_or_empty_commit_is_recorded_not_guessed(index):
    down = function_map(advisory("x", ["acme/text/abc1234"]), "acme/text", index, FakeFetcher())
    assert down["affected"] == down["candidates"] == [] and "couldn't be fetched" in down["unresolved"][0]
    empty = function_map(advisory("x", ["acme/text/abc1234"]), "acme/text", index, FakeFetcher({PATCH_URL: (200, "")}))
    assert "empty diff" in empty["unresolved"][0]
