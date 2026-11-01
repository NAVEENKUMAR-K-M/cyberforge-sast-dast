from helpers import FakeFetcher, osv_record, osv_replies, package, project

from sca import advisories
from sca import inventory as inv


def inventory(tmp_path, packages):
    return inv.load(project(str(tmp_path), packages, {}))


def test_batch_ids_are_followed_by_full_records_and_aliases_merge(tmp_path):
    data = inventory(tmp_path, [package("a/web", "v2.1.0")])
    records = {"GHSA-aaaa-bbbb-cccc": osv_record("GHSA-aaaa-bbbb-cccc", "a/web", "2.0.0", "2.1.5", aliases=["CVE-2026-1"]),
               "PKSA-1": osv_record("PKSA-1", "a/web", "2.0.0", "2.1.5", aliases=["CVE-2026-1"])}
    fetcher = FakeFetcher(osv_replies({"a/web": ["GHSA-aaaa-bbbb-cccc", "PKSA-1"]}, records, epss=[], kev=[]))
    result = advisories.lookup(data, fetcher)
    found = result["matches"]["a/web"]
    assert len(found) == 1 and found[0]["id"] == "GHSA-aaaa-bbbb-cccc" and found[0]["cves"] == ["CVE-2026-1"]
    assert found[0]["fixed_versions"] == ["2.1.5"]
    assert "https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc" in fetcher.calls


def test_no_match_is_reported_as_no_known_advisories_not_as_safe(tmp_path):
    result = advisories.lookup(inventory(tmp_path, [package("a/web")]), FakeFetcher(osv_replies({}, {})))
    assert result["status"] == "ok" and result["no_match"] == ["a/web"] and result["matches"] == {}


def test_an_unavailable_query_says_unavailable(tmp_path):
    result = advisories.lookup(inventory(tmp_path, [package("a/web")]), FakeFetcher())
    assert result["status"] == "unavailable" and result["no_match"] == []


def test_a_branch_version_is_not_checked(tmp_path):
    result = advisories.lookup(inventory(tmp_path, [package("a/web", "dev-main")]), FakeFetcher(osv_replies({}, {})))
    assert "a/web" in result["not_checked"] and result["no_match"] == []


def test_enrichment_availability_is_separate_from_the_advisory(tmp_path):
    data = inventory(tmp_path, [package("a/web", "2.1.0")])
    record = osv_record("GHSA-aaaa-bbbb-cccc", "a/web", "2.0.0", "2.1.5", aliases=["CVE-2026-1"])
    found = advisories.lookup(data, FakeFetcher(osv_replies({"a/web": ["GHSA-aaaa-bbbb-cccc"]},
                                                            {"GHSA-aaaa-bbbb-cccc": record})))["matches"]["a/web"][0]
    assert found["epss"]["status"] == "unavailable" and found["kev"]["status"] == "unavailable"
    assert found["ghsa"]["status"] == "unavailable"
    assert found["cvss"]["score"] is None and found["cvss"]["vector"].startswith("CVSS:3.1/")


def test_epss_not_scored_and_kev_listed(tmp_path):
    data = inventory(tmp_path, [package("a/web", "2.1.0")])
    record = osv_record("GHSA-aaaa-bbbb-cccc", "a/web", "2.0.0", "2.1.5", aliases=["CVE-2026-1"])
    ghsa = {"vulnerabilities": [{"package": {"name": "a/web"}, "vulnerable_functions": ["A\\Web::run"]}],
            "cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:N", "score": 7.5}}}
    found = advisories.lookup(data, FakeFetcher(osv_replies({"a/web": ["GHSA-aaaa-bbbb-cccc"]}, {"GHSA-aaaa-bbbb-cccc": record},
                                                            epss=[], kev=["CVE-2026-1"],
                                                            ghsa={"GHSA-aaaa-bbbb-cccc": ghsa})))["matches"]["a/web"][0]
    assert found["epss"]["status"] == "not scored" and found["kev"]["status"] == "listed"
    assert found["ghsa"]["vulnerable_functions"] == ["A\\Web::run"] and found["cvss"]["score"] == 7.5


def test_fix_commits_come_from_any_github_commit_reference(tmp_path):
    data = inventory(tmp_path, [package("a/web", "2.1.0")])
    record = osv_record("GHSA-aaaa-bbbb-cccc", "a/web", "2.0.0", "2.1.5",
                        commits=["a/web/commit/0123456789abcdef0123456789abcdef01234567", "a/web/pull/12"])
    found = advisories.lookup(data, FakeFetcher(osv_replies({"a/web": ["GHSA-aaaa-bbbb-cccc"]},
                                                            {"GHSA-aaaa-bbbb-cccc": record})))["matches"]["a/web"][0]
    assert found["fix_commits"] == [("a", "web", "0123456789abcdef0123456789abcdef01234567")]


def test_version_ranges():
    events = [{"introduced": "6.0.1"}, {"fixed": "6.4.46"}, {"introduced": "7.0.0"}, {"fixed": "7.4.19"}]
    assert advisories._in_range("v7.4.18", events) is True
    assert advisories._in_range("7.4.19", events) is False
    assert advisories._in_range("6.0.0", events) is False
    assert advisories._in_range("7.0.0-RC1", events) is False
    assert advisories._in_range("1.0", [{"introduced": "0"}, {"fixed": "3.35.3"}]) is True
    assert advisories.release_version("v7.4.18") == "7.4.18" and advisories.release_version("1.x-dev") is None
