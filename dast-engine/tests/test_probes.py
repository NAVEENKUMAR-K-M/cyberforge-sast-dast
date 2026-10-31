from unittest.mock import patch

import pytest

from core.models import InjectionPoint, ParamLocation
from core.request_manager import Budget, RequestManager
from core.scheduler import DeadlineTimer
from core.scope_guard import ScopeGuard
from discovery.baseline import get_baseline
from scanners.probes.cmdi import CmdiProbe
from scanners.probes.open_redirect import OpenRedirectProbe
from scanners.probes.path_traversal import PathTraversalProbe
from scanners.probes.sqli import SqliProbe
from scanners.probes.xss import XssProbe


def make_rm(base_url: str) -> RequestManager:
    guard = ScopeGuard(allowed_hosts=["127.0.0.1"], denylist_patterns=[])
    timer = DeadlineTimer(60)
    budget = Budget(deadline_ts=timer.start + 60, report_reserve_s=1)
    return RequestManager(scope_guard=guard, budget=budget, start_rps=50, floor_rps=10)


def make_point(url: str, param: str, method: str = "GET", location: ParamLocation = ParamLocation.QUERY) -> InjectionPoint:
    return InjectionPoint(method=method, url=url, route_template=url.split("?")[0], param=param, param_location=location)


# --- SQLi --------------------------------------------------------------

@pytest.mark.asyncio
async def test_sqli_probe_detects_vulnerable_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/sqli?id=1"
        point = make_point(url, "id")
        baseline = await get_baseline(rm, "GET", url)
        findings = await SqliProbe().detect(rm, point, baseline)
    finally:
        await rm.aclose()
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


@pytest.mark.asyncio
async def test_sqli_probe_ignores_doc_prose_mentioning_exception_names(vuln_app_url):
    """Regression test: confirmed against live DVWA, whose own setup docs
    mention "mysqli_sql_exception" in prose about PHP 8.1 compatibility --
    no error involved. A bare exception-class-name signature must not
    fire on that; it needs the "uncaught ..." / "...: " shape a real
    stack trace actually has."""
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/docs_decoy?id=1"
        point = make_point(url, "id")
        baseline = await get_baseline(rm, "GET", url)
        findings = await SqliProbe().detect(rm, point, baseline, hinted=True)
    finally:
        await rm.aclose()
    assert findings == [], "prose mentioning an exception class name must not be mistaken for a thrown error"


@pytest.mark.asyncio
async def test_sqli_probe_silent_on_decoy_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/sqli_decoy?id=1"
        point = make_point(url, "id")
        baseline = await get_baseline(rm, "GET", url)
        findings = await SqliProbe().detect(rm, point, baseline, hinted=True)
    finally:
        await rm.aclose()
    assert findings == [], "decoy (parameterised query, int-cast) must not be flagged"


# --- XSS -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_xss_probe_detects_vulnerable_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/xss?name=x"
        point = make_point(url, "name")
        findings = await XssProbe().detect(rm, point, baseline=None)
    finally:
        await rm.aclose()
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-79"


@pytest.mark.asyncio
async def test_xss_probe_silent_on_decoy_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/xss_decoy?name=x"
        point = make_point(url, "name")
        findings = await XssProbe().detect(rm, point, baseline=None)
    finally:
        await rm.aclose()
    assert findings == [], "HTML-escaped reflection must not be flagged"


def test_classify_context_ignores_quote_only_reflection_in_body_text():
    """Regression test: confirmed against live DVWA, a quote-wrapped
    marker landed unescaped inside a SQL error message's body *text*
    (not an attribute or script context) -- the DB query only broke on
    the quote character itself, with no angle bracket involved. Quotes
    are inert in plain body text -- only a surviving angle bracket can
    actually open a new tag -- so this must not be classified as
    exploitable even though the payload technically "survived" verbatim."""
    from scanners.probes.xss import _classify_context

    body = "<html><body><b>Fatal error</b>: bad value near 'dzabc12345' at line 1</body></html>"
    assert _classify_context(body, "'dzabc12345'") is None


def test_classify_context_flags_angle_bracket_reflection_in_body_text():
    from scanners.probes.xss import _classify_context

    body = "<html><body>Hello <dzabc12345></body></html>"
    assert _classify_context(body, "<dzabc12345>") == "html_body"


def test_classify_context_flags_attribute_context():
    from scanners.probes.xss import _classify_context

    body = '<html><body><input value="dzabc12345"></body></html>'
    assert _classify_context(body, '"dzabc12345"') == "attribute"


def test_classify_context_none_when_escaped():
    from scanners.probes.xss import _classify_context

    body = "<html><body>Hello &lt;dzabc12345&gt;</body></html>"
    assert _classify_context(body, "<dzabc12345>") is None


# --- Command injection -----------------------------------------------------

@pytest.mark.asyncio
async def test_cmdi_probe_detects_vulnerable_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/cmdi?host=localhost"
        point = make_point(url, "host")
        findings = await CmdiProbe().detect(rm, point, baseline=None)
    finally:
        await rm.aclose()
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"


@pytest.mark.asyncio
async def test_cmdi_probe_silent_on_decoy_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/cmdi_decoy?host=localhost"
        point = make_point(url, "host")
        findings = await CmdiProbe().detect(rm, point, baseline=None)
    finally:
        await rm.aclose()
    assert findings == [], "list-form shell=False call must not be flagged"


@pytest.mark.asyncio
async def test_cmdi_probe_ignores_coincidental_number_match(vuln_app_url):
    """Regression test: a computed marker that happens to coincide with a
    number already present on an unrelated, static page (an order
    number here) must not be mistaken for command execution."""
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/cmdi_coincidence?host=localhost"
        point = make_point(url, "host")
        with patch("scanners.probes.cmdi.random_small_ints", return_value=(100, 23)):
            findings = await CmdiProbe().detect(rm, point, baseline=None)
    finally:
        await rm.aclose()
    assert findings == [], "a coincidental match on a static, input-independent page must not be flagged"


@pytest.mark.asyncio
async def test_sqli_probe_ignores_exact_error_phrase_present_regardless_of_input(vuln_app_url):
    """Regression test: confirmed against live DVWA, verbatim -- its own
    help text reads "an uncaught mysqli_sql_exception" while describing a
    PHP version change, with no error involved and the same text shown
    for any input."""
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/docs_decoy?id=1"
        point = make_point(url, "id")
        baseline = await get_baseline(rm, "GET", url)
        findings = await SqliProbe().detect(rm, point, baseline, hinted=True)
    finally:
        await rm.aclose()
    assert findings == [], "exact error phrase present on a clean request too must not be flagged"


@pytest.mark.asyncio
async def test_xss_probe_ignores_reflection_in_a_non_html_response(vuln_app_url):
    """Regression test: confirmed on the benchmark shop, a page served as
    text/plain was reported as XSS, though a browser never runs that as markup."""
    rm = make_rm(vuln_app_url)
    try:
        point = make_point(f"{vuln_app_url}/xss_plain_text?q=a", "q")
        findings = await XssProbe().detect(rm, point, baseline=None)
    finally:
        await rm.aclose()
    assert findings == []


# --- Path traversal ----------------------------------------------------------

@pytest.mark.asyncio
async def test_path_traversal_probe_detects_vulnerable_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/traversal?page=readme.txt"
        point = make_point(url, "page")
        findings = await PathTraversalProbe().detect(rm, point, baseline=None, hinted=True)
    finally:
        await rm.aclose()
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-22"


@pytest.mark.asyncio
async def test_path_traversal_probe_ignores_generic_word_mentions(vuln_app_url):
    """Regression test: confirmed against live DVWA, a page that just
    mentions "localhost" in ordinary content must not be mistaken for a
    successful /etc/hosts read -- any traversal-confirmation signature
    needs to be distinctive, never a common word."""
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/mentions_localhost?page=x"
        point = make_point(url, "page")
        findings = await PathTraversalProbe().detect(rm, point, baseline=None, hinted=True)
    finally:
        await rm.aclose()
    assert findings == [], "a page merely mentioning a common word must not be flagged"


@pytest.mark.asyncio
async def test_path_traversal_probe_silent_on_decoy_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/traversal_decoy?page=readme.txt"
        point = make_point(url, "page")
        findings = await PathTraversalProbe().detect(rm, point, baseline=None, hinted=True)
    finally:
        await rm.aclose()
    assert findings == [], "realpath-confined handler must not be flagged"


# --- Open redirect -----------------------------------------------------------

@pytest.mark.asyncio
async def test_open_redirect_probe_detects_vulnerable_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/redirect?next=/"
        point = make_point(url, "next")
        findings = await OpenRedirectProbe().detect(rm, point, baseline=None, hinted=True)
    finally:
        await rm.aclose()
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-601"


@pytest.mark.asyncio
async def test_open_redirect_probe_silent_on_decoy_route(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/redirect_decoy?next=/"
        point = make_point(url, "next")
        findings = await OpenRedirectProbe().detect(rm, point, baseline=None, hinted=True)
    finally:
        await rm.aclose()
    assert findings == [], "relative-only allowlist must not be flagged"


@pytest.mark.asyncio
async def test_open_redirect_probe_not_tried_on_unrelated_param_name(vuln_app_url):
    rm = make_rm(vuln_app_url)
    try:
        url = f"{vuln_app_url}/redirect?next=/"
        point = make_point(url, "unrelated_field_name")
        findings = await OpenRedirectProbe().detect(rm, point, baseline=None, hinted=False)
    finally:
        await rm.aclose()
    assert findings == [], "an unhinted, non-redirect-looking param name should not be probed at all"
