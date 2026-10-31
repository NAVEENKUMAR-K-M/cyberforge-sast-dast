from urllib.parse import parse_qs, urlparse

from core.models import InjectionPoint, ParamLocation
from scanners.probes.util import build_request


def test_query_location_preserves_sibling_form_fields():
    """Regression test: confirmed against live DVWA, a GET-method form's
    other fields (e.g. a "Submit" button) live in body_template, not in
    the point's URL -- a crawled <form method="GET"> never embeds field
    values in its action attribute. Dropping that sibling field meant
    DVWA's SQLi page (gated behind isset($_GET['Submit'])) never even
    reached the vulnerable code path during a real scan."""
    point = InjectionPoint(
        method="GET",
        url="http://localhost:8080/vulnerabilities/sqli/",  # bare action, no query string
        route_template="/vulnerabilities/sqli/",
        param="id",
        param_location=ParamLocation.QUERY,
        seed_value="",
        body_template={"Submit": "Submit"},
    )
    url, kwargs = build_request(point, "1' OR '1'='1")
    params = kwargs["params"]
    assert params["id"] == "1' OR '1'='1"
    assert params["Submit"] == "Submit", "the sibling 'Submit' field must still be sent"


def test_query_location_without_body_template_still_works():
    point = InjectionPoint(
        method="GET",
        url="http://localhost:8080/search?q=hello&page=1",
        route_template="/search",
        param="q",
        param_location=ParamLocation.QUERY,
        seed_value="hello",
    )
    url, kwargs = build_request(point, "payload")
    params = kwargs["params"]
    assert params["q"] == "payload"
    assert params["page"] == "1", "existing query params from the URL itself must still be preserved"
    assert urlparse(url).query == ""
