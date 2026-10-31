from discovery.injection_points import derive_route_template, dedupe_points
from core.models import InjectionPoint, ParamLocation


def test_numeric_segment_collapsed():
    assert derive_route_template("/api/orders/17") == "/api/orders/{id}"
    assert derive_route_template("/api/orders/17/items/42") == "/api/orders/{id}/items/{id}"


def test_uuid_segment_collapsed():
    assert (
        derive_route_template("/api/users/550e8400-e29b-41d4-a716-446655440000")
        == "/api/users/{id}"
    )


def test_non_numeric_path_unchanged():
    assert derive_route_template("/vulnerabilities/sqli/") == "/vulnerabilities/sqli/"


def test_dedupe_points_collapses_duplicates():
    p1 = InjectionPoint(method="GET", url="http://x/a?id=1", route_template="/a", param="id", param_location=ParamLocation.QUERY)
    p2 = InjectionPoint(method="GET", url="http://x/a?id=1", route_template="/a", param="id", param_location=ParamLocation.QUERY)
    p3 = InjectionPoint(method="GET", url="http://x/a?id=2", route_template="/a", param="id", param_location=ParamLocation.QUERY)
    result = dedupe_points([p1, p2, p3])
    # p1/p2 share url+key so collapse; p3 has a different url so stays distinct
    assert len(result) == 2
