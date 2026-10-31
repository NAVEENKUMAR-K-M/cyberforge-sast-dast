from core.models import InjectionPoint, ParamLocation
from discovery.crawler import CrawlResult
from discovery.injection_points import build_injection_points
from discovery.route_map_loader import hint_key, hint_keys, load_sast_hints
from discovery.templates import normalize, path_index


def test_placeholders_in_every_style_normalise_alike():
    for style in ("/orders/{order_id}/items", "/orders/{id}/items", "/orders/<int:id>/items", "/orders/<id>/items",
                  "/orders/:id/items", "/orders/{id:int}/items/", "/orders/{id?}/items"):
        assert normalize(style) == "/orders/{}/items"
    assert normalize("/") == "/" and normalize("/a/") == "/a" and normalize("/a?x=1") == "/a"


def test_path_parameters_are_known_by_position():
    assert path_index("/a/{x}/b/{y}", "y") == 1 and path_index("/a/<int:x>/b/<y>", "x") == 0
    assert path_index("/a/{x}", "z") is None


def test_a_hint_written_with_one_name_reaches_a_point_with_another(tmp_path):
    hints = tmp_path / "h.json"
    hints.write_text('{"hints": [{"route": "/orders/{order_id}", "method": "GET", "param": "order_id", "selector": null, "cwe": "CWE-89"}]}')
    index = load_sast_hints(hints)
    # a crawl calls the same placeholder {id}
    found = [index[k] for k in hint_keys("GET", "/orders/{id}", "id", "path", None) if k in index]
    assert found == [["CWE-89"]]
    assert hint_key("get", "/orders/{x}/", "q", None) == hint_key("GET", "/orders/{y}", "q", None)


def test_a_spot_the_code_knows_is_not_tested_twice():
    crawl = CrawlResult()
    crawl.urls.update({"http://127.0.0.1:9/orders/7", "http://127.0.0.1:9/search?q=a"})
    route_map = [
        {"method": "GET", "path": "/orders/{order_id}", "params": [{"name": "order_id", "location": "path", "type": "validated"}], "fields": []},
        {"method": "GET", "path": "/search", "params": [{"name": "q", "location": "query"}], "fields": []},
    ]
    points = build_injection_points(route_map, crawl, base_url="http://127.0.0.1:9")
    assert sorted((p.route_template, p.param, p.meta.get("origin")) for p in points) == [
        ("/orders/{order_id}", "order_id", "route_map"), ("/search", "q", "route_map")]
