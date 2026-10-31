"""Builds the de-duplicated InjectionPoint list from the union of:
  - SAST-provided route_map.json (authoritative route templates)
  - Crawled URLs (query params) and forms (body params)
  - OpenAPI/Swagger specs discovered during crawl

Also derives a route_template for raw crawled URLs by collapsing path
segments that look like ids (numeric, uuid) into `{param}` placeholders,
so that /orders/17 and /orders/42 count as one route.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse, parse_qs, urljoin

from core.models import InjectionPoint, ParamLocation
from discovery.crawler import CrawlResult

_NUMERIC_SEG = re.compile(r"^\d+$")
_PATH_VALUE = re.compile(r"\{(\w+)\??\}")
_UUID_SEG = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def derive_route_template(path: str) -> str:
    segments = path.split("/")
    out = []
    for seg in segments:
        if _NUMERIC_SEG.match(seg) or _UUID_SEG.match(seg):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)


def from_route_map(routes: list[dict], base_url: str = "") -> list[InjectionPoint]:
    """`base_url`, when given, resolves each route's bare path (e.g.
    "/account/orders.php", exactly what SAST's routes.json and
    route_map_loader produce) into a concrete request URL. Without it, the
    request manager's scope guard rejects every route-map-sourced request
    outright -- confirmed in testing: a scan crashes on the first baseline
    request with "Refusing out-of-scope request: /account/orders.php",
    since a bare path has no host for the scope guard to check against.
    `route_template` always stays the original bare path."""
    points = []
    for r in routes:
        for p in r.get("params", []):
            if not p.get("name"):
                continue
            loc = p.get("location", "query")
            try:
                location = ParamLocation(loc)
            except ValueError:
                location = ParamLocation.QUERY
            url = urljoin(base_url, r["path"].lstrip("/")) if base_url else r["path"]
            url = _fill_path_values(url, p["name"] if location == ParamLocation.PATH else None)
            # A selector ("action=view") picks which code runs on a shared
            # path. It stays in the URL for every request to this point, query
            # and body alike: the code reads it from the query string.
            selector = r.get("selector")
            if selector:
                url = f"{url}?{urlencode(parse_qsl(selector, keep_blank_values=True))}"
            siblings, query_extras, body_extras = _split_fields(r.get("fields") or [], p["name"], location, r["method"])
            points.append(
                InjectionPoint(
                    method=r["method"],
                    url=url,
                    route_template=r["path"],
                    param=p["name"],
                    param_location=location,
                    seed_value="1" if location == ParamLocation.PATH else "",
                    body_template=siblings or None,
                    meta={"type": p.get("type"), "origin": "route_map"},
                    selector=selector,
                    query_extras=query_extras,
                    body_extras=body_extras,
                )
            )
    return points


def _fill_path_values(url: str, keep: str | None) -> str:
    """Route templates hold placeholders such as `{id}` or `{id?}`. Only the one being
    tested stays a placeholder, and the rest get a harmless value so the URL exists."""
    def fill(match: re.Match) -> str:
        return "{" + keep + "}" if match.group(1) == keep else "1"
    return _PATH_VALUE.sub(fill, url)


def _split_fields(fields: list[dict], tested: str, location: ParamLocation, method: str) -> tuple[dict, dict, dict]:
    """Sorts a route's other fields by where they belong. `siblings` travel with the tested
    value. The extras go in the other place: a POST can read `action` from its URL and
    `name` from its body, and either being in the wrong place means the code never runs."""
    siblings, query_extras, body_extras = {}, {}, {}
    same_place = {ParamLocation.QUERY: "query", ParamLocation.BODY: "body", ParamLocation.JSON: "body"}.get(location)
    for f in fields:
        name = f["name"]
        if name == tested:
            continue
        where = f.get("location")
        if where in ("any", None):
            where = same_place or ("query" if method == "GET" else "body")
        if method == "GET":
            where = "query"  # a GET has no body to put it in
        if where == same_place:
            siblings[name] = f["value"]
        elif where == "query":
            query_extras[name] = f["value"]
        elif where == "body":
            body_extras[name] = f["value"]
    return siblings, query_extras, body_extras


def from_crawl(crawl_result: CrawlResult) -> list[InjectionPoint]:
    points = []
    for url in sorted(crawl_result.urls):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        route_template = derive_route_template(parsed.path)
        points.extend(_path_value_points(parsed, route_template))
        for name, values in qs.items():
            points.append(
                InjectionPoint(
                    method="GET",
                    url=url,
                    route_template=route_template,
                    param=name,
                    param_location=ParamLocation.QUERY,
                    seed_value=values[0] if values else "",
                    meta={"origin": "crawl"},
                )
            )
    for form in crawl_result.forms:
        route_template = derive_route_template(urlparse(form.action).path)
        location = ParamLocation.BODY if form.method == "POST" else ParamLocation.QUERY
        for name, value in form.fields.items():
            ftype = form.field_types.get(name, "text")
            if ftype in ("submit", "button", "hidden") and name.lower() not in ("id",):
                # still record hidden fields as context, but they're rarely the
                # injectable param of interest; keep them as low-priority tier-2.
                pass
            points.append(
                InjectionPoint(
                    method=form.method,
                    url=form.action,
                    route_template=route_template,
                    param=name,
                    param_location=location,
                    seed_value=value,
                    body_template={k: v for k, v in form.fields.items() if k != name},
                    meta={"origin": "crawl_form", "field_type": ftype},
                )
            )
    return points


def _path_value_points(parsed, route_template: str) -> list[InjectionPoint]:
    """A value in the path is input too: `/orders/7` reads `7` just as `?id=7` would."""
    points = []
    segments = parsed.path.split("/")
    found = 0
    for index, segment in enumerate(segments):
        if not (_NUMERIC_SEG.match(segment) or _UUID_SEG.match(segment)):
            continue
        found += 1
        name = "id" if found == 1 else f"id{found}"
        template = "/".join([*segments[:index], "{" + name + "}", *segments[index + 1:]])
        points.append(
            InjectionPoint(
                method="GET",
                url=urlunparse(parsed._replace(path=template)),
                route_template=route_template,
                param=name,
                param_location=ParamLocation.PATH,
                seed_value=segment,
                meta={"origin": "crawl_path"},
            )
        )
    return points


def dedupe_points(points: list[InjectionPoint]) -> list[InjectionPoint]:
    seen: dict[str, InjectionPoint] = {}
    for p in points:
        key = p.key() + "|" + p.url
        if key not in seen:
            seen[key] = p
    return list(seen.values())


def build_injection_points(
    route_map: list[dict] | None,
    crawl_result: CrawlResult | None,
    openapi_routes: list[dict] | None = None,
    base_url: str = "",
) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    if route_map:
        points.extend(from_route_map(route_map, base_url))
    if openapi_routes:
        points.extend(from_route_map(openapi_routes, base_url))
    if crawl_result:
        points.extend(from_crawl(crawl_result))
    return dedupe_points(points)
