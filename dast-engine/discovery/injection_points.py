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
from urllib.parse import urlparse, parse_qs, urljoin

from core.models import InjectionPoint, ParamLocation
from discovery.crawler import CrawlResult

_NUMERIC_SEG = re.compile(r"^\d+$")
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
        # Required params (e.g. DVWA's "Submit" button, route_map_loader's
        # required_params): without these the request never reaches the
        # vulnerable code at all. Carried on every point for this route so
        # build_request() sends them alongside whichever param is actually
        # being fuzzed -- the same fix already applied to crawled GET forms.
        required = r.get("required_params") or {}
        for p in r.get("params", []):
            if not p.get("name"):
                continue
            loc = p.get("location", "query")
            try:
                location = ParamLocation(loc)
            except ValueError:
                location = ParamLocation.QUERY
            body_template = {k: v for k, v in required.items() if k != p["name"]} or None
            url = urljoin(base_url, r["path"].lstrip("/")) if base_url else r["path"]
            points.append(
                InjectionPoint(
                    method=r["method"],
                    url=url,
                    route_template=r["path"],
                    param=p["name"],
                    param_location=location,
                    body_template=body_template,
                    meta={"type": p.get("type"), "origin": "route_map"},
                )
            )
    return points


def from_crawl(crawl_result: CrawlResult) -> list[InjectionPoint]:
    points = []
    for url in crawl_result.urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        route_template = derive_route_template(parsed.path)
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
