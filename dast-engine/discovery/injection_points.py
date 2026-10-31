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
from urllib.parse import urlparse, parse_qs

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


def from_route_map(routes: list[dict]) -> list[InjectionPoint]:
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
            points.append(
                InjectionPoint(
                    method=r["method"],
                    url=r["path"],  # may be a template; resolved later against base_url
                    route_template=r["path"],
                    param=p["name"],
                    param_location=location,
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
) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    if route_map:
        points.extend(from_route_map(route_map))
    if openapi_routes:
        points.extend(from_route_map(openapi_routes))
    if crawl_result:
        points.extend(from_crawl(crawl_result))
    return dedupe_points(points)
