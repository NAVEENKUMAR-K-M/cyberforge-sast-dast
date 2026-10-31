"""Lightweight crawler: follows in-scope links and forms, collects URLs with
query params, form actions/fields, and JS-embedded URLs. No execution engine
(Playwright is reserved for optional confirmation elsewhere) — this is a
fast, static HTML + regex crawl, which is enough for route discovery.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin

from bs4 import BeautifulSoup

from core.request_manager import RequestManager
from core.scope_guard import ScopeGuard

logger = logging.getLogger("dast.crawler")

JS_URL_RE = re.compile(r"""["'](/[A-Za-z0-9_\-/.]+?)["']""")

# Static-asset extensions worth recording for passive checks (e.g. an
# exposed backup) but not worth spending crawl-queue slots following links
# *to* — they're never an injection surface and, on a doc-heavy app, can
# otherwise consume the entire page budget before the real routes are seen.
_SKIP_FOLLOW_EXT = (
    ".md", ".pdf", ".zip", ".dist", ".ini", ".log", ".tar", ".gz",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
)


def _should_follow(url: str) -> bool:
    path = url.split("?")[0].lower()
    return not path.endswith(_SKIP_FOLLOW_EXT)


@dataclass
class CrawledForm:
    method: str
    action: str
    fields: dict[str, str] = field(default_factory=dict)  # name -> default value
    field_types: dict[str, str] = field(default_factory=dict)  # name -> input type


@dataclass
class CrawlResult:
    urls: set[str] = field(default_factory=set)  # GET URLs with query params preserved
    forms: list[CrawledForm] = field(default_factory=list)
    api_specs: list[str] = field(default_factory=list)  # OpenAPI/Swagger documents the app publishes


async def _fetch_robots_sitemap(rm: RequestManager, base_url: str, seen: set[str]) -> None:
    for path in ("/robots.txt", "/sitemap.xml"):
        url = urljoin(base_url, path)
        resp = await rm.get(url)
        if resp is None or resp.status_code != 200:
            continue
        for match in re.finditer(r"https?://[^\s\"'<>]+", resp.text):
            seen.add(match.group(0))
        for match in re.finditer(r"(?im)^Disallow:\s*(\S+)", resp.text):
            seen.add(urljoin(base_url, match.group(1)))


# Where frameworks publish their API description: FastAPI, Flask-RESTX/flasgger/smorest, Spring, DRF, Rails.
SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/openapi.yaml", "/openapi.yml", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json", "/api/v1/openapi.json", "/api/docs/openapi.json", "/docs/openapi.json",
    "/swagger/v1/swagger.json", "/v2/api-docs", "/apispec_1.json", "/api/schema/?format=json", "/schema/?format=json",
)


async def _fetch_api_specs(rm: RequestManager, base_url: str) -> list[str]:
    specs = []
    for path in SPEC_PATHS:
        url = urljoin(base_url, path)
        resp = await rm.get(url)
        if resp is None or resp.status_code != 200:
            continue
        content_type = resp.headers.get("content-type", "").lower()
        # A single-page app answers every unknown path with its HTML shell, which says nothing about an API.
        if "json" in content_type or "yaml" in content_type or (path.endswith((".yaml", ".yml")) and "html" not in content_type):
            specs.append(url)
    return specs


def _parse_forms(html: str, page_url: str) -> list[CrawledForm]:
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for f in soup.find_all("form"):
        method = (f.get("method") or "GET").upper()
        action = urljoin(page_url, f.get("action") or page_url)
        fields: dict[str, str] = {}
        field_types: dict[str, str] = {}
        for inp in f.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower() if inp.name == "input" else "text"
            value = inp.get("value", "") if inp.name != "select" else ""
            fields[name] = value
            field_types[name] = itype
        forms.append(CrawledForm(method=method, action=action, fields=fields, field_types=field_types))
    return forms


async def crawl(
    rm: RequestManager,
    scope_guard: ScopeGuard,
    seed_urls: list[str],
    max_pages: int = 200,
) -> CrawlResult:
    result = CrawlResult()
    visited: set[str] = set()
    queue: list[str] = [urldefrag(u)[0] for u in seed_urls]

    base = seed_urls[0] if seed_urls else ""
    await _fetch_robots_sitemap(rm, base, result.urls)
    api_specs = await _fetch_api_specs(rm, base)
    result.urls.update(api_specs)
    result.api_specs = api_specs

    while queue and len(visited) < max_pages:
        if rm.budget.expired():
            logger.info("Crawler stopping: deadline reached")
            break
        url = queue.pop(0)
        if url in visited:
            continue
        if not scope_guard.is_in_scope(url):
            continue
        visited.add(url)

        resp = await rm.get(url)
        if resp is None:
            continue
        # Record the URL even on an error status: a 500 with a stack trace
        # or a 403 leaking a path is exactly what the passive scanner needs
        # to see. Only link/form extraction requires a successful HTML body.
        result.urls.add(url)
        if resp.status_code >= 400:
            continue

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type:
            continue

        html = resp.text
        result.forms.extend(_parse_forms(html, url))

        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            # Strip the fragment: it's never sent on the wire, so '#foo' and
            # '#bar' on the same page are the same request, not two pages.
            link = urldefrag(urljoin(url, a["href"]))[0]
            if scope_guard.is_in_scope(link) and link not in visited and _should_follow(link):
                queue.append(link)

        for match in JS_URL_RE.finditer(html):
            candidate = urldefrag(urljoin(url, match.group(1)))[0]
            if scope_guard.is_in_scope(candidate) and candidate not in visited and _should_follow(candidate):
                queue.append(candidate)

    return result
