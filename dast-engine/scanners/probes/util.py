"""Shared helpers for building payload requests and loading payload files.

Centralising this in one place means every probe treats all six param
locations (query/body/json/path/header/cookie) the same way, and keeps
the actual send/parse mechanics out of each CWE-specific module.
"""
from __future__ import annotations

import random
import string
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

import yaml

from core.models import InjectionPoint, ParamLocation

PAYLOADS_DIR = Path(__file__).resolve().parent.parent.parent / "payloads"


@lru_cache(maxsize=None)
def load_payloads(filename: str) -> dict:
    path = PAYLOADS_DIR / filename
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _location_value(point: InjectionPoint) -> str:
    loc = point.param_location
    return loc.value if isinstance(loc, ParamLocation) else str(loc)


def build_request(point: InjectionPoint, payload: str) -> tuple[str, dict]:
    """Returns (url, kwargs) ready for RequestManager.send(point.method, url, **kwargs)."""
    loc = _location_value(point)
    kwargs: dict = {}
    if point.headers:
        kwargs["headers"] = dict(point.headers)
    if point.cookies:
        kwargs["cookies"] = dict(point.cookies)

    if loc == "query":
        parsed = urlparse(point.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        flat = {k: (v[0] if v else "") for k, v in qs.items()}
        # A GET-method form's *other* fields (e.g. a "Submit" button) live
        # in body_template, not in the URL's own query string -- a crawled
        # <form method="GET"> never embeds field values in its `action`
        # attribute. Without this, those sibling fields silently vanish
        # from the request; confirmed in testing: DVWA's SQLi page gates
        # its query entirely behind `isset($_GET['Submit'])`, so dropping
        # that field meant the vulnerable code path never even ran.
        flat.update(point.body_template or {})
        flat[point.param] = payload
        url = urlunparse(parsed._replace(query=""))
        kwargs["params"] = flat
        return url, kwargs

    if loc == "body":
        data = dict(point.body_template or {})
        data[point.param] = payload
        kwargs["data"] = data
        return point.url, kwargs

    if loc == "json":
        data = dict(point.body_template or {})
        data[point.param] = payload
        kwargs["json"] = data
        return point.url, kwargs

    if loc == "path" and point.param:
        placeholder = "{" + point.param + "}"
        if placeholder in point.url:
            return point.url.replace(placeholder, payload), kwargs
        # no literal placeholder in this URL; fall back to a query param
        kwargs["params"] = {point.param: payload}
        return point.url, kwargs

    if loc == "header" and point.param:
        headers = dict(kwargs.get("headers", {}))
        headers[point.param] = payload
        kwargs["headers"] = headers
        return point.url, kwargs

    if loc == "cookie" and point.param:
        cookies = dict(kwargs.get("cookies", {}))
        cookies[point.param] = payload
        kwargs["cookies"] = cookies
        return point.url, kwargs

    # unknown/unsupported location: safest fallback is a query param
    kwargs["params"] = {point.param: payload} if point.param else {}
    return point.url, kwargs


def random_marker(prefix: str = "dz", length: int = 8) -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}{suffix}"


def random_small_ints() -> tuple[int, int]:
    return random.randint(1000, 9000), random.randint(100, 900)


async def is_clean_request_noise(rm, point: InjectionPoint, needle: str) -> bool:
    """True if `needle` (an error signature, a computed marker, ...) also
    appears in the response to a *harmless control value* for this same
    point, rather than the actual payload.

    The control value is a random alphanumeric token -- not the point's
    original seed value. That distinction matters: a seed value like
    "readme" is a *recognized* key that can render different content than
    the fallback page an *unrecognized* value (whether that's our payload
    or this control) triggers. Confirmed in testing: comparing against the
    seed value missed a false positive for exactly this reason (the seed
    showed a smaller, recognized-key page; both the payload and a neutral
    unrecognized value fell through to the same larger default page that
    happened to contain the matched phrase). Comparing against an equally
    "unrecognized but harmless" value isolates whether the special
    characters in the payload caused the match, or whether being merely
    unrecognized is enough on its own.

    Costs one extra request, paid only when a tentative match was already
    found -- the common (non-matching) case is unaffected.
    """
    control_value = random_marker(prefix="ctrl", length=10)
    url, kwargs = build_request(point, control_value)
    resp = await rm.send(point.method, url, **kwargs)
    if resp is None:
        return False  # can't confirm noise; don't block the finding on a failed request
    return needle in resp.text
