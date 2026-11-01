"""Cached HTTP for advisory and registry lookups. Only the standard library, like correlator/planner.py.

Every reply is cached on disk with the time it was fetched, so a rerun reproduces the same data and an offline run
(`offline=True`) reads only the cache. A committed cache is how the benchmark runs without network.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "cyberforge-sca")
USER_AGENT = "cyberforge-sca/1.0"


class Unavailable(Exception):
    """The data couldn't be fetched (offline and not cached, network error, rate limit). Never means "no data"."""


def _post(url, body, headers, timeout):
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


class Fetcher:
    def __init__(self, cache_dir: str | None = None, offline: bool = False, ttl: float = 86400, token: str | None = None,
                 timeout: float = 30, send=_post, clock=time.time):
        self.cache_dir = cache_dir or DEFAULT_CACHE
        self.offline, self.ttl, self.token, self.timeout = offline, ttl, token, timeout
        self._send, self._clock = send, clock

    def get_json(self, url: str):
        status, text, meta = self.request(url)
        return status, (json.loads(text) if status == 200 else None), meta

    def post_json(self, url: str, payload):
        status, text, meta = self.request(url, json.dumps(payload, sort_keys=True))
        return status, (json.loads(text) if status == 200 else None), meta

    def get_text(self, url: str):
        status, text, meta = self.request(url)
        return status, (text if status == 200 else None), meta

    def request(self, url: str, body: str | None = None):
        """Returns (status, text, {"source", "fetched_at"}). Raises Unavailable when nothing usable can be had."""
        path = os.path.join(self.cache_dir, hashlib.sha256(f"{url}\n{body or ''}".encode()).hexdigest() + ".json")
        cached = None
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as handle:
                cached = json.load(handle)
        if cached and (self.offline or self._clock() - cached["epoch"] < self.ttl):
            return cached["status"], cached["text"], {"source": "cache", "fetched_at": cached["fetched_at"]}
        if self.offline:
            raise Unavailable(f"offline and not cached: {url}")
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.token and url.startswith("https://api.github.com/"):
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            status, text = self._send(url, body.encode() if body is not None else None, headers, self.timeout)
        except (OSError, ValueError) as exc:
            if cached:
                return cached["status"], cached["text"], {"source": "cache (stale)", "fetched_at": cached["fetched_at"]}
            raise Unavailable(f"{url}: {exc}") from None
        if status in (403, 429) or status >= 500:      # rate limits and server trouble pass; they say nothing about the data
            if cached:
                return cached["status"], cached["text"], {"source": "cache (stale)", "fetched_at": cached["fetched_at"]}
            raise Unavailable(f"{url}: HTTP {status}")
        now = self._clock()
        record = {"url": url, "body": body, "status": status, "text": text, "epoch": now,
                  "fetched_at": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        os.makedirs(self.cache_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=1, sort_keys=True)
        return status, text, {"source": "live", "fetched_at": record["fetched_at"]}
