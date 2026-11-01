"""Builds small Composer projects on disk, and a fetcher that answers from a dict instead of the network."""
from __future__ import annotations

import json
import os

from sca.http import Unavailable


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def package(name, version="1.0.0", requires=(), psr4=None, bin=(), files=(), dev=False, reference="a" * 40):
    entry = {"name": name, "version": version, "type": "library",
             "source": {"type": "git", "url": f"https://github.com/{name}.git", "reference": reference},
             "dist": {"type": "zip", "url": f"https://api.github.com/repos/{name}/zipball/{reference}", "reference": reference},
             "require": {"php": ">=8.1", **{r: "*" for r in requires}},
             "autoload": {"psr-4": psr4 or {}}}
    if files:
        entry["autoload"]["files"] = list(files)
    if bin:
        entry["bin"] = list(bin)
    entry["_dev"] = dev
    return entry


def project(root, packages, app_files, requires=None, sources=None, repositories=None):
    """An app with composer.json, composer.lock, vendor/composer/installed.json and the given source files."""
    requires = requires if requires is not None else [p["name"] for p in packages if not p["_dev"]]
    manifest = {"name": "test/app", "require": {"php": ">=8.1", **{r: "*" for r in requires}}}
    if repositories is not None:
        manifest["repositories"] = repositories
    lock = {"content-hash": "", "packages": [], "packages-dev": []}
    from sca.supply import content_hashes
    lock["content-hash"] = sorted(content_hashes(manifest))[0]
    installed = []
    for p in packages:
        entry = {k: v for k, v in p.items() if k != "_dev"}
        lock["packages-dev" if p["_dev"] else "packages"].append(entry)
        installed.append({**entry, "install-path": f"../{p['name']}"})
    write(root, "composer.json", json.dumps(manifest, indent=4))
    write(root, "composer.lock", json.dumps(lock, indent=4))
    write(root, "vendor/composer/installed.json", json.dumps({"packages": installed}, indent=4))
    for rel, text in (sources or {}).items():
        write(root, f"vendor/{rel}", text)
    for rel, text in app_files.items():
        write(root, rel, text)
    return root


class FakeFetcher:
    """Answers GETs and POSTs from `replies` ({url: (status, data)}); anything else is Unavailable."""

    def __init__(self, replies=None, down=()):
        self.replies, self.down, self.calls = dict(replies or {}), set(down), []

    def _answer(self, url):
        self.calls.append(url)
        if url in self.down or not any(url.startswith(u) for u in self.replies):
            raise Unavailable(f"no reply for {url}")
        key = next(u for u in self.replies if url == u) if url in self.replies else \
            next(u for u in self.replies if url.startswith(u))
        status, data = self.replies[key]
        return status, data, {"source": "test", "fetched_at": "2026-11-01T00:00:00Z"}

    def get_json(self, url):
        return self._answer(url)

    def post_json(self, url, payload):
        status, data, meta = self._answer(url)
        return status, data(payload) if callable(data) else data, meta

    def get_text(self, url):
        return self._answer(url)


def osv_record(vid, package, introduced, fixed, summary="", details="", commits=(), aliases=()):
    return {"id": vid, "aliases": list(aliases), "summary": summary, "details": details,
            "affected": [{"package": {"name": package, "ecosystem": "Packagist"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
            "references": [{"type": "WEB", "url": f"https://github.com/{c}"} for c in commits],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}


def osv_replies(matches: dict, records: dict, epss=None, kev=None, ghsa=None):
    """matches: {package: [ids]}; records: {id: record}. EPSS/KEV/GHSA left out are unavailable."""
    def batch(payload):
        return {"results": [{"vulns": [{"id": i} for i in matches.get(q["package"]["name"], [])]}
                            for q in payload["queries"]]}
    replies = {"https://api.osv.dev/v1/querybatch": (200, batch)}
    for vid, record in records.items():
        replies[f"https://api.osv.dev/v1/vulns/{vid}"] = (200, record)
    if epss is not None:
        replies["https://api.first.org/data/v1/epss"] = (200, {"data": epss})
    if kev is not None:
        replies["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"] = \
            (200, {"vulnerabilities": [{"cveID": c, "dateAdded": "2026-01-01"} for c in kev]})
    for vid, record in (ghsa or {}).items():
        replies[f"https://api.github.com/advisories/{vid}"] = (200, record)
    return replies
