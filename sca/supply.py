"""Stage 6: supply-chain checks. Each finding states its evidence and is worded no stronger than that evidence.

- malicious package: an OSV MAL-* record matched to this ecosystem, package and version (a fact);
- unlocked or unpinned: no lockfile, a lockfile out of step with composer.json, branches instead of releases (facts);
- dependency-confusion risk: only when the repository settings let a public package stand in for one from a private
  repository. Composer 2 repositories are canonical by default, so a custom repository alone isn't a finding;
- name similarity: a name a small edit away from a popular package under a different vendor. A warning, never a
  claim of typosquatting.
"""
from __future__ import annotations

import hashlib
import json
import os

from sca.advisories import release_version
from sca.http import Unavailable
from sca.inventory import ROOT

POPULAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "popular-packagist.txt")
CONTENT_HASH_KEYS = ["name", "version", "require", "require-dev", "conflict", "replace", "provide", "minimum-stability",
                     "prefer-stable", "repositories", "extra"]


def check(inventory: dict, matches: dict, fetcher, popular: set | None = None) -> list:
    findings = []
    findings += _malicious(matches)
    findings += _unpinned(inventory)
    findings += _confusion(inventory, fetcher)
    findings += _similar_names(inventory, popular if popular is not None else load_popular())
    return findings


def _malicious(matches):
    out = []
    for package, advisories in sorted(matches.items()):
        for advisory in advisories:
            if advisory["malicious"]:
                out.append({"kind": "malicious package", "package": package, "cwe": "CWE-506",
                            "title": f"{package} matches malicious-package record {advisory['id']}",
                            "evidence": f"OSV matched {advisory['id']} to Packagist {package} at this version",
                            "url": advisory["url"]})
    return out


def content_hashes(manifest: dict) -> set:
    """The content-hash Composer's Locker::getContentHash writes for this composer.json. Composer 2.11 added
    `config.policy` to it, so a lock written by an earlier release can carry the hash without it: both are accepted."""
    relevant = {key: manifest[key] for key in CONTENT_HASH_KEYS if key in manifest}
    config = manifest.get("config") or {}
    hashes = set()
    for with_policy in (True, False):
        current = dict(relevant)
        picked = {key: config[key] for key in ("platform", "policy") if key in config and (with_policy or key != "policy")}
        if picked:
            current["config"] = picked
        text = json.dumps(_php_arrays(dict(sorted(current.items()))), separators=(",", ":"), ensure_ascii=True)
        hashes.add(hashlib.md5(text.replace("/", "\\/").encode()).hexdigest())
    return hashes


def _php_arrays(value):
    """PHP decodes an empty JSON object as an empty array, and encodes it back as []."""
    if isinstance(value, dict):
        return {k: _php_arrays(v) for k, v in value.items()} if value else []
    if isinstance(value, list):
        return [_php_arrays(v) for v in value]
    return value


def _unpinned(inventory):
    out = []
    if inventory["manifest"] and not inventory["lockfile"]:
        return [{"kind": "unlocked", "package": None, "title": "composer.json has no composer.lock",
                 "evidence": "without a lockfile every install resolves versions again, so what runs isn't fixed"}]
    if not inventory["lockfile"]:
        return out
    manifest = inventory.get("manifest_data")
    if manifest is not None and inventory["content_hash"] and inventory["content_hash"] not in content_hashes(manifest):
        out.append({"kind": "lockfile out of date", "package": None,
                    "title": "composer.lock's content-hash doesn't match composer.json",
                    "evidence": "composer.json changed after the lock was written, so the lock may not be what it asks for"})
    for name in inventory["root"]["require"] + inventory["root"]["require_dev"]:
        if name not in inventory["packages"] and name not in inventory["edges"].get(ROOT, []):
            out.append({"kind": "lockfile out of date", "package": name,
                        "title": f"{name} is required by composer.json but not in composer.lock",
                        "evidence": "the lock doesn't record which version of it is installed"})
    for name, package in sorted(inventory["packages"].items()):
        if release_version(package["version"]) is None:
            out.append({"kind": "unpinned", "package": name, "title": f"{name} is locked to a branch ({package['version']})",
                        "evidence": f"a branch moves; the lock pins commit {package['reference'] or 'unknown'}"})
        elif package["source_type"] in ("git", "hg", "svn") and not package["reference"]:
            out.append({"kind": "unpinned", "package": name, "title": f"{name} comes from {package['source_type']} without a fixed reference",
                        "evidence": "nothing fixes which commit is installed"})
    return out


def _confusion(inventory, fetcher):
    out = []
    repositories = inventory["root"]["repositories"]
    if isinstance(repositories, dict):
        repositories = [{"name": k, **v} if isinstance(v, dict) else {"name": k, "disabled": v is False}
                        for k, v in repositories.items()]
    if any(r.get("packagist.org") is False or (r.get("name") == "packagist.org" and r.get("disabled")) for r in repositories):
        return out       # Packagist is switched off, so nothing public can stand in
    for repo in repositories:
        if not isinstance(repo, dict) or repo.get("type") in (None, "path", "artifact") or repo.get("canonical", True):
            continue      # canonical (the default): Composer won't look elsewhere for the packages it provides
        url = repo.get("url", "")
        allowed = repo.get("only")
        for name, package in sorted(inventory["packages"].items()):
            if allowed is not None and name not in allowed:
                continue
            origin = f"{package['dist_url'] or ''} {package['source_url'] or ''}"
            if not url or url.split("://")[-1].split("/")[0] not in origin:
                continue
            try:
                status, _, meta = fetcher.get_json(f"https://repo.packagist.org/p2/{name}.json")
            except Unavailable as exc:
                out.append({"kind": "dependency confusion (not checked)", "package": name,
                            "title": f"couldn't check whether {name} is also published on Packagist",
                            "evidence": f"{url} is non-canonical; Packagist lookup unavailable: {exc}"})
                continue
            if status == 200:
                out.append({"kind": "dependency-confusion risk", "package": name,
                            "title": f"{name} comes from a non-canonical repository and the same name is on Packagist",
                            "evidence": f"{url} has canonical: false, so Composer may prefer Packagist's {name} "
                                        f"(checked {meta['fetched_at']})"})
    return out


def load_popular() -> set:
    try:
        with open(POPULAR, encoding="utf-8") as handle:
            return {line.strip() for line in handle if line.strip() and not line.startswith("#")}
    except OSError:
        return set()


def distance(a: str, b: str) -> int:
    """Edit distance with adjacent swaps (optimal string alignment)."""
    previous2, previous = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            if previous2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                current[j] = min(current[j], previous2[j - 2] + 1)
        previous2, previous = previous, current
    return previous[-1]


def _similar_names(inventory, popular):
    """A vendor name on Packagist belongs to whoever registered it, so a near-miss under the *same* vendor is that
    vendor's own package. Only a different vendor is worth a warning."""
    out = []
    for name in sorted(inventory["packages"]):
        if name in popular:
            continue
        vendor = name.split("/")[0]
        limit = 1 if len(name) < 12 else 2
        close = sorted((distance(name, other), other) for other in popular
                       if other.split("/")[0] != vendor and abs(len(other) - len(name)) <= limit)
        close = [(d, other) for d, other in close if 0 < d <= limit]
        if close:
            out.append({"kind": "name similarity", "package": name,
                        "title": f"{name} is a few characters away from the popular {close[0][1]}",
                        "evidence": f"edit distance {close[0][0]} under a different vendor. A warning only: "
                                    "a similar name is not evidence of typosquatting"})
    return out
