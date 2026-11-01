"""Stage 3: what is known about each package version: advisories (OSV, which mirrors GHSA), and their enrichment.

OSV's batch query returns only advisory IDs, so each ID's full record is fetched after it, and records that are the same
vulnerability under different IDs are merged by alias. Enrichment (the GHSA record's function list and published score,
EPSS, KEV) is looked up separately: when one of those is unavailable, that field says so and nothing else changes.

A successful query with no matches means "no known advisories returned by OSV at <time>". It is not a clean bill.
"""
from __future__ import annotations

import re

from sca.http import Unavailable

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
GHSA_API = "https://api.github.com/advisories/{}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
COMMIT_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})\b", re.I)


def release_version(version: str) -> str | None:
    """The version OSV can match, or None for a branch (dev-main, 1.x-dev) whose code isn't a release."""
    v = (version or "").strip()
    if not v or v.startswith("dev-") or v.endswith("-dev"):
        return None
    return v[1:] if v[:1] in "vV" and v[1:2].isdigit() else v


# Composer's own grammar (VersionParser::normalize): a number with up to four parts, or a date, then an optional
# stability modifier with its number, then an optional -dev, and build metadata (+...) that is ignored.
_MODIFIER = r"(?:[._-]?(?:(?P<mod>stable|beta|b|rc|alpha|a|patch|pl|p)(?P<after>(?:[.-]?\d+)*))?(?P<dev>[.-]?dev)?)?"
_CLASSICAL = re.compile(r"v?(?P<first>\d{1,5})(?P<rest>(?:\.\d+){0,3})" + _MODIFIER, re.I)
_DATE = re.compile(r"v?(?P<date>\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2})" + _MODIFIER, re.I)
_FIRST = ((-1,), 0, (), 0)      # sorts below every version: an advisory "introduced 0" starts at the beginning
_STABILITY = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "rc": 2, "stable": 3, "": 3, "patch": 4, "pl": 4, "p": 4}


def _key(version: str):
    """A sortable key in Composer's order, or None when Composer itself couldn't read the version. A version we
    can't read is never guessed at: callers report it as unknown."""
    text = (version or "").strip()
    plus = re.fullmatch(r"([^,\s+]+)\+\S+", text)
    if plus:
        text = plus.group(1)
    m = _CLASSICAL.fullmatch(text)
    if m:
        numbers = [int(m.group("first"))] + [int(x) for x in m.group("rest").split(".") if x]
        numbers += [0] * (4 - len(numbers))      # Composer pads an ordinary version to four parts
    else:
        m = _DATE.fullmatch(text)
        if not m:
            return None
        numbers = [int(x) for x in re.split(r"\D+", m.group("date")) if x]   # a date isn't padded: 2020.01.01 < 2020.01.01.0
    modifier, after, dev = (m.group("mod") or "").lower(), m.group("after") or "", m.group("dev")
    stability = _STABILITY[modifier]
    if dev and not modifier:
        stability = -1                          # 1.0.0-dev sorts below 1.0.0-alpha
    return (tuple(numbers), stability, tuple(int(x) for x in re.findall(r"\d+", after)), 0 if dev else 1)


def _in_range(version, events) -> bool | None:
    """Whether a version is inside any of an OSV range's introduced/fixed (or last_affected) spans, by Composer's
    ordering: a pre-release sorts below its release, so 3.1.0-beta is below an `introduced 3.1`."""
    mine = _key(version)
    if mine is None:
        return None
    start = None
    for event in events:
        if "introduced" in event:
            start = _FIRST if event["introduced"] == "0" else _key(event["introduced"])
            if start is None:
                return None            # a bound we can't read: don't skip the range as if it didn't apply
        elif start is not None and ("fixed" in event or "last_affected" in event):
            end = _key(event.get("fixed") or event.get("last_affected"))
            if end is None:
                return None
            if start <= mine and (mine < end if "fixed" in event else mine <= end):
                return True
            start = None
    if start is not None and start <= mine:
        return True
    return False


def _summarise(record: dict, package: str, version: str) -> dict:
    """The parts of an OSV record this package's row needs."""
    ranges, listed = [], []
    for affected in record.get("affected") or []:
        if (affected.get("package") or {}).get("name", "").lower() != package:
            continue
        for rng in affected.get("ranges") or []:
            ranges.append({"type": rng.get("type"), "events": rng.get("events") or [],
                           "applies": _in_range(version, rng.get("events") or []) if rng.get("type") in ("ECOSYSTEM", "SEMVER") else None})
        specific = affected.get("ecosystem_specific") or {}
        for item in specific.get("imports") or []:
            listed.extend(item.get("symbols") or [])
        listed.extend(specific.get("functions") or specific.get("vulnerable_functions") or [])
    fixed = sorted({e["fixed"] for r in ranges if r["applies"] for e in r["events"] if "fixed" in e}) or \
        sorted({e["fixed"] for r in ranges for e in r["events"] if "fixed" in e})
    references = [r.get("url") for r in record.get("references") or [] if r.get("url")]
    commits = []
    for url in references:
        m = COMMIT_URL.match(url)
        if m and (m.group(1), m.group(2), m.group(3).lower()) not in commits:
            commits.append((m.group(1), m.group(2), m.group(3).lower()))
    return {"summary": record.get("summary") or "", "details": record.get("details") or "",
            "published": record.get("published"), "modified": record.get("modified"),
            "severity": record.get("severity") or [], "ranges": ranges, "fixed_versions": fixed,
            "references": references, "fix_commits": commits, "osv_listed_functions": listed}


def lookup(inventory: dict, fetcher) -> dict:
    """Advisories for every locked package. Never says "safe": a failed query is `unavailable`."""
    result = {"source": "OSV", "status": "ok", "error": None, "fetched_at": None, "matches": {}, "no_match": [],
              "not_checked": {}}
    queries, names = [], []
    for name in sorted(inventory["packages"]):
        version = release_version(inventory["packages"][name]["version"])
        if version is None:
            result["not_checked"][name] = "a development branch, not a release, so advisories can't be matched by version"
            continue
        names.append(name)
        queries.append({"package": {"name": name, "ecosystem": "Packagist"}, "version": version})
    if not queries:
        return result
    try:
        status, data, meta = fetcher.post_json(OSV_BATCH, {"queries": queries})
    except Unavailable as exc:
        result.update(status="unavailable", error=str(exc))
        return result
    if status != 200 or not isinstance(data, dict):
        result.update(status="unavailable", error=f"OSV answered HTTP {status}")
        return result
    result["fetched_at"] = meta["fetched_at"]
    ids_by_package = {}
    for name, query, answer in zip(names, queries, data.get("results") or []):
        ids = [v["id"] for v in answer.get("vulns") or []]
        token = answer.get("next_page_token")
        while token:
            try:
                _, more, _ = fetcher.post_json(OSV_BATCH, {"queries": [{**query, "page_token": token}]})
            except Unavailable as exc:
                result["not_checked"][name] = f"only part of OSV's answer could be read: {exc}"
                break
            page = ((more or {}).get("results") or [{}])[0]
            ids += [v["id"] for v in page.get("vulns") or []]
            token = page.get("next_page_token")
        ids_by_package[name] = ids

    records = {}
    for vid in sorted({i for ids in ids_by_package.values() for i in ids}):
        try:
            status, record, meta = fetcher.get_json(OSV_VULN.format(vid))
            records[vid] = (record, meta["fetched_at"]) if status == 200 and record else (None, f"HTTP {status}")
        except Unavailable as exc:
            records[vid] = (None, str(exc))

    for name in names:
        ids = ids_by_package.get(name, [])
        if not ids:
            result["no_match"].append(name)
            continue
        version = release_version(inventory["packages"][name]["version"])
        merged = _merge(ids, records)
        result["matches"][name] = [_advisory(group, records, name, version) for group in merged]
    _enrich(result, fetcher)
    return result


def _merge(ids, records):
    """Groups IDs that are the same vulnerability (shared aliases), so it is listed once."""
    groups = []
    for vid in ids:
        record = records.get(vid, (None, None))[0] or {}
        names = {vid, *(record.get("aliases") or [])}
        hit = next((g for g in groups if g & names), None)
        if hit is None:
            groups.append(set(names))
        else:
            hit |= names
    out = []
    for group in groups:
        osv_ids = sorted(i for i in group if i in records)
        out.append({"osv_ids": osv_ids, "aliases": sorted(group)})
    return out


def _advisory(group, records, package, version):
    primary = next((i for i in group["osv_ids"] if i.startswith("GHSA-")), group["osv_ids"][0])
    record, fetched = records.get(primary, (None, None))
    advisory = {"id": primary, "aliases": [a for a in group["aliases"] if a != primary],
                "cves": [a for a in group["aliases"] if a.startswith("CVE-")],
                "url": f"https://osv.dev/vulnerability/{primary}", "malicious": primary.startswith("MAL-"),
                "record": "ok" if record else f"unavailable: {fetched}", "fetched_at": fetched if record else None}
    if record:
        advisory.update(_summarise(record, package, version))
    else:
        advisory.update({"summary": "", "details": "", "severity": [], "ranges": [], "fixed_versions": [],
                         "references": [], "fix_commits": [], "osv_listed_functions": []})
    return advisory


def _enrich(result, fetcher):
    advisories = [a for found in result["matches"].values() for a in found]
    for package, found in result["matches"].items():
        for advisory in found:
            advisory["ghsa"] = _ghsa(advisory, package, fetcher)
            advisory["cvss"] = _cvss(advisory)
    cves = sorted({c for a in advisories for c in a["cves"]})
    epss, kev = _epss(cves, fetcher), _kev(fetcher)
    for advisory in advisories:
        scores = [epss["scores"][c] for c in advisory["cves"] if c in epss.get("scores", {})]
        if epss["status"] != "ok":
            advisory["epss"] = {"status": "unavailable", "reason": epss["error"]}
        elif not advisory["cves"]:
            advisory["epss"] = {"status": "not applicable", "reason": "the advisory has no CVE"}
        elif scores:
            best = max(scores, key=lambda s: s["epss"])
            advisory["epss"] = {"status": "ok", **best, "fetched_at": epss["fetched_at"]}
        else:
            advisory["epss"] = {"status": "not scored", "reason": "FIRST has no score for this CVE yet", "fetched_at": epss["fetched_at"]}
        if kev["status"] != "ok":
            advisory["kev"] = {"status": "unavailable", "reason": kev["error"]}
        else:
            listed = [kev["entries"][c] for c in advisory["cves"] if c in kev["entries"]]
            advisory["kev"] = ({"status": "listed", "date_added": listed[0], "fetched_at": kev["fetched_at"]} if listed
                               else {"status": "not listed", "fetched_at": kev["fetched_at"]})


def _ghsa(advisory, package, fetcher):
    ghsa_id = next((i for i in [advisory["id"], *advisory["aliases"]] if i.startswith("GHSA-")), None)
    if ghsa_id is None:
        return {"status": "not applicable"}
    try:
        status, record, meta = fetcher.get_json(GHSA_API.format(ghsa_id))
    except Unavailable as exc:
        return {"status": "unavailable", "reason": str(exc)}
    if status != 200 or not record:
        return {"status": "unavailable", "reason": f"HTTP {status}"}
    functions = []
    for vuln in record.get("vulnerabilities") or []:
        if (vuln.get("package") or {}).get("name", "").lower() == package:
            functions.extend(vuln.get("vulnerable_functions") or [])
    severities = record.get("cvss_severities") or {}
    return {"status": "ok", "id": ghsa_id, "fetched_at": meta["fetched_at"], "vulnerable_functions": sorted(set(functions)),
            "cvss_v3": severities.get("cvss_v3") or None, "cvss_v4": severities.get("cvss_v4") or None,
            "cwes": [c.get("cwe_id") for c in record.get("cwes") or [] if c.get("cwe_id")]}


def _cvss(advisory):
    """The advisory's published base score: GHSA's when it has one, otherwise only the vector OSV gives."""
    ghsa = advisory.get("ghsa") or {}
    for version, key in (("3.1", "cvss_v3"), ("4.0", "cvss_v4")):
        entry = ghsa.get(key) or {}
        if entry.get("score") and entry.get("vector_string"):
            return {"score": entry["score"], "vector": entry["vector_string"], "version": version, "source": "GHSA"}
    vectors = [s.get("score") for s in advisory.get("severity") or [] if s.get("score")]
    return {"score": None, "vector": vectors[0] if vectors else None, "version": None,
            "source": "OSV (vector only; no published score was available)" if vectors else None}


def _epss(cves, fetcher):
    if not cves:
        return {"status": "ok", "scores": {}, "fetched_at": None, "error": None}
    scores, fetched = {}, None
    for start in range(0, len(cves), 50):
        chunk = cves[start:start + 50]
        try:
            status, data, meta = fetcher.get_json(EPSS_API.format(",".join(chunk)))
        except Unavailable as exc:
            return {"status": "unavailable", "error": str(exc)}
        if status != 200 or not isinstance(data, dict):
            return {"status": "unavailable", "error": f"HTTP {status}"}
        fetched = meta["fetched_at"]
        for row in data.get("data") or []:
            scores[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
    return {"status": "ok", "scores": scores, "fetched_at": fetched, "error": None}


def _kev(fetcher):
    try:
        status, data, meta = fetcher.get_json(KEV_FEED)
    except Unavailable as exc:
        return {"status": "unavailable", "error": str(exc)}
    if status != 200 or not isinstance(data, dict):
        return {"status": "unavailable", "error": f"HTTP {status}"}
    return {"status": "ok", "fetched_at": meta["fetched_at"],
            "entries": {v["cveID"]: v.get("dateAdded") for v in data.get("vulnerabilities") or [] if v.get("cveID")}}
