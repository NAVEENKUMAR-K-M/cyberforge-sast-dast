"""The four statuses, per package and advisory. Each row starts Unknown and moves only on complete evidence.

- **Reachable**: static potential reachability. A path from a root to an affected function where every call resolved
  to one target. Not a demonstrated exploit, and not proof the path runs under every configuration.
- **Imported-only**: the package's code is used, its affected functions are known, and no path reaches them, within
  the analysed scope, with nothing unresolved that could reach them.
- **Present-only**: nothing in the analysed source uses the package, within the analysed scope, with nothing
  unresolved that could reach it.
- **Unknown**: anything less. "Never downgrade Unknown" means never trading uncertainty for a reassuring status
  without that evidence; a better-supported assessment later can still move a row either way.
"""
from __future__ import annotations

import hashlib
from collections import Counter

from sca.callgraph import first_doubt, path_assumptions, path_to
from sca.inventory import ROOT, ancestors, display_path

STATUS_ORDER = {"Reachable": 0, "Unknown": 1, "Imported-only": 2, "Present-only": 3}


def package_of(index, label: str):
    info = index.class_info(label)
    if info is not None:
        return info.package
    fns = index.functions.get(label.lower())
    if fns:
        return fns[0].package
    return index.owning_package(label)


def used_packages(index, reach) -> dict:
    """package -> how it is used, for every package used starting from the app: the app's own code, code the roots
    reach, and whatever a used package's code mentions. Packages mentioned only by packages nobody uses are not used:
    two unused packages that require each other don't make each other used."""
    uses = _mentions(index)
    used = {ROOT: "the app"}
    for state in reach.any:
        used.setdefault(index.funcs[state[0]].package, "code the roots reach")
    queue = list(used)
    while queue:
        by = queue.pop()
        for owner in sorted(uses.get(by, ())):
            if owner not in used:
                used[owner] = f"mentioned by {'the app' if by == ROOT else by}"
                queue.append(owner)
    return used


def _mentions(index) -> dict:
    """package -> packages its analysed source mentions (code, imports, extends, implements, traits)."""
    found: dict = {}

    def add(by, label):
        owner = package_of(index, label) if label else None
        if owner and owner != by:
            found.setdefault(by, set()).add(owner)

    for fn in list(index.funcs.values()):
        if fn.kind in ("method", "function", "file"):
            for label in index.references(fn):
                add(fn.package, label)
    for infos in index.classes.values():
        for info in infos:
            for label in info.parents + info.interfaces + info.traits:
                add(info.package, label)
    for info in index.files.values():
        for label in info["imports"]:
            add(info["package"], label)
    return found


def assess(package: str, advisory: dict, fmap: dict, ctx: dict) -> dict:
    inventory, sources, index, reach = ctx["inventory"], ctx["sources"], ctx["index"], ctx["reach"]
    seeing = {package} | ancestors(inventory, package)
    limits = list(ctx["global_limits"])
    row = {"id": hashlib.sha256(f"{package}|{inventory['packages'][package]['version']}|{advisory['id']}".encode()).hexdigest()[:16],
           "package": package, "version": inventory["packages"][package]["version"],
           "dev": inventory["packages"][package]["dev"], "dependency_path": display_path(inventory, package),
           "advisory": _advisory_view(advisory), "status": "Unknown", "reason": "", "path": None, "assumptions": [],
           "symbols": {"affected": fmap["affected"], "candidates": fmap["candidates"], "unresolved": fmap["unresolved"]},
           "patches": fmap["patches"],
           "source": {k: sources[package][k] for k in ("path", "identity", "integrity")},
           "scope": {"roots": ctx["roots_description"],
                     "packages_analysed": sorted(p for p in seeing if p != ROOT),
                     "call_kinds": ctx["call_kinds"]},
           "limits": limits}

    for name in inventory["packages"][package]["bin"]:
        limits.append(f"declares the executable {name}; process configuration isn't examined, so whether it is launched "
                      "is not known")
    missing = sorted(p for p in seeing if p != ROOT and not sources[p]["present"])
    if missing:
        limits.append("source not supplied for " + ", ".join(missing))
    if not sources[package]["matches_lock"] and sources[package]["present"]:
        limits.append(f"{package}: {sources[package]['identity']}")
    if not reach.complete:
        limits.append(f"call graph incomplete: {reach.limit}")

    affected = [s for s in fmap["affected"] if s["exists"]]
    candidates = [s for s in fmap["candidates"] if s["exists"]]

    for symbol in affected:
        steps = path_to(index, reach.exact, symbol["key"])
        if steps:
            row.update(status="Reachable", path=steps, assumptions=path_assumptions(steps),
                       reason=f"{symbol['symbol']} ({symbol['provenance']}) is reached from {steps[0]['function']} "
                              f"in {len(steps) - 1} calls, each resolved to one target")
            return row

    def unknown(reason, steps=None):
        row.update(status="Unknown", reason=reason, path=steps, assumptions=path_assumptions(steps) if steps else [])
        return row

    if not sources[package]["present"]:
        return unknown(f"the source of {package} wasn't supplied, so its functions can't be looked for")
    if sources[package]["identity"].startswith("install record differs"):
        return unknown(f"the supplied source of {package} isn't recorded as the locked version")
    for symbol in affected:
        steps = path_to(index, reach.any, symbol["key"])
        if steps:
            doubt = first_doubt(steps)
            return unknown(f"{symbol['symbol']} is reached only through a call that isn't resolved to one target "
                           f"({doubt['how']} at {doubt['file']}:{doubt['line']})", steps)
    for symbol in candidates:
        steps = path_to(index, reach.any, symbol["key"])
        if steps:
            doubt = first_doubt(steps)
            how = (f"has a path from an entry point only through calls not resolved to one target (first: {doubt['how']} "
                   f"at {doubt['file']}:{doubt['line']})" if doubt else "is reached through resolved calls")
            return unknown(f"{symbol['symbol']} {how}, and it is only a function the fix commit changed: the advisory "
                           "doesn't establish it as the affected function", steps)
    if missing:
        return unknown("source not supplied for " + ", ".join(missing) + ", which can call into " + package)
    if not reach.complete:
        return unknown(f"the call graph is incomplete ({reach.limit})")
    relevant = [site for state, site in reach.unresolved
                if (site.unresolved == "any" and index.funcs[state[0]].package in seeing)
                or (site.unresolved.startswith("missing:") and site.unresolved[8:] in seeing)]
    if relevant:
        sites = {(s.file, s.line): s for s in relevant}          # one call site is met once per object state it runs under
        kinds = Counter(s.how for s in sites.values()).most_common(3)
        common = ", ".join(f"{how} ×{n}" for how, n in kinds)
        first = min(sites.values(), key=lambda s: (s.file, s.line))
        row["limits"].append(f"{len(sites)} call(s) the analysis can't resolve, in code that can see {package}; most common: "
                             f"{common}; first at {first.file}:{first.line}")
        return unknown(f"{len(sites)} call(s) the analysis can't resolve, in code that can see {package}, could reach it "
                       f"(most common: {kinds[0][0]} ×{kinds[0][1]})")

    how_used = ctx["used"].get(package)
    present_reason = (f"nothing the app uses, directly or through other packages, mentions {package}, "
                      "and no root reaches its code")
    if not affected:
        reason = "; ".join(fmap["unresolved"]) or "no function of the package is identified as affected"
        if how_used:
            return unknown(f"the package is used ({how_used}), but its affected function isn't identified ({reason})")
        row.update(status="Present-only", reason=present_reason)
        return row
    if how_used:
        row.update(status="Imported-only",
                   reason=f"{package} is used ({how_used}), but no path from a root reaches "
                          + ", ".join(s["symbol"] for s in affected))
        return row
    row.update(status="Present-only", reason=present_reason)
    return row


def _advisory_view(advisory: dict) -> dict:
    return {k: advisory.get(k) for k in ("id", "aliases", "cves", "url", "summary", "published", "modified",
                                          "fixed_versions", "cvss", "epss", "kev", "record", "fetched_at")} | \
        {"ghsa": {k: v for k, v in (advisory.get("ghsa") or {}).items() if k in ("status", "id", "reason", "fetched_at", "cwes")}}


def order(rows: list) -> list:
    """Known exploitation first (Reachable, then Unknown), then Reachable, Unknown, Imported-only, Present-only;
    within each, EPSS then the published CVSS score. A KEV-listed Unknown isn't ranked below an unlisted Reachable."""
    def tier(row):
        kev = (row["advisory"].get("kev") or {}).get("status") == "listed"
        if kev and row["status"] in ("Reachable", "Unknown"):
            return 0
        return 1 + STATUS_ORDER[row["status"]]

    def key(row):
        epss = (row["advisory"].get("epss") or {}).get("epss")
        score = (row["advisory"].get("cvss") or {}).get("score")
        return (tier(row), STATUS_ORDER[row["status"]], -(epss if epss is not None else -1),
                -(score if score is not None else -1), row["package"], row["advisory"]["id"])

    ranked = sorted(rows, key=key)
    for rank, row in enumerate(ranked, 1):
        row["rank"] = rank
    return ranked
