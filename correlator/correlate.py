"""Links runtime findings to the code that causes them (FR-5), merges every sighting of a bug
into one issue (FR-6) and labels each issue by what proved it (FR-7).

Reads only the two scanners' `*.common.json` reports (common/FORMAT.md).
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import jsonschema

from correlator import evidence
from correlator.rank import rank

SCHEMA_VERSION = "1.0"
COMMON = Path(__file__).resolve().parents[1] / "common"
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
CONFIDENCE_ORDER = ["low", "medium", "high"]
# How a runtime route matched a code route, from most to least direct.
MATCH_KINDS = ["exact", "alias", "template", "stored-write"]


class InputError(Exception):
    """A report that can't be correlated, with a message saying why."""


@lru_cache(maxsize=1)
def _validator():
    schema = json.loads((COMMON / "finding.schema.json").read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


@lru_cache(maxsize=1)
def _families() -> dict:
    raw = json.loads((COMMON / "cwe_families.json").read_text(encoding="utf-8"))["families"]
    return {int(k): int(v) for k, v in raw.items()}


def load_report(path, expected_source: str) -> dict:
    """Reads one report and checks it before anything trusts it."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"{path}: can't read it as JSON ({exc})") from None
    errors = sorted(_validator().iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        where = "/".join(str(p) for p in errors[0].absolute_path) or "<root>"
        raise InputError(f"{path}: not in the common finding format ({where}: {errors[0].message[:160]})")
    if doc["source"] != expected_source:
        raise InputError(f"{path}: expected a {expected_source} report, but it's a {doc['source']} report")
    duplicates = sorted(i for i, n in Counter(f["id"] for f in doc["findings"]).items() if n > 1)
    if duplicates:
        raise InputError(f"{path}: finding IDs must be unique, but these repeat: {', '.join(duplicates[:5])}")
    for f in doc["findings"]:
        number = int(f["cwe"].split("-")[1])
        if f["cwe_family"] != f"CWE-{_families().get(number, number)}":
            raise InputError(f"{path}: {f['id']} reports {f['cwe']} in family {f['cwe_family']}, "
                             "which disagrees with common/cwe_families.json")
    return doc


# ---- matching (FR-5) ----

def _strip_base(path: str, base: str) -> str:
    """`/app/search.php` on an app served under `/app` is the code's `/search.php`."""
    if base and (path == base or path.startswith(base + "/")):
        return path[len(base):] or "/"
    return path


def _segments_match(template: str, path: str) -> bool:
    """`{name}` on either side stands for exactly one non-empty segment."""
    a, b = template.split("/"), path.split("/")
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        placeholder = (x.startswith("{") and x.endswith("}")) or (y.startswith("{") and y.endswith("}"))
        if not (x == y or (placeholder and x and y)):
            return False
    return True


def _route_kind(route: dict, path: str) -> str | None:
    if route["path"] == path:
        return "exact"
    if path in route.get("aliases", []):
        return "alias"
    if any(_segments_match(c, path) for c in [route["path"], *route.get("aliases", [])]):
        return "template"
    return None


def _route_views(route: dict, base: str) -> list:
    """SAST's --base-path puts the prefix on code routes and the DAST target URL carries it on runtime
    routes. Try the code route as written and without the prefix, so either tool may have added it."""
    views = [route]
    if base:
        bare = {**route, "path": _strip_base(route["path"], base),
                "aliases": [_strip_base(a, base) for a in route.get("aliases", [])]}
        if bare != route:
            views.append(bare)
    return views


def _selector_ok(code_selector, runtime_selector, url_query: dict) -> bool:
    """A code route reached only through `?action=view` matches only a test of that page."""
    if not code_selector:
        return True
    key, _, value = code_selector.partition("=")
    return runtime_selector == code_selector or url_query.get(key) == value


def _location_ok(code: str, runtime: str) -> bool:
    return code == runtime or (code == "any" and runtime in ("query", "body")) or "unknown" in (code, runtime)


def _match(dast: dict, sast: dict, dast_path: str, base: str = ""):
    """Returns (strength, basis) when this code finding explains this runtime finding, else None.
    "strong" means the parameter is named on both sides. "weak" means the code only knows the
    input came from somewhere in the request (`*`), which isn't enough to merge on."""
    if sast["cwe_family"] != dast["cwe_family"]:
        return None
    param = dast["params"][0]
    names = {p["name"] for p in sast["params"] if _location_ok(p["location"], param["location"])}
    if param["name"] in names:
        strength = "strong"
    elif "*" in names:
        strength = "weak"
    else:
        return None
    query = dict(parse_qsl(urlparse(dast["runtime"]["url"]).query))
    write_routes = (((sast.get("code") or {}).get("stored_flow") or {}).get("write_routes")) or []
    best = None
    for route, stored in [(r, False) for r in sast["routes"]] + [(r, True) for r in write_routes]:
        if not _selector_ok(route.get("selector"), dast["routes"][0]["selector"], query):
            continue
        for view in _route_views(route, base):
            kind = _route_kind(view, dast_path)
            if kind is None:
                continue
            kind = "stored-write" if stored else kind
            candidate = (MATCH_KINDS.index(kind), view["path"], route.get("selector") or "", kind)
            best = candidate if best is None else min(best, candidate)
    if best is None:
        return None
    return strength, {"kind": best[3], "code_route": best[1], "selector": best[2] or None,
                      "parameter": param["name"], "location": param["location"]}


# ---- grouping (FR-6) ----

def _carrier(f: dict) -> tuple:
    """Where the value that reaches this sink was last produced: the last step of its trace before
    the sink. Two sinks fed by the same built value share it. Two separately built statements don't."""
    steps = [t for t in f["code"]["trace"] if not t["note"].startswith("reaches sink")]
    return (steps[-1]["file"], steps[-1]["line"], steps[-1]["note"]) if steps else ()


def _code_groups(findings: list) -> list:
    """One bug in the code can reach several sinks, such as one built query used twice. Open findings
    with the same family, in the same function, sharing an input name and fed by the same built value,
    are one bug. Separately built statements are different bugs even when they use the same input:
    each needs its own fix, and a runtime test can't tell which one it hit."""
    parent = {f["id"]: f["id"] for f in findings}

    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_place = defaultdict(list)
    for f in findings:
        by_place[(f["cwe_family"], f["code"]["file"], f["code"]["function"], _carrier(f))].append(f)
    for members in by_place.values():
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if ({p["name"] for p in a["params"]} - {"*"}) & ({p["name"] for p in b["params"]} - {"*"}):
                    parent[root(a["id"])] = root(b["id"])
    groups = defaultdict(list)
    for f in findings:
        groups[root(f["id"])].append(f)
    return sorted((sorted(g, key=lambda f: f["id"]) for g in groups.values()), key=lambda g: g[0]["id"])


def _runtime_groups(findings: list, base: str):
    """Several sightings of one input are one observation: the same family, route, page, parameter and
    place in the request. A query sighting and a body sighting stay separate, since they are different
    requests, and join one issue only when they link to the same code bug."""
    groups = defaultdict(list)
    others = []
    for f in findings:
        if f["scope"] == "endpoint" and f["params"] and f["routes"]:
            route = f["routes"][0]
            param = f["params"][0]
            key = (f["cwe_family"], _strip_base(route["path"], base), route["selector"] or "",
                   param["name"], param["location"])
            groups[key].append(f)
        else:
            others.append(f)
    ordered = {key: sorted(groups[key], key=lambda f: f["id"]) for key in sorted(groups)}
    return ordered, sorted(others, key=lambda f: f["id"])


# ---- issues (FR-6) and labels (FR-7) ----

def _hash(prefix: str, parts) -> str:
    return f"{prefix}:" + hashlib.sha1("\0".join(parts).encode("utf-8")).hexdigest()[:16]


def _merged_routes(findings: list, base: str) -> list:
    merged = {}
    for f in findings:
        for r in f["routes"]:
            path = _strip_base(r["path"], base)
            entry = merged.setdefault((path, r["selector"] or ""), {"path": path, "aliases": set(), "selector": r["selector"], "methods": set()})
            entry["aliases"].update(r.get("aliases", []))
            entry["methods"].update(r["methods"])
    return [{**e, "aliases": sorted(e["aliases"]), "methods": sorted(e["methods"])} for _, e in sorted(merged.items())]


def _issue(issue_id, label, code, runtime, base, ambiguous=False, candidates=(), conflict_with=()):
    members = code + runtime
    lead = code[0] if code else runtime[0]
    params = {(p["name"], p["location"]): p for f in members for p in f["params"]}
    issue = {
        "issue_id": issue_id,
        "label": label,
        "cwe": lead["cwe"],
        "cwe_family": lead["cwe_family"],
        "title": lead["title"],
        "severity": max((f["severity"] for f in members), key=SEVERITY_ORDER.index),
        "confidence": max((f["confidence"] for f in members), key=CONFIDENCE_ORDER.index),
        # In a hand-checked sample, low-confidence code findings were never real, so on their
        # own they're kept for the record but not reported.
        "reportable": not (label == "Code only" and all(f["confidence"] == "low" for f in code)),
        "stored": any(((f.get("code") or {}).get("stored_flow")) for f in code),
        "ambiguous": ambiguous,
        "candidates": sorted(candidates),
        "routes": _merged_routes(members, base),
        "params": [dict(params[k]) for k in sorted(params)],
        "sast_ids": [f["id"] for f in code],
        "dast_ids": [f["id"] for f in runtime],
        "runtime_verification": evidence.assess(runtime),
        "evidence": {"code": code, "runtime": runtime},
    }
    if conflict_with:
        issue["conflict"] = True
        issue["conflict_with"] = sorted(conflict_with)
    return issue


def _base_path(explicit, dast_doc) -> str:
    if explicit is not None:
        return "/" + explicit.strip("/") if explicit.strip("/") else ""
    return urlparse(dast_doc.get("target", "")).path.rstrip("/")


_INCLUDE_GUARD = re.compile(r"^(.+) == '([^']*)'$")


def _resolve_by_fixed_context(strong: set, code_groups: list, fixed_context: dict) -> set:
    """Several candidates can be mutually exclusive branches of the same `include $var` (e.g. DVWA's
    difficulty level picks low.php / medium.php / high.php): SAST records that as one condition per
    branch, `"{var} == '{file}'"`. When the scan's own fixed post-login state (set once, then
    denylisted from changing again) says which value was active the whole run, that rules out every
    branch but the one that was actually live -- real evidence, not a guess. Candidates can still
    share that one branch without being the same bug (DVWA's low.php itself builds two separately
    chosen queries, one per database driver): narrowing to them is still progress even when it can't
    settle the two apart, so this returns the narrowed set rather than insisting on exactly one.
    Returns `strong` unchanged when the candidates aren't that shape or don't share a guard variable."""
    if not fixed_context or len(strong) < 2:
        return strong
    per_group = {}
    for index in strong:
        guards = set()
        for finding in code_groups[index]:
            for condition in finding["code"].get("conditions") or []:
                m = _INCLUDE_GUARD.match(condition)
                if m:
                    guards.add(m.groups())
        if not guards:
            return strong
        per_group[index] = guards
    variables = {var for guards in per_group.values() for var, _ in guards}
    if len(variables) != 1:
        return strong
    values = {str(v) for v in fixed_context.values()}
    narrowed = {index for index, guards in per_group.items()
                if any(literal in values or literal.rsplit(".", 1)[0] in values for _, literal in guards)}
    return narrowed or strong


def correlate(sast_doc: dict, dast_doc: dict, base_path: str | None = None, sources: dict | None = None) -> dict:
    base = _base_path(base_path, dast_doc)
    open_code = [f for f in sast_doc["findings"] if f["status"] == "open"]
    suppressed = sorted((f for f in sast_doc["findings"] if f["status"] == "suppressed"), key=lambda f: f["id"])
    code_groups = _code_groups(open_code)
    group_of = {f["id"]: i for i, g in enumerate(code_groups) for f in g}
    code_ids = [_hash("issue", ["code", *(f["id"] for f in g)]) for g in code_groups]
    runtime_groups, app_wide = _runtime_groups(dast_doc["findings"], base)
    fixed_context = dast_doc.get("stats", {}).get("coverage", {}).get("fixed_runtime_context") or {}

    linked = defaultdict(list)          # code group index -> runtime group keys
    link_records, conflicts, runtime_only = [], [], []
    for key, members in runtime_groups.items():
        path = key[1]
        strong, weak, bases = set(), set(), []
        for d in members:
            for s in open_code:
                found = _match(d, s, path, base)
                if found is None:
                    continue
                strength, basis = found
                (strong if strength == "strong" else weak).add(group_of[s["id"]])
                if strength == "strong":
                    bases.append((MATCH_KINDS.index(basis["kind"]), s["id"], d["id"], basis))
        if len(strong) > 1:
            narrowed = _resolve_by_fixed_context(strong, code_groups, fixed_context)
            if narrowed != strong:
                strong = narrowed
                bases = [b for b in bases if group_of[b[1]] in strong]
        if len(strong) == 1:
            index = next(iter(strong))
            linked[index].append(key)
            basis = min(bases, key=lambda b: b[:3])[3]
            sast_ids = [f["id"] for f in code_groups[index]]
            dast_ids = [f["id"] for f in members]
            link_records.append({
                "link_id": _hash("link", [*sast_ids, "", *dast_ids]),
                "issue_id": code_ids[index],
                "sast_ids": sast_ids,
                "dast_ids": dast_ids,
                "strength": "strong",
                "match_basis": {"cwe_family": key[0], "runtime_route": path, **basis},
            })
            continue
        if not strong:
            safe = [s for s in suppressed if any(_match(d, s, path, base) for d in members)]
            if safe:
                # The runtime says exploitable, the code says protected: neither side decides. The
                # record keeps both sides' full evidence. A runtime finding whose evidence shows the
                # weakness itself is also ranked as a Runtime only issue, flagged as a conflict.
                reasons = sorted({s["code"]["suppression_reason"] for s in safe})
                verification = evidence.assess(members)
                record = {"dast_ids": [f["id"] for f in members], "sast_ids": [s["id"] for s in safe],
                          "reason": "The code was marked safe (" + "; ".join(reasons) + "), but a runtime test reported it",
                          "runtime_verification": verification,
                          "evidence": {"code": safe, "runtime": members}}
                if verification["level"] == "validated":
                    issue = _issue(_hash("issue", ["runtime", *key]), "Runtime only", [], members, base,
                                   conflict_with=[s["id"] for s in safe])
                    runtime_only.append(issue)
                    record["issue_id"] = issue["issue_id"]
                conflicts.append(record)
                continue
        candidates = [code_ids[i] for i in (strong or weak)]
        issue_id = _hash("issue", ["runtime", *key])
        runtime_only.append(_issue(issue_id, "Runtime only", [], members, base, ambiguous=len(strong) > 1, candidates=candidates))

    issues = runtime_only
    for i, group in enumerate(code_groups):
        runtime = [f for key in linked.get(i, []) for f in runtime_groups[key]]
        issues.append(_issue(code_ids[i], "Confirmed" if runtime else "Code only", group, sorted(runtime, key=lambda f: f["id"]), base))
    for f in app_wide:
        issues.append(_issue(_hash("issue", ["runtime", f["id"]]), "Runtime only", [], [f], base))
    issues = rank(issues)

    diagnostics = []
    code_paths = {p for f in open_code for r in f["routes"] for v in _route_views(r, base) for p in [v["path"], *v.get("aliases", [])]}
    runtime_paths = {key[1] for key in runtime_groups}
    if code_paths and runtime_paths and not any(_route_kind({"path": c, "aliases": []}, r) for c in code_paths for r in runtime_paths):
        diagnostics.append("No runtime route matches any code route. The reports may be for different deployments, "
                           "or the app may be served under a base path (--base-path).")

    coverage = (dast_doc.get("stats") or {}).get("coverage") or {}
    reachable = coverage.get("points_found", 0) - coverage.get("points_dropped_by_scope", 0)
    if coverage and (coverage.get("deadline_reached") or coverage.get("points_tested", 0) < reachable):
        diagnostics.append(f"The runtime scan tested {coverage.get('points_tested', 0)} of {reachable} reachable inputs"
                           + (" and ran out of time" if coverage.get("deadline_reached") else "")
                           + ". A Code only issue means no runtime proof was found, not that it was tested and found safe.")

    labels = Counter(i["label"] for i in issues)
    return {
        "schema_version": SCHEMA_VERSION,
        "inputs": {
            "sast": {"path": (sources or {}).get("sast", ""), "target": sast_doc.get("target", "")},
            "dast": {"path": (sources or {}).get("dast", ""), "target": dast_doc.get("target", "")},
        },
        "base_path": base,
        "issues": issues,
        "links": sorted(link_records, key=lambda x: x["link_id"]),
        "conflicts": sorted(conflicts, key=lambda x: x["dast_ids"]),
        "suppressed": [{"sast_id": f["id"], "cwe": f["cwe"], "file": f["code"]["file"], "line": f["code"]["line"],
                        "reason": f["code"]["suppression_reason"]} for f in suppressed],
        "diagnostics": diagnostics,
        "stats": {
            "issues": len(issues),
            "reportable": sum(1 for i in issues if i["reportable"]),
            "confirmed": labels["Confirmed"],
            "code_only": labels["Code only"],
            "runtime_only": labels["Runtime only"],
            "links": len(link_records),
            "ambiguous": sum(1 for i in issues if i["ambiguous"]),
            "conflicts": len(conflicts),
            "conflict_issues": sum(1 for i in issues if i.get("conflict")),
            "suppressed": len(suppressed),
            "runtime_coverage": coverage,
        },
    }
