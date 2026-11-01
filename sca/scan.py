"""Runs the stages in order and assembles sca.json."""
from __future__ import annotations

import json
import os

from sca import advisories, assess, callgraph, inventory as inv, supply
from sca.phpindex import Index
from sca.symbols import function_map

CALL_KINDS = ["namespaced and global functions (use function included)", "static calls, self::, parent::, static::",
              "new and the constructor it runs", "$this, with the object's class when it was created with new",
              "receivers typed by a parameter, property or return type, or assigned from new", "inherited and trait methods",
              "literal includes and vendor/autoload.php", "callables written as literal strings or arrays"]
ASSUMPTIONS = ["a package calls only packages it declares as dependencies in composer.lock",
               "library source is analysed only for packages that can reach an affected package",
               "a call that can't be resolved, or that resolves to several targets, never supports Reachable"]


def run(app_dir: str, fetcher, routes_path: str | None = None, deps_dir: str | None = None, lock_path: str | None = None,
        max_states: int = 200_000, timeout: float = 60.0) -> tuple[dict, dict]:
    app_dir = os.path.abspath(app_dir)
    deps_dir = os.path.abspath(deps_dir) if deps_dir else os.path.join(app_dir, "vendor")
    diagnostics = []
    inventory = inv.load(app_dir, lock_path)
    sources = inv.locate_sources(inventory, deps_dir)
    matches = advisories.lookup(inventory, fetcher)
    if matches["status"] != "ok":
        diagnostics.append(f"advisory lookup unavailable ({matches['error']}): which dependencies are affected is unknown")

    affected = sorted(p for p, found in matches["matches"].items() if any(not a["malicious"] for a in found))
    analysed = sorted({p for name in affected for p in ({name} | inv.ancestors(inventory, name)) if p != inv.ROOT})
    index = Index(app_dir)
    index.add_tree(app_dir, inv.ROOT, "")
    for prefix in _autoload_prefixes(inventory["root"]["autoload"]):
        index.prefixes.append((prefix.lower(), inv.ROOT))
    autoload_files = []
    for name in analysed:
        source = sources[name]
        if not source["present"]:
            continue
        rules = inventory["packages"][name]["autoload"]
        rel_base = os.path.relpath(source["path"], app_dir).replace(os.sep, "/")
        if rel_base.startswith(".."):
            rel_base = f"[{name}]"
        include = _autoload_paths(rules)
        index.add_tree(source["path"], name, rel_base, include=include if include else None,
                       exclude_patterns=rules.get("exclude-from-classmap") or [])
        for prefix in _autoload_prefixes(rules):
            index.prefixes.append((prefix.lower(), name))
        for path in rules.get("files") or []:
            info = index.files.get(f"{rel_base}/{path}".replace("/./", "/"))
            if info is not None:
                autoload_files.append(info["top"])

    roots, roots_description = _roots(index, app_dir, routes_path, diagnostics)
    reach = callgraph.explore(index, roots, autoload_files, max_states=max_states, timeout=timeout)
    ctx = {"inventory": inventory, "sources": sources, "index": index, "reach": reach,
           "used": assess.used_packages(index, reach), "roots_description": roots_description,
           "call_kinds": CALL_KINDS, "global_limits": []}
    rows = []
    for name in affected:
        for advisory in matches["matches"][name]:
            if advisory["malicious"]:
                continue
            rows.append(assess.assess(name, advisory, function_map(advisory, name, index, fetcher), ctx))
    rows = assess.order(rows)
    findings = supply.check(inventory, matches["matches"], fetcher)

    stats = {status: sum(1 for r in rows if r["status"] == status) for status in assess.STATUS_ORDER}
    stats["supply_chain"] = len(findings)
    no_match = matches["no_match"]
    report = {
        "schema_version": "1.0", "tool": "cyberforge-sca", "app": app_dir, "lockfile": inventory["lockfile"],
        "dependency_source": deps_dir,
        "packages": [_package_view(inventory, sources, matches, name) for name in sorted(inventory["packages"])],
        "advisory_lookup": {"source": matches["source"], "status": matches["status"], "error": matches["error"],
                            "fetched_at": matches["fetched_at"], "not_checked": matches["not_checked"],
                            "no_known_advisories": {"packages": no_match,
                                                    "note": f"no known advisories returned by OSV at {matches['fetched_at']}"
                                                    if no_match else None}},
        "dependencies": rows,
        "supply_chain": findings,
        "analysis": {"roots": roots_description, "packages_analysed": analysed, "files_indexed": len(index.files),
                     "functions_reached_exact": len({s[0] for s in reach.exact}),
                     "functions_reached_any": len({s[0] for s in reach.any}),
                     "unresolved_sites_reached": len(reach.unresolved), "complete": reach.complete,
                     "limit": reach.limit, "call_kinds": CALL_KINDS, "assumptions": ASSUMPTIONS},
        "diagnostics": diagnostics,
        "stats": stats,
    }
    return report, inv.cyclonedx(inventory)


def _autoload_paths(rules: dict) -> list:
    paths = []
    for kind in ("psr-4", "psr-0"):
        for value in (rules.get(kind) or {}).values():
            paths.extend(value if isinstance(value, list) else [value])
    paths.extend(rules.get("classmap") or [])
    paths.extend(rules.get("files") or [])
    return [p.strip("/").removeprefix("./") for p in paths]


def _autoload_prefixes(rules: dict) -> list:
    return [prefix for kind in ("psr-4", "psr-0") for prefix in (rules.get(kind) or {}) if prefix]


def _roots(index, app_dir, routes_path, diagnostics):
    if not routes_path:
        roots = [info["top"] for rel, info in sorted(index.files.items()) if info["package"] == inv.ROOT and info["top"].body]
        return roots, f"every app file with top-level code ({len(roots)}; no route map given)"
    with open(routes_path, encoding="utf-8") as handle:
        routes = json.load(handle)
    base = routes.get("source_root") or app_dir
    roots, seen = [], set()
    for route in routes.get("routes") or []:
        handler = route.get("handler") or {}
        if not handler.get("file"):
            continue
        rel = os.path.relpath(os.path.join(base, handler["file"]), app_dir).replace(os.sep, "/")
        info = index.files.get(rel)
        if info is None:
            diagnostics.append(f"route {route.get('path')}: handler file {rel} isn't in the analysed source")
            continue
        function = handler.get("function") or "<top-level>"
        if function == "<top-level>":
            fn = info["top"]
        else:
            in_file = [f for f in index.funcs.values() if f.sf.rel == rel and f.kind in ("method", "function")]
            fn = next((f for f in in_file if f.line == handler.get("start_line")), None) or \
                next((f for f in in_file if f.name.lower() == function.split("::")[-1].split("@")[-1].lower()), None)
        if fn is None:
            diagnostics.append(f"route {route.get('path')}: handler {function} not found in {rel}")
            continue
        if fn.key not in seen:
            seen.add(fn.key)
            roots.append(fn)
    return roots, f"{len(roots)} route handlers from the route map ({os.path.basename(routes_path)})"


def _package_view(inventory, sources, matches, name):
    package = inventory["packages"][name]
    found = matches["matches"].get(name)
    if matches["status"] != "ok":
        advisory_status = "unknown: advisory lookup unavailable"
    elif name in matches["not_checked"]:
        advisory_status = f"not checked: {matches['not_checked'][name]}"
    elif found:
        advisory_status = ", ".join(a["id"] for a in found)
    else:
        advisory_status = f"no known advisories returned by OSV at {matches['fetched_at']}"
    return {"name": name, "version": package["version"], "dev": package["dev"],
            "direct": name in inventory["edges"].get(inv.ROOT, []), "path": inv.display_path(inventory, name),
            "requires": inventory["edges"].get(name, []), "bin": package["bin"],
            "source": {k: sources[name][k] for k in ("path", "identity", "integrity")}, "advisories": advisory_status}
