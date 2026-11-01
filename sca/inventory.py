"""Stages 1 and 2: the dependency inventory from composer.lock, its paths and SBOM, and where each package's source is.

The lockfile says which package and version is installed and who requires it. It doesn't prove the files on disk are
that version, so identity (what the lock and Composer's install record say) and integrity (whether the files were
checked against a published checksum) are kept apart.
"""
from __future__ import annotations

import json
import os
import re
from collections import deque

PLATFORM = re.compile(r"^(php(-64bit|-ipv6|-zts|-debug)?|hhvm|ext-.+|lib-.+|composer(-plugin-api|-runtime-api)?)$", re.I)
ROOT = "<root>"


class InventoryError(ValueError):
    pass


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise InventoryError(f"can't read {path}: {exc}") from None


def _requires(entry: dict) -> list:
    return sorted(name.lower() for name in (entry.get("require") or {}) if not PLATFORM.match(name))


def load(app_dir: str, lock_path: str | None = None) -> dict:
    manifest_path = os.path.join(app_dir, "composer.json")
    lock_path = lock_path or os.path.join(app_dir, "composer.lock")
    manifest = _read_json(manifest_path) if os.path.isfile(manifest_path) else None
    lock = _read_json(lock_path) if os.path.isfile(lock_path) else None
    inventory = {"manifest": manifest_path if manifest is not None else None,
                 "lockfile": lock_path if lock is not None else None,
                 "root": {"name": (manifest or {}).get("name") or "root",
                          "require": _requires(manifest or {}),
                          "require_dev": sorted(n.lower() for n in ((manifest or {}).get("require-dev") or {}) if not PLATFORM.match(n)),
                          "autoload": (manifest or {}).get("autoload") or {},
                          "repositories": (manifest or {}).get("repositories") or []},
                 "manifest_data": manifest, "content_hash": (lock or {}).get("content-hash"),
                 "packages": {}, "edges": {}, "paths": {}}
    if lock is None:
        return inventory

    providers = {}
    entries = [(e, False) for e in lock.get("packages") or []] + [(e, True) for e in lock.get("packages-dev") or []]
    for entry, dev in entries:
        name = entry["name"].lower()
        source, dist = entry.get("source") or {}, entry.get("dist") or {}
        inventory["packages"][name] = {
            "name": name, "version": entry.get("version", ""), "dev": dev, "type": entry.get("type", "library"),
            "reference": source.get("reference") or dist.get("reference"), "source_type": source.get("type"),
            "source_url": source.get("url"), "dist_url": dist.get("url"), "dist_shasum": dist.get("shasum") or None,
            "requires": _requires(entry), "autoload": entry.get("autoload") or {}, "bin": list(entry.get("bin") or []),
        }
        for kind in ("replace", "provide"):
            for alias in entry.get(kind) or {}:
                providers.setdefault(alias.lower(), name)

    def resolve(name):
        return name if name in inventory["packages"] else providers.get(name)

    for name, package in inventory["packages"].items():
        inventory["edges"][name] = sorted({r for r in (resolve(n) for n in package["requires"]) if r and r != name})
    inventory["edges"][ROOT] = sorted({r for r in (resolve(n) for n in inventory["root"]["require"] + inventory["root"]["require_dev"]) if r})
    inventory["paths"] = _shortest_paths(inventory["edges"])
    return inventory


def _shortest_paths(edges: dict) -> dict:
    """One representative path per package: the shortest from the root, ties broken by name. Not every path."""
    paths = {ROOT: [ROOT]}
    queue = deque([ROOT])
    while queue:
        current = queue.popleft()
        for dep in edges.get(current, []):
            if dep not in paths:
                paths[dep] = paths[current] + [dep]
                queue.append(dep)
    return paths


def ancestors(inventory: dict, name: str) -> set:
    """Packages with a dependency path to `name` (the root included), so code that can see it."""
    reverse = {}
    for parent, deps in inventory["edges"].items():
        for dep in deps:
            reverse.setdefault(dep, set()).add(parent)
    seen, queue = set(), [name]
    while queue:
        for parent in reverse.get(queue.pop(), ()):
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)
    return seen


def locate_sources(inventory: dict, deps_dir: str) -> dict:
    """Where each package's files are, and what is known about them. Nothing is downloaded or run."""
    installed = {}
    record = os.path.join(deps_dir, "composer", "installed.json")
    if os.path.isfile(record):
        data = _read_json(record)
        for entry in data.get("packages", data) if isinstance(data, dict) else data:
            installed[entry["name"].lower()] = entry
    found = {}
    for name, package in inventory["packages"].items():
        entry = installed.get(name)
        if entry and entry.get("install-path"):
            path = os.path.normpath(os.path.join(deps_dir, "composer", entry["install-path"]))
        else:
            path = os.path.join(deps_dir, *name.split("/"))
        present = os.path.isdir(path)
        if entry is None:
            identity = "not recorded: no install record for this package"
        else:
            got_ref = (entry.get("source") or {}).get("reference") or (entry.get("dist") or {}).get("reference")
            if entry.get("version") == package["version"] and got_ref == package["reference"]:
                identity = "install record matches the lock's version and reference"
            else:
                identity = f"install record differs from the lock: {entry.get('version')} {got_ref}"
        found[name] = {"path": path if present else None, "present": present, "identity": identity,
                       "matches_lock": entry is not None and identity.startswith("install record matches"),
                       "integrity": "not verified: the files were not compared with a published checksum"}
    return found


def cyclonedx(inventory: dict) -> dict:
    """The inventory as a CycloneDX 1.5 SBOM, with the dependency graph. No timestamp, so reruns are identical."""
    def purl(name):
        return f"pkg:composer/{name}@{inventory['packages'][name]['version']}"

    components, dependencies = [], [{"ref": "root", "dependsOn": [purl(n) for n in inventory["edges"].get(ROOT, [])]}]
    for name in sorted(inventory["packages"]):
        package = inventory["packages"][name]
        group, _, short = name.partition("/")
        component = {"type": "library", "bom-ref": purl(name), "group": group, "name": short, "version": package["version"],
                     "purl": purl(name), "scope": "optional" if package["dev"] else "required",
                     "properties": [{"name": "cyberforge:path", "value": " > ".join(display_path(inventory, name))}]}
        if package["source_url"]:
            component["externalReferences"] = [{"type": "vcs", "url": package["source_url"]}]
        components.append(component)
        dependencies.append({"ref": purl(name), "dependsOn": [purl(d) for d in inventory["edges"].get(name, [])]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "bom-ref": "root", "name": inventory["root"]["name"]},
                         "tools": {"components": [{"type": "application", "name": "cyberforge-sca"}]}},
            "components": components, "dependencies": dependencies}


def display_path(inventory: dict, name: str) -> list:
    path = inventory["paths"].get(name)
    if path is None:
        return [inventory["root"]["name"], f"{name} (no path from the root)"]
    return [inventory["root"]["name"]] + path[1:]
