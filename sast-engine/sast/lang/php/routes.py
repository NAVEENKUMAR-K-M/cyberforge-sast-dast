"""The route map: which URL runs which code (FR-4)."""
from __future__ import annotations

import os
import posixpath
import re

from sast.core.model import Route

from .project import Project, parse_forms


class RouteMap:
    def __init__(self, project: Project, base_path: str = ""):
        self.p = project
        self.prefix = "/" + base_path.strip("/") if base_path.strip("/") else ""
        self.routes: dict[tuple, Route] = {}

    def get(self, path, selector=None, kind="file", handler=None, aliases=None) -> Route:
        key = (path, selector)
        route = self.routes.get(key)
        if route is None:
            route = Route(path=path, selector=selector, kind=kind, aliases=list(aliases or []))
            self.routes[key] = route
            if handler:
                self._set_handler(route, handler)
        return route

    def _set_handler(self, route, rel):
        sf = self.p.files[rel]
        route.handler_file, route.start_line, route.end_line = rel, 1, max(len(sf.lines), 1)
        route.form_fields = parse_forms(sf.data.decode("utf-8", "replace"))

    def for_file(self, rel) -> Route | None:
        path = self.p.web_path(rel)
        if path is None:
            return None
        aliases = []
        if posixpath.basename(path) == "index.php":
            parent = posixpath.dirname(path)
            aliases.append(self.prefix + (parent.rstrip("/") + "/"))
        return self.get(self.prefix + path, None, "file", rel, aliases)

    def json_list(self):
        return [r.to_json() for r in sorted(self.routes.values(), key=lambda r: (r.path, r.selector or ""))]


# Files a framework runs while starting up. They declare routes; they are not pages (/web.php is not a URL).
FRAMEWORK_BOOT = re.compile(r"(^|/)(routes/\w+\.php|bootstrap/(app|providers)\.php|database/(migrations|seeders|factories)/)")


def find_entries(project: Project, edges: dict) -> list:
    """A file is an entry point if the web can run it and no other file includes it."""
    included = set()
    for source, targets in edges.items():
        included.update(t for t in targets if t != source)
    entries = []
    for rel, sf in project.files.items():
        if rel in included or not sf.has_top_level_code or sf.direct_guard or FRAMEWORK_BOOT.search(rel):
            continue
        if project.web_path(rel) is None or project.is_blocked(rel):
            continue
        entries.append(rel)
    return sorted(entries, key=lambda r: (r.count("/"), r))


_REWRITE = re.compile(r"^\s*RewriteRule\s+(\S+)\s+(\S+)", re.I | re.M)


def _pattern_to_template(pattern: str, names: dict) -> str | None:
    """Turns a rewrite pattern into a path template: `^orders/([0-9]+)$` becomes `orders/{id}`.
    Returns None for anything it can't read with confidence, such as a catch-all."""
    text = pattern.lstrip("^").rstrip("$")
    out, group, index = "", 0, 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            out += text[index + 1]
            index += 2
        elif char == "(":
            depth, end = 1, index + 1
            while end < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[end], 0)
                end += 1
            group += 1
            out += "{" + names.get(group, f"p{group}") + "}"
            index = end
        elif text[index:index + 2] == "/?":
            index += 2
        elif char.isalnum() or char in "/-_.":
            out += char
            index += 1
        else:
            return None
    return out if re.search(r"[A-Za-z0-9]", re.sub(r"\{[^}]*\}", "", out)) else None


def apply_rewrites(project: Project, routes: RouteMap) -> int:
    """Adds the public URLs from .htaccess rewrite rules as aliases, so a runtime finding on
    `/orders/7` can be matched to the code in `orders.php`. Returns how many rules were applied."""
    applied = 0
    for dirpath, dirnames, filenames in os.walk(project.root):
        dirnames[:] = sorted(d for d in dirnames if d not in project.exclude)
        if ".htaccess" not in filenames:
            continue
        try:
            with open(os.path.join(dirpath, ".htaccess"), errors="replace") as handle:
                rules = _REWRITE.findall(handle.read())
        except OSError:
            continue
        base = os.path.relpath(dirpath, project.root).replace(os.sep, "/")
        base = "" if base == "." else base
        for pattern, target in rules:
            applied += _apply_rule(pattern, target, base, project, routes)
    return applied


def _apply_rule(pattern, target, base, project, routes) -> int:
    file_part, _, query = target.partition("?")
    if target == "-" or "://" in target or "$" in file_part:
        return 0
    pairs = [pair.partition("=") for pair in query.split("&") if "=" in pair]
    names = {int(value[1:]): name for name, _, value in pairs if re.fullmatch(r"\$\d+", value)}
    template = _pattern_to_template(pattern, names)
    rel = posixpath.normpath(posixpath.join(base, file_part.lstrip("/")))
    if template is None or rel not in project.files:
        return 0
    web_path = project.web_path(posixpath.join(base, template)) if base or not project.web_root else None
    alias = routes.prefix + (web_path if web_path else "/" + template.lstrip("/"))
    fixed = [f"{name}={value}" for name, _, value in pairs if "$" not in value]
    path = project.web_path(rel)
    route = next((routes.routes[(routes.prefix + path, selector)] for selector in fixed
                  if path and (routes.prefix + path, selector) in routes.routes), None)
    route = route or routes.for_file(rel)
    if route is None:
        return 0
    if alias not in route.aliases:
        route.aliases.append(alias)
    return 1
