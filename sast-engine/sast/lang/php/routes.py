"""The route map: which URL runs which code (FR-4)."""
from __future__ import annotations

import posixpath

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


def find_entries(project: Project, edges: dict) -> list:
    """A file is an entry point if the web can run it and no other file includes it."""
    included = set()
    for source, targets in edges.items():
        included.update(t for t in targets if t != source)
    entries = []
    for rel, sf in project.files.items():
        if rel in included or not sf.has_top_level_code or sf.direct_guard:
            continue
        if project.web_path(rel) is None or project.is_blocked(rel):
            continue
        entries.append(rel)
    return sorted(entries, key=lambda r: (r.count("/"), r))
