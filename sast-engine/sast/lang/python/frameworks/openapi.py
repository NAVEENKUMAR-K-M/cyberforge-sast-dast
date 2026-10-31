"""Routes declared in an OpenAPI document, as connexion and similar spec-first frameworks serve them.

The code has no @route decorators: the document says which URL and method run which function (`operationId:
api_views.users.login_user`), and which query, path, header and body values the function receives. So the
document is the route map.
"""
from __future__ import annotations

import os

try:  # PyYAML is a declared dependency; a JSON-only fallback keeps a missing install from breaking every scan
    import yaml
except ImportError:  # pragma: no cover
    yaml = None
import json

from .common import Seed

MAX_SPEC_BYTES = 3_000_000
METHODS = ("get", "post", "put", "patch", "delete")
LOCATIONS = {"query": "query", "path": "path", "header": "header", "cookie": "cookie", "formData": "body"}
NUMERIC_FORMATS = {"uuid", "date", "date-time", "ipv4", "ipv6"}


def load_specs(root: str, excludes) -> list:
    """(relative path, parsed document) for each OpenAPI/Swagger file in the project."""
    found = []
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in excludes)
        for name in sorted(names):
            if not name.lower().endswith((".yml", ".yaml", ".json")):
                continue
            full = os.path.join(folder, name)
            try:
                if os.path.getsize(full) > MAX_SPEC_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            if "paths" not in text or not ("openapi" in text[:4000] or "swagger" in text[:4000]):
                continue
            doc = _parse(text)
            if isinstance(doc, dict) and isinstance(doc.get("paths"), dict) and ("openapi" in doc or "swagger" in doc):
                found.append((os.path.relpath(full, root).replace(os.sep, "/"), doc))
    return found


def _parse(text: str):
    try:
        return json.loads(text)
    except ValueError:
        pass
    if yaml is None:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:  # a broken document is skipped, not fatal
        return None


class Spec:
    def __init__(self, doc: dict):
        self.doc = doc

    def resolve(self, node):
        seen = 0
        while isinstance(node, dict) and "$ref" in node and seen < 8:
            target = self._lookup(node["$ref"])
            if target is None:
                break
            node, seen = target, seen + 1
        return node if isinstance(node, dict) else {}

    def _lookup(self, ref):
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return None
        node = self.doc
        for part in ref[2:].split("/"):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def properties(self, schema, depth=0) -> dict:
        schema = self.resolve(schema)
        if depth > 6 or not schema:
            return {}
        props = {}
        for part in schema.get("allOf") or []:
            props.update(self.properties(part, depth + 1))
        props.update(schema.get("properties") or {})
        return props

    def base_path(self) -> str:
        servers = self.doc.get("servers") or []
        if servers and isinstance(servers[0], dict):
            from urllib.parse import urlparse
            return urlparse(servers[0].get("url", "")).path.rstrip("/")
        return (self.doc.get("basePath") or "").rstrip("/")

    def operations(self):
        """(path, METHOD, operation, parameters shared by the path)."""
        for path, item in sorted(self.doc["paths"].items()):
            if not isinstance(item, dict):
                continue
            shared = item.get("parameters") or []
            for method in METHODS:
                op = item.get(method)
                if isinstance(op, dict):
                    yield path, method.upper(), op, shared

    def seeds(self, op: dict, shared: list):
        """(all inputs as Seeds for the route, {handler parameter name: Seed})."""
        everything, by_var = [], {}
        for raw in [*shared, *(op.get("parameters") or [])]:
            p = self.resolve(raw)
            if p.get("in") == "body":
                body = self._body_seed(p.get("schema") or {}, p.get("required", True))
                everything.append(body)
                by_var[p.get("name") or "body"] = body
            elif p.get("name"):
                schema = self.resolve(p.get("schema") or {}) or p
                seed = Seed(p["name"], LOCATIONS.get(p.get("in"), "query"), numeric=_is_validated(schema), required=bool(p.get("required")))
                everything.append(seed)
                by_var[p["name"].replace("-", "_")] = seed
        request_body = self.resolve(op.get("requestBody") or {})
        for media, location in (("application/json", "json"), ("application/x-www-form-urlencoded", "body"), ("multipart/form-data", "body")):
            content = (request_body.get("content") or {}).get(media)
            if content:
                body = self._body_seed(content.get("schema") or {}, request_body.get("required", False), location)
                everything.append(body)
                by_var["body"] = body
                break
        return everything, by_var

    def _body_seed(self, schema: dict, required, location="json") -> Seed:
        props = self.properties(schema)
        if not props:
            return Seed("*", location, kind="value", required=bool(required))
        required_names = set(self.resolve(schema).get("required") or [])
        fields = {}
        for name, prop in props.items():
            prop = self.resolve(prop)
            if prop.get("type") in ("object", "array") and not prop.get("enum"):
                continue
            fields[name] = Seed(name, location, numeric=_is_validated(prop), required=name in required_names)
        return Seed("", location, kind="model", fields=fields, required=bool(required))


def _is_validated(schema: dict) -> bool:
    """Whether the framework parses the value as a number, date or one of a few choices before the code sees it."""
    return schema.get("type") in ("integer", "number", "boolean") or bool(schema.get("enum")) or schema.get("format") in NUMERIC_FORMATS
