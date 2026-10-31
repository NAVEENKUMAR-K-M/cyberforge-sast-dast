"""Parses an OpenAPI/Swagger spec fetched by the crawler into route entries
compatible with route_map_loader's normalized shape.

FastAPI, Django REST framework and most generators write every body and many parameters as `$ref`s into
`components`, so those are followed. A request body's other required fields travel with the one being
tested (`fields`), with a value of the right type, because a JSON body missing one is rejected with a 422
before it reaches the code under test.
"""
from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

import yaml

logger = logging.getLogger("dast.openapi_loader")

MAX_REF_DEPTH = 8
MAX_FIELDS = 30
_IN_TO_LOCATION = {"query": "query", "path": "path", "header": "header", "cookie": "cookie", "formData": "body"}
# Values a client cannot slip an injection payload into: the framework parses them before the app sees them.
_VALIDATED_FORMATS = {"uuid", "date", "date-time", "time", "ipv4", "ipv6"}


async def load_from_url(rm, spec_url: str) -> list[dict]:
    resp = await rm.get(spec_url)
    if resp is None:
        return []
    try:
        return parse_spec(_decode(resp))
    except (ValueError, yaml.YAMLError) as exc:
        logger.warning("Failed to load OpenAPI spec %s: %s", spec_url, exc)
        return []


def _decode(resp) -> dict:
    try:
        data = resp.json()
    except ValueError:
        data = yaml.safe_load(resp.text)
    if not isinstance(data, dict):
        raise ValueError("not an object")
    return data


def parse_spec(spec: dict) -> list[dict]:
    """Reads OpenAPI 3 and Swagger 2 into route entries, one per path and method."""
    routes: list[dict] = []
    servers = spec.get("servers") or []
    # The path prefix only: a spec's server host may not be the host being tested.
    base_path = (urlparse(servers[0].get("url", "")).path if servers and isinstance(servers[0], dict)
                 else spec.get("basePath", "") or "").rstrip("/")
    resolver = _Resolver(spec)

    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        shared = methods.get("parameters", [])
        for method, op in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE") or not isinstance(op, dict):
                continue
            params: list[dict] = []
            fields: list[dict] = []
            for raw in [*shared, *op.get("parameters", [])]:
                p = resolver.resolve(raw)
                if p.get("in") == "body":
                    _body_params(resolver, p.get("schema", {}), "json", params, fields)
                elif p.get("name"):
                    schema = resolver.resolve(p.get("schema") or {})
                    params.append({"name": p["name"], "location": _IN_TO_LOCATION.get(p.get("in"), "query"),
                                   "type": _kind(schema, p)})
                    if p.get("required") and p.get("in") in ("query", "path", "header", "cookie"):
                        fields.append({"name": p["name"], "value": _sample(schema), "location": _IN_TO_LOCATION.get(p["in"], "query")})
            body = resolver.resolve(op.get("requestBody") or {})
            content = body.get("content", {}) if isinstance(body, dict) else {}
            for media, location in (("application/json", "json"), ("application/x-www-form-urlencoded", "body"),
                                    ("multipart/form-data", "body")):
                if media in content:
                    _body_params(resolver, content[media].get("schema", {}), location, params, fields)
                    break
            routes.append({"method": method.upper(), "path": base_path + path, "params": params, "fields": fields})
    return routes


def _body_params(resolver, schema, location: str, params: list, fields: list) -> None:
    """The top-level fields of a body. Each can be tested; the required ones travel with the others."""
    props, required = resolver.properties(schema)
    for name, prop in list(props.items())[:MAX_FIELDS]:
        prop = resolver.resolve(prop)
        kind = _kind(prop, {})
        if prop.get("type") in ("object", "array") and not prop.get("enum"):
            continue  # a nested value would need a nested body, which a flat field can't express
        if prop.get("readOnly"):
            continue
        params.append({"name": name, "location": location, "type": kind})
        if name in required:
            fields.append({"name": name, "value": _sample(prop), "location": "body"})


def _kind(schema: dict, param: dict) -> str | None:
    """What the framework guarantees about a value, in the words route_map_loader and the probes use."""
    if schema.get("enum"):
        return "enum"
    if schema.get("format") in _VALIDATED_FORMATS:
        return "uuid" if schema.get("format") == "uuid" else "validated"
    return schema.get("type") or param.get("type")


def _sample(schema: dict):
    """A value of the right type for a field that has to be present but isn't being tested."""
    for key in ("example", "default"):
        if key in schema and schema[key] is not None:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "integer":
        return max(1, int(schema.get("minimum", 1)))
    if kind == "number":
        return max(1.0, float(schema.get("minimum", 1.0)))
    if kind == "boolean":
        return True
    if kind == "array":
        return []
    if kind == "object":
        return {}
    fmt = schema.get("format")
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    if fmt == "date":
        return "2024-01-01"
    if fmt == "date-time":
        return "2024-01-01T00:00:00Z"
    if fmt == "email":
        return "user@example.com"
    return "1"


class _Resolver:
    """Follows `$ref`s and merges `allOf`, without looping on a schema that refers to itself."""

    def __init__(self, spec: dict):
        self.spec = spec

    def resolve(self, node, depth: int = 0) -> dict:
        if not isinstance(node, dict):
            return {}
        seen = 0
        while "$ref" in node and seen < MAX_REF_DEPTH:
            target = self._lookup(node["$ref"])
            if target is None:
                return {k: v for k, v in node.items() if k != "$ref"}
            node = target
            seen += 1
        return node

    def _lookup(self, ref: str):
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return None  # a reference to another file isn't followed
        node = self.spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node if isinstance(node, dict) else None

    def properties(self, schema, depth: int = 0) -> tuple[dict, set]:
        """(properties, required names) of an object schema, with allOf parts merged and the first
        branch of a oneOf or anyOf taken."""
        schema = self.resolve(schema)
        if depth > MAX_REF_DEPTH or not schema:
            return {}, set()
        props: dict = {}
        required = set(schema.get("required") or [])
        for part in schema.get("allOf") or []:
            inner_props, inner_required = self.properties(part, depth + 1)
            props.update(inner_props)
            required |= inner_required
        for key in ("oneOf", "anyOf"):
            options = schema.get(key) or []
            if options and not props and not schema.get("properties"):
                inner_props, inner_required = self.properties(options[0], depth + 1)
                props.update(inner_props)
                required |= inner_required
        props.update(schema.get("properties") or {})
        return props, required
