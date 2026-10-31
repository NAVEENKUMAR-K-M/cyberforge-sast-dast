"""Helpers the Flask and FastAPI route readers share."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from ..project import Project, PyFile, dotted

FLASK_LIKE_MODULES = {"flask", "quart", "flask_restx", "flask_restful", "flask_smorest", "flask_openapi3", "flask_apispec"}
FASTAPI_LIKE_MODULES = {"fastapi", "starlette"}
# Types that cannot carry an injection payload once the framework has parsed them.
SAFE_TYPES = {"int", "float", "bool", "UUID", "Decimal", "date", "datetime", "time", "timedelta", "Literal", "conint", "confloat",
              "PositiveInt", "NegativeInt", "NonNegativeInt", "PositiveFloat"}


@dataclass
class Seed:
    """What a handler parameter holds at the start of the request."""
    name: str                  # the name the client uses (a header is dashed)
    location: str
    numeric: bool = False      # parsed as a number, so injection payloads are rejected before the handler runs
    kind: str = "value"        # value | model | request
    fields: dict = field(default_factory=dict)
    required: bool = True


class Consts:
    """String constants defined at the top of modules, for prefixes written as `API = "/api"`."""

    def __init__(self, project: Project):
        self.project = project
        self._cache: dict[str, dict] = {}

    def module(self, sf: PyFile) -> dict:
        got = self._cache.get(sf.rel)
        if got is not None:
            return got
        self._cache[sf.rel] = values = {}
        for _ in range(2):
            for stmt in sf.tree.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    text = self.text(stmt.value, sf)
                    if text is not None:
                        values[stmt.targets[0].id] = text
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                    text = self.text(stmt.value, sf)
                    if text is not None:
                        values[stmt.target.id] = text
        return values

    def text(self, node, sf: PyFile) -> str | None:
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.JoinedStr):
            out = []
            for part in node.values:
                piece = self.text(part.value if isinstance(part, ast.FormattedValue) else part, sf)
                if piece is None:
                    return None
                out.append(piece)
            return "".join(out)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.text(node.left, sf), self.text(node.right, sf)
            return left + right if left is not None and right is not None else None
        if isinstance(node, ast.Name):
            local = self._cache.get(sf.rel, {})
            if node.id in local:
                return local[node.id]
            target = self.project.resolve_dotted(sf, node.id)
            if target and target[0] == "var" and target[1] is not sf:
                return self.module(target[1]).get(target[2])
            return None
        if isinstance(node, ast.Attribute):
            name = dotted(node)
            target = self.project.resolve_dotted(sf, name) if name else None
            if target and target[0] == "var":
                return self.module(target[1]).get(target[2])
        return None

    def strings(self, node, sf: PyFile) -> list | None:
        """A list or tuple of string constants, such as methods=["GET", "POST"]."""
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            out = [self.text(e, sf) for e in node.elts]
            return None if any(item is None for item in out) else out
        return None


def keyword(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def arg_or_keyword(call: ast.Call, index: int, name: str):
    if len(call.args) > index and not isinstance(call.args[index], ast.Starred):
        return call.args[index]
    return keyword(call, name)


def join_url(*parts: str) -> str:
    """Joins URL pieces with one slash between them. A trailing slash on the last piece is kept."""
    out = ""
    for part in parts:
        if not part:
            continue
        out = out.rstrip("/") + "/" + part.lstrip("/") if out else "/" + part.lstrip("/")
    return re.sub(r"/{2,}", "/", out) or "/"


_FLASK_RULE = re.compile(r"<(?:(?P<conv>[A-Za-z_]\w*)(?:\((?P<args>[^)]*)\))?:)?(?P<name>[A-Za-z_]\w*)>")
NUMERIC_CONVERTERS = {"int", "float", "uuid"}


def flask_template(rule: str):
    """`/orders/<int:order_id>` -> ('/orders/{order_id}', {'order_id': True}) where True marks a numeric converter."""
    typed: dict[str, bool] = {}

    def replace(match):
        typed[match.group("name")] = (match.group("conv") or "") in NUMERIC_CONVERTERS
        return "{" + match.group("name") + "}"

    return _FLASK_RULE.sub(replace, rule), typed


_FASTAPI_PARAM = re.compile(r"\{([A-Za-z_]\w*)(?::[^}]*)?\}")


def fastapi_template(path: str):
    names = []

    def replace(match):
        names.append(match.group(1))
        return "{" + match.group(1) + "}"

    return _FASTAPI_PARAM.sub(replace, path), names


def imports_framework(sf: PyFile, modules: set) -> bool:
    roots = {value.split(".")[0] for value in sf.imports.values()}
    return bool(roots & modules)
