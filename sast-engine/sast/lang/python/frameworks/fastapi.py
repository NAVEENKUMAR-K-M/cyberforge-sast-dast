"""FastAPI: where each handler parameter comes from, read off the signature."""
from __future__ import annotations

import ast

from ..project import FuncDef, Project, dotted
from .common import SAFE_TYPES, Seed

MARKER_LOCATIONS = {"Query": "query", "Header": "header", "Cookie": "cookie", "Form": "body", "File": "file",
                    "Body": "json", "Path": "path"}
DEPENDS = {"Depends", "Security"}
MARKER_NAMES = set(MARKER_LOCATIONS) | DEPENDS
NOT_INPUT = {"Response", "BackgroundTasks", "HTTPConnection", "Session", "AsyncSession", "Connection", "SecurityScopes",
             "WebSocket", "Engine"}
MODEL_BASES = {"BaseModel", "SQLModel", "BaseSettings"}
ENUM_BASES = {"Enum", "IntEnum", "StrEnum", "IntFlag", "Flag"}


def bind(project: Project, fd: FuncDef, path_names, depth=0):
    """Returns ({python parameter: Seed}, [Seed for inputs a dependency reads])."""
    seeds: dict[str, Seed] = {}
    extra: list[Seed] = []
    args = fd.node.args
    positional = [*args.posonlyargs, *args.args]
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    pairs = list(zip(positional, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))
    for arg, default in pairs:
        if arg.arg in ("self", "cls"):
            continue
        inner, markers = _split_annotation(arg.annotation)
        if default is not None and isinstance(default, ast.Call):
            markers.append(default)
        marker = next((m for m in markers if isinstance(m, ast.Call) and (dotted(m.func) or "").split(".")[-1] in MARKER_NAMES), None)
        marker_name = (dotted(marker.func) or "").split(".")[-1] if marker is not None else None
        if marker_name in DEPENDS:
            if depth < 3 and marker.args:
                target = _depends_target(project, fd, marker.args[0])
                if target is not None:
                    nested, more = bind(project, target, path_names, depth + 1)
                    extra.extend(_flatten(nested.values()))
                    extra.extend(more)
            continue
        seed = _seed_for(project, fd, arg, inner, default, marker, marker_name, path_names)
        if seed is not None:
            seeds[arg.arg] = seed
    return seeds, extra


def _split_annotation(ann):
    """Annotated[T, Query(...)] -> (T, [Query(...)]). Other annotations come back unchanged."""
    if ann is None:
        return None, []
    if isinstance(ann, ast.Subscript) and (dotted(ann.value) or "").split(".")[-1] == "Annotated":
        elts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
        return elts[0], list(elts[1:])
    return ann, []


def _depends_target(project, fd, node):
    name = dotted(node)
    if not name:
        return None
    target = project.resolve_dotted(fd.file, name)
    return target[1] if target and target[0] == "func" else None


def _unwrap(ann):
    """Strips Optional, `| None` and list-like wrappers: returns (inner annotation, is a list)."""
    is_list = False
    for _ in range(4):
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            parts = [p for p in (ann.left, ann.right) if not (isinstance(p, ast.Constant) and p.value is None)]
            ann = parts[0] if parts else ann.left
            continue
        if isinstance(ann, ast.Subscript):
            outer = (dotted(ann.value) or "").split(".")[-1]
            elts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
            if outer in ("Optional", "Union"):
                parts = [p for p in elts if not (isinstance(p, ast.Constant) and p.value is None)]
                ann = parts[0] if parts else ann
                continue
            if outer in ("list", "List", "Sequence", "set", "Set", "tuple", "Tuple", "Iterable", "FrozenSet"):
                is_list = True
                ann = elts[0]
                continue
        break
    return ann, is_list


def _seed_for(project, fd, arg, ann, default, marker, marker_name, path_names):
    ann, _ = _unwrap(ann) if ann is not None else (None, False)
    type_name = (dotted(ann.value if isinstance(ann, ast.Subscript) else ann) or "").split(".")[-1] if ann is not None else ""
    if type_name == "Request":
        return Seed("", "any", kind="request")
    if type_name in NOT_INPUT:
        return None
    info = project.lookup_class(fd.file, dotted(ann)) if ann is not None and dotted(ann) else None
    is_model = info is not None and (project.class_has_base(info, MODEL_BASES) or _is_dataclass(info))
    is_enum = info is not None and project.class_has_base(info, ENUM_BASES)
    location = MARKER_LOCATIONS.get(marker_name or "")
    if location is None:
        if arg.arg in path_names:
            location = "path"
        elif is_model:
            location = "json"
        elif type_name in ("dict", "Dict", "Any", "Mapping"):
            location = "json"
        elif type_name in ("UploadFile", "File"):
            location = "file"
        else:
            location = "query"
    name = _alias(marker) or (arg.arg.replace("_", "-") if location == "header" else arg.arg)
    required = _required(default, marker)
    if is_model and location == "json":
        return Seed(name, "json", kind="model", fields=_model_fields(project, info, 0), required=required)
    numeric = type_name in SAFE_TYPES or is_enum or type_name == "Literal"
    return Seed(name, location, numeric=numeric, required=required)


def _is_dataclass(info) -> bool:
    return any((dotted(d.func if isinstance(d, ast.Call) else d) or "").split(".")[-1] == "dataclass" for d in info.node.decorator_list)


def _alias(marker):
    if isinstance(marker, ast.Call):
        for kw in marker.keywords:
            if kw.arg == "alias" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return None


def _required(default, marker) -> bool:
    if marker is not None:
        first = marker.args[0] if marker.args else next((k.value for k in marker.keywords if k.arg == "default"), None)
        return isinstance(first, ast.Constant) and first.value is Ellipsis
    return default is None


def _model_fields(project, info, depth) -> dict:
    fields: dict[str, Seed] = {}
    if depth > 3:
        return fields
    for base in info.bases:
        target = project.resolve_dotted(info.file, base) if base else None
        if target and target[0] == "class":
            fields.update(_model_fields(project, target[1], depth + 1))
    for stmt in info.node.body:
        if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
            continue
        ann, _ = _unwrap(stmt.annotation)
        type_name = (dotted(ann.value if isinstance(ann, ast.Subscript) else ann) or "").split(".")[-1]
        if type_name == "ClassVar":
            continue
        value = stmt.value
        required = value is None or (isinstance(value, ast.Constant) and value.value is Ellipsis)
        name = stmt.target.id
        if isinstance(value, ast.Call) and (dotted(value.func) or "").split(".")[-1] == "Field":
            first = value.args[0] if value.args else next((k.value for k in value.keywords if k.arg == "default"), None)
            required = isinstance(first, ast.Constant) and first.value is Ellipsis
            name = _alias(value) or name
        nested = project.lookup_class(info.file, dotted(ann)) if dotted(ann) else None
        if nested is not None and project.class_has_base(nested, MODEL_BASES):
            fields[stmt.target.id] = Seed(name, "json", kind="model", fields=_model_fields(project, nested, depth + 1), required=required)
        else:
            enum = nested is not None and project.class_has_base(nested, ENUM_BASES)
            fields[stmt.target.id] = Seed(name, "json", numeric=type_name in SAFE_TYPES or enum, required=required)
    return fields


def _flatten(seeds):
    """The leaf inputs of a set of seeds: model fields stand in for the model."""
    for seed in seeds:
        if seed.kind == "model":
            yield from _flatten(seed.fields.values())
        elif seed.kind == "value":
            yield seed
