"""Finds the URLs a Flask or FastAPI app serves, and which function answers each one.

Every URL is written as a template with `{name}` placeholders whatever the framework spells it as, so a
runtime finding on `/api/orders/5` and the code behind `/api/orders/<int:order_id>` meet at one path.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field

from sast.core.model import Param, Route

from .frameworks import django as django_mod
from .frameworks import fastapi as fastapi_mod
from .frameworks import openapi as openapi_mod
from .frameworks.common import (FASTAPI_LIKE_MODULES, FLASK_LIKE_MODULES, Consts, Seed, arg_or_keyword, fastapi_template,
                                flask_template, imports_framework, join_url, keyword)
from .project import HTTP_METHODS, ClassInfo, FuncDef, Project, PyFile, dotted

CONSTRUCTORS = {
    "Flask": "flask_app", "Quart": "flask_app", "Blueprint": "flask_bp", "FastAPI": "fastapi_app",
    "APIRouter": "fastapi_router", "Api": "flask_api", "Namespace": "flask_ns",
}
PREFIX_KEYWORD = {"flask_bp": "url_prefix", "fastapi_router": "prefix", "flask_api": "prefix", "flask_ns": "path"}
LINK_CALLS = {"register_blueprint": ("url_prefix", "override"), "include_router": ("prefix", "prepend"),
              "add_namespace": ("path", "override")}
VERB_DECORATORS = {"get", "post", "put", "delete", "patch", "head", "options"}


@dataclass
class Obj:
    kind: str
    prefix: str
    file: str
    name: str


@dataclass
class Link:
    parent: tuple | None
    child: tuple
    prefix: str | None
    mode: str


class HandlerRoute:
    """One function answering one URL, with the method(s) it answers."""
    __slots__ = ("fd", "view", "framework", "seeds", "html")

    def __init__(self, fd, view, framework, seeds, html):
        self.fd, self.view, self.framework, self.seeds, self.html = fd, view, framework, seeds, html


class GenericRoute:
    """A generic class-based view, analysed from its class attributes rather than from code."""
    __slots__ = ("g", "view")

    def __init__(self, g, view):
        self.g, self.view = g, view


@dataclass
class RouteMap:
    routes: dict = field(default_factory=dict)       # template -> merged Route
    handlers: list = field(default_factory=list)     # HandlerRoute
    generics: list = field(default_factory=list)     # GenericRoute

    def merge_params(self):
        """A URL's own entry lists everything any of its handlers reads. Handlers learn their parameters
        while the analysis runs, so this is called again after it."""
        for handler in [*self.handlers, *self.generics]:
            merged = self.routes[handler.view.path]
            for key, param in handler.view.params.items():
                merged.params.setdefault(key, param)
            for key, param in handler.view.required.items():
                merged.required.setdefault(key, param)

    def json_list(self) -> list:
        return [route.to_json() for _, route in sorted(self.routes.items())]


def extract(project: Project, base_path: str = "") -> RouteMap:
    return _Extractor(project, base_path).run()


class _Extractor:
    def __init__(self, project: Project, base_path: str):
        self.project, self.base_path = project, base_path.rstrip("/")
        self.consts = Consts(project)
        self.objects: dict[tuple, Obj] = {}
        self.links: dict[tuple, list] = {}
        self.out = RouteMap()
        self._prefix_cache: dict[tuple, str] = {}

    def run(self) -> RouteMap:
        for sf in self.project.files.values():
            self._find_objects(sf)
        for sf in self.project.files.values():
            self._find_links(sf)
        raw = []
        for sf in self.project.files.values():
            raw.extend(self._decorated(sf))
            raw.extend(self._calls(sf))
        for entry in sorted(raw, key=lambda e: (e["file"], e["line"], e["path"], e["fd"].label)):
            self._add(entry)
        self._spec_routes()
        self._django_routes()
        self.out.merge_params()
        return self.out

    # ---- apps, blueprints and routers ----------------------------------------------------------------------------

    def _find_objects(self, sf: PyFile):
        for node in ast.walk(sf.tree):
            target, value = _assignment(node)
            if target is None or not isinstance(value, ast.Call):
                continue
            ctor = (dotted(value.func) or "").split(".")[-1]
            kind = CONSTRUCTORS.get(ctor)
            if kind is None:
                continue
            if ctor in ("Api", "Namespace") and not imports_framework(sf, FLASK_LIKE_MODULES):
                continue
            prefix = ""
            wanted = PREFIX_KEYWORD.get(kind)
            if wanted:
                found = keyword(value, wanted)
                prefix = (self.consts.text(found, sf) or "") if found is not None else ""
            self.objects[(sf.rel, target)] = Obj(kind, prefix, sf.rel, target)

    def _key(self, sf: PyFile, node) -> tuple | None:
        name = dotted(node)
        if not name:
            return None
        if (sf.rel, name) in self.objects:
            return sf.rel, name
        target = self.project.resolve_dotted(sf, name)
        if target and target[0] == "var" and (target[1].rel, target[2]) in self.objects:
            return target[1].rel, target[2]
        return None

    def _find_links(self, sf: PyFile):
        for node in ast.walk(sf.tree):
            target, value = _assignment(node)
            if target is not None and isinstance(value, ast.Call) and (sf.rel, target) in self.objects:
                if self.objects[(sf.rel, target)].kind in ("flask_api",) and value.args:
                    parent = self._key(sf, value.args[0])
                    if parent is not None:
                        self.links.setdefault((sf.rel, target), []).append(Link(parent, (sf.rel, target), None, "prepend"))
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in LINK_CALLS and node.args):
                continue
            wanted, mode = LINK_CALLS[node.func.attr]
            child = self._key(sf, node.args[0])
            if child is None:
                continue
            prefix_node = keyword(node, wanted)
            prefix = self.consts.text(prefix_node, sf) if prefix_node is not None else None
            self.links.setdefault(child, []).append(Link(self._key(sf, node.func.value), child, prefix, mode))

    def _full_prefix(self, key, seen=()) -> str:
        if key is None or key in seen or key not in self.objects:
            return ""
        if key in self._prefix_cache:
            return self._prefix_cache[key]
        own = self.objects[key].prefix
        options = sorted(self.links.get(key, []), key=lambda l: (l.parent or ("", ""), l.prefix or ""))
        if not options:
            out = own
        else:
            link = options[0]
            above = self._full_prefix(link.parent, (*seen, key))
            middle = (link.prefix if link.prefix is not None else own) if link.mode == "override" else (link.prefix or "") + own
            out = above + middle
        self._prefix_cache[key] = out
        return out

    # ---- finding handlers ----------------------------------------------------------------------------------------

    def _framework(self, sf: PyFile, key, attr: str) -> str:
        if key is not None:
            return "fastapi" if self.objects[key].kind.startswith("fastapi") else "flask"
        if imports_framework(sf, FASTAPI_LIKE_MODULES) and not imports_framework(sf, FLASK_LIKE_MODULES):
            return "fastapi"
        return "flask"

    def _accepts(self, sf: PyFile, key) -> bool:
        return key is not None or imports_framework(sf, FLASK_LIKE_MODULES | FASTAPI_LIKE_MODULES)

    def _decorated(self, sf: PyFile) -> list:
        out = []
        for fd in self.project.defs_by_file[sf.rel]:
            for deco in fd.node.decorator_list:
                out.extend(self._from_decorator(sf, deco, [fd], fd.node.lineno))
        for info in (c for infos in self.project.classes.values() for c in infos if c.file is sf):
            handlers = [fd for name, fd in info.methods.items() if name in HTTP_METHODS]
            for deco in info.node.decorator_list:
                out.extend(self._from_decorator(sf, deco, handlers, info.node.lineno, class_based=True))
        return out

    def _from_decorator(self, sf, deco, handlers, line, class_based=False) -> list:
        if not (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)):
            return []
        attr = deco.func.attr
        if attr not in VERB_DECORATORS and attr not in ("route", "api_route"):
            return []
        path_node = arg_or_keyword(deco, 0, "path") if attr != "route" else arg_or_keyword(deco, 0, "rule")
        path = self.consts.text(path_node, sf) if path_node is not None else None
        key = self._key(sf, deco.func.value)
        if path is None or not self._accepts(sf, key):
            return []
        framework = self._framework(sf, key, attr)
        methods = self.consts.strings(keyword(deco, "methods"), sf) if keyword(deco, "methods") is not None else None
        out = []
        for fd in handlers:
            if class_based:
                chosen = [fd.name.upper()]
            elif attr in VERB_DECORATORS:
                chosen = [attr.upper()]
            else:
                chosen = [m.upper() for m in methods] if methods else ["GET"]
            out.append(self._entry(sf, key, framework, path, chosen, fd, deco, line))
        return out

    def _calls(self, sf: PyFile) -> list:
        out = []
        for node in ast.walk(sf.tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            attr = node.func.attr
            key = self._key(sf, node.func.value)
            if attr == "add_url_rule":
                rule = self.consts.text(arg_or_keyword(node, 0, "rule"), sf) if arg_or_keyword(node, 0, "rule") is not None else None
                view = arg_or_keyword(node, 2, "view_func")
                if rule is None or view is None or not self._accepts(sf, key):
                    continue
                methods = self.consts.strings(keyword(node, "methods"), sf) if keyword(node, "methods") is not None else None
                for fd, is_class in self._view_targets(sf, view):
                    if is_class:
                        for name, method_fd in sorted(fd.methods.items()):
                            if name in HTTP_METHODS:
                                out.append(self._entry(sf, key, "flask", rule, [name.upper()], method_fd, node, node.lineno))
                    else:
                        out.append(self._entry(sf, key, "flask", rule, [m.upper() for m in methods] if methods else ["GET"], fd, node, node.lineno))
            elif attr == "add_api_route":
                path_node = arg_or_keyword(node, 0, "path")
                endpoint = arg_or_keyword(node, 1, "endpoint")
                path = self.consts.text(path_node, sf) if path_node is not None else None
                target = self.project.resolve_dotted(sf, dotted(endpoint) or "") if endpoint is not None else None
                if path is None or not target or target[0] != "func":
                    continue
                methods = self.consts.strings(keyword(node, "methods"), sf) if keyword(node, "methods") is not None else None
                out.append(self._entry(sf, key, "fastapi", path, [m.upper() for m in methods] if methods else ["GET"], target[1], node, node.lineno))
            elif attr == "add_resource" and len(node.args) >= 2:
                target = self.project.resolve_dotted(sf, dotted(node.args[0]) or "")
                if not target or target[0] != "class":
                    continue
                for url_node in node.args[1:]:
                    url = self.consts.text(url_node, sf)
                    if url is None:
                        continue
                    for name, method_fd in sorted(target[1].methods.items()):
                        if name in HTTP_METHODS:
                            out.append(self._entry(sf, key, "flask", url, [name.upper()], method_fd, node, node.lineno))
        return out

    def _view_targets(self, sf, node) -> list:
        """`view_func=handler` or `view_func=Cls.as_view("name")` -> [(FuncDef or ClassInfo, is class)]."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
            target = self.project.resolve_dotted(sf, dotted(node.func.value) or "")
            return [(target[1], True)] if target and target[0] == "class" else []
        target = self.project.resolve_dotted(sf, dotted(node) or "")
        return [(target[1], False)] if target and target[0] == "func" else []

    # ---- building routes -----------------------------------------------------------------------------------------

    def _entry(self, sf, key, framework, path, methods, fd, node, line) -> dict:
        return {"sf": sf, "file": sf.rel, "line": line, "key": key, "framework": framework, "path": path,
                "methods": methods, "fd": fd, "node": node}

    def _add(self, entry):
        key, framework, fd, sf = entry["key"], entry["framework"], entry["fd"], entry["sf"]
        full = join_url(self.base_path, self._full_prefix(key), entry["path"])
        node = entry["node"]
        strict_off = isinstance(node, ast.Call) and isinstance(keyword(node, "strict_slashes"), ast.Constant) \
            and keyword(node, "strict_slashes").value is False
        if framework == "fastapi":
            template, path_names = fastapi_template(full)
            seeds, extra = fastapi_mod.bind(self.project, fd, set(path_names))
            html = _is_html_class(node)
            slash_alias = True
        else:
            template, typed = flask_template(full)
            seeds = {name: Seed(name, "path", numeric=numeric) for name, numeric in typed.items() if name in fd.params}
            extra, html, slash_alias = [], True, strict_off
        self._register(template, entry["methods"], fd, framework, seeds, extra, html, slash_alias)

    def _register(self, template, methods, fd, framework, seeds, extra, html, slash_alias, all_seeds=None):
        merged = self.out.routes.get(template)
        if merged is None:
            merged = self.out.routes[template] = Route(path=template, kind="framework", handler_file=fd.file.rel,
                                                       handler_function=fd.label, start_line=fd.start_line, end_line=fd.end_line)
        merged.methods.update(methods)
        if template != "/":
            alias = template[:-1] if template.endswith("/") else template + "/"
            if (template.endswith("/") or slash_alias) and alias not in merged.aliases:
                merged.aliases.append(alias)
        view = Route(path=template, kind="framework", methods=set(methods), handler_file=fd.file.rel,
                     handler_function=fd.label, start_line=fd.start_line, end_line=fd.end_line)
        _record_params(view, all_seeds if all_seeds is not None else seeds.values(), extra)
        self.out.handlers.append(HandlerRoute(fd, view, framework, seeds, html))

    def _django_routes(self):
        result = django_mod.routes(self.project, self.consts, self.base_path)
        for entry in result.entries:
            self._register(entry.template, entry.methods, entry.fd, "django-hook" if entry.hook else "django", entry.seeds, [], not entry.hook, False,
                           all_seeds=entry.all_seeds)
        for generic in result.generics:
            self._register_generic(generic)

    def _register_generic(self, g):
        """A generic view: the URL and the inputs come from its class attributes, since the code that reads them is Django's."""
        info, methods = g.info, django_mod.GENERIC_METHODS[g.kind]
        end = getattr(info.node, "end_lineno", None) or info.node.lineno
        merged = self.out.routes.get(g.template)
        if merged is None:
            merged = self.out.routes[g.template] = Route(path=g.template, kind="framework", handler_file=info.file.rel,
                                                         handler_function=info.name, start_line=info.node.lineno, end_line=end)
        merged.methods.update(methods)
        if g.template != "/" and g.template.endswith("/") and g.template[:-1] not in merged.aliases:
            merged.aliases.append(g.template[:-1])
        view = Route(path=g.template, kind="framework", methods=set(methods), handler_file=info.file.rel,
                     handler_function=info.name, start_line=info.node.lineno, end_line=end)
        seeds = [Seed(name, "path", numeric=numeric) for name, numeric in g.converters.items()]
        seeds += [Seed(name, "body", numeric=name in g.typed, required=False) for name in g.fields]
        if g.paginated:
            seeds.append(Seed("page", "query", required=False))
        _record_params(view, seeds, [])
        self.out.generics.append(GenericRoute(g, view))

    # ---- routes declared in an OpenAPI document -------------------------------------------------------------------

    def _spec_routes(self):
        for rel, doc in openapi_mod.load_specs(self.project.root, self.project.excludes):
            spec = openapi_mod.Spec(doc)
            prefix = self._add_api_prefix(rel) if self._add_api_prefix(rel) is not None else spec.base_path()
            for path, method, op, shared in spec.operations():
                handler = self._spec_handler(op)
                if handler is None:
                    continue
                template = join_url(self.base_path, prefix, path)
                everything, by_var = spec.seeds(op, shared)
                seeds = {var: seed for var, seed in by_var.items() if var in handler.params}
                self._register(template, [method], handler, "openapi", seeds, [], False, False, all_seeds=everything)

    def _spec_handler(self, op: dict):
        name = op.get("operationId")
        if not isinstance(name, str):
            return None
        controller = op.get("x-openapi-router-controller") or op.get("x-swagger-router-controller")
        for candidate in ([f"{controller}.{name}"] if controller else []) + [name]:
            target = self.project.resolve_qualified_name(candidate)
            if target and target[0] == "func":
                return target[1]
        return None

    def _add_api_prefix(self, spec_rel: str):
        """`app.add_api("openapi.yml", base_path="/v1")`: the prefix connexion mounts a document under."""
        stem = os.path.basename(spec_rel)
        for sf in self.project.files.values():
            for node in ast.walk(sf.tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_api" and node.args:
                    named = self.consts.text(node.args[0], sf)
                    if named and os.path.basename(named) == stem:
                        found = keyword(node, "base_path")
                        return (self.consts.text(found, sf) or "").rstrip("/") if found is not None else None
        return None


def _assignment(node):
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target.id, node.value
    return None, None


def _is_html_class(node) -> bool:
    if isinstance(node, ast.Call):
        found = keyword(node, "response_class")
        return found is not None and (dotted(found) or "").split(".")[-1] == "HTMLResponse"
    return False


def _record_params(view: Route, seeds, extra):
    for seed in _leaves(seeds, extra):
        param = Param(seed.name, seed.location, type="validated" if seed.numeric else None)
        key = (seed.name, seed.location)
        view.params.setdefault(key, param)
        if seed.required or seed.location == "path":
            view.required.setdefault(key, param)


def _leaves(seeds, extra):
    for seed in seeds:
        if seed.kind == "model":
            yield from _leaves(seed.fields.values(), ())
        elif seed.kind == "value":
            yield seed
    yield from extra
