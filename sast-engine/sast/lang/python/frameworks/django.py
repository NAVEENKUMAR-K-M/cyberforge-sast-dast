"""Django: routes declared in urls.py, and how each view receives its input.

Django keeps URLs apart from the views: `urlpatterns = [path("orders/<int:pk>/", views.order)]`, with other
urls.py files pulled in under a prefix by `include()`. A view is a function that takes the request first, or a
class whose get/post/... methods answer the matching HTTP method. DRF routers (`router.register("orders",
OrderViewSet)`) expand to the usual list/detail URLs.
"""
from __future__ import annotations

import ast
import re

from ..project import HTTP_METHODS, ClassInfo, FuncDef, Project, PyFile, dotted
from .common import Consts, Seed, join_url

URL_CALLS = {"path", "re_path", "url"}
ROUTER_CLASSES = {"DefaultRouter", "SimpleRouter", "ExtendedSimpleRouter", "ExtendedDefaultRouter"}
MAX_DEPTH = 8
# Converters whose values can't carry markup or quotes.
VALIDATED_CONVERTERS = {"int", "uuid", "slug"}
_PATH_CONVERTER = re.compile(r"<(?:(?P<conv>\w+):)?(?P<name>\w+)>")
_NAMED_GROUP = re.compile(r"\(\?P<(\w+)>((?:[^()]|\([^()]*\))*)\)")
_PLAIN_GROUP = re.compile(r"\((?!\?)((?:[^()]|\([^()]*\))*)\)")
_NUMERIC_GROUP = re.compile(r"^(\\d|\[0-9\])[+*]?(\{\d+(,\d*)?\})?$")
_SAFE_GROUP = re.compile(r"^\[[\w\-\\]+\][+*]$|^(\\w|\\d)[+*]$|^\[A-Za-z0-9_\-\]\+$")
REQUIRE_METHODS = {"require_GET": ["GET"], "require_POST": ["POST"], "require_safe": ["GET", "HEAD"]}
VIEWSET_ACTIONS = [
    ("list", "GET", ""), ("create", "POST", ""), ("retrieve", "GET", "/{pk}"), ("update", "PUT", "/{pk}"),
    ("partial_update", "PATCH", "/{pk}"), ("destroy", "DELETE", "/{pk}"),
]
# Django's ready-made views, in the order a class that mixes several is read.
GENERIC_KINDS = [
    ("CreateView", "create"), ("UpdateView", "update"), ("DeleteView", "delete"), ("FormView", "form"),
    ("ListView", "list"), ("ArchiveIndexView", "list"), ("YearArchiveView", "list"), ("MonthArchiveView", "list"),
    ("DayArchiveView", "list"), ("TodayArchiveView", "list"), ("DetailView", "detail"), ("DateDetailView", "detail"),
    ("TemplateView", "template"),
]
GENERIC_METHODS = {"list": ["GET"], "detail": ["GET"], "template": ["GET"], "create": ["GET", "POST"],
                   "update": ["GET", "POST"], "form": ["GET", "POST"], "delete": ["GET", "POST", "DELETE"]}
# Methods the framework calls on a generic view, and the HTTP method that gets there.
HOOKS = {"get_queryset": ["GET"], "get_context_data": ["GET"], "get_object": ["GET"], "get_template_names": ["GET"],
         "get_redirect_url": ["GET"], "form_valid": ["POST"], "form_invalid": ["POST"], "get_success_url": ["POST"],
         "get_form_kwargs": ["POST"]}
MODEL_TYPED = {"IntegerField", "BigIntegerField", "SmallIntegerField", "PositiveIntegerField", "PositiveSmallIntegerField",
               "FloatField", "DecimalField", "BooleanField", "NullBooleanField", "DateField", "DateTimeField", "TimeField",
               "DurationField", "UUIDField", "ForeignKey", "OneToOneField", "ManyToManyField"}


class Generic:
    """What a generic view does for the project, from its class attributes: the model it reads or writes, the fields a
    form submits, the template it renders."""
    __slots__ = ("template", "info", "kind", "model", "fields", "typed", "template_name", "context_names", "paginated", "converters")

    def __init__(self, template, info, kind, converters):
        self.template, self.info, self.kind, self.converters = template, info, kind, converters
        self.model, self.fields, self.typed = None, [], set()
        self.template_name, self.context_names, self.paginated = None, set(), False


class Entry:
    """One view answering one URL."""
    __slots__ = ("template", "methods", "fd", "seeds", "all_seeds", "hook")

    def __init__(self, template, methods, fd, seeds, all_seeds, hook=False):
        self.template, self.methods, self.fd, self.seeds, self.all_seeds, self.hook = template, methods, fd, seeds, all_seeds, hook


class Result:
    def __init__(self):
        self.entries: list[Entry] = []
        self.generics: list[Generic] = []


def routes(project: Project, consts: Consts, base_path: str = "") -> Result:
    return _Reader(project, consts, base_path).read()


class _Reader:
    def __init__(self, project: Project, consts: Consts, base_path: str):
        self.project, self.consts, self.base_path = project, consts, base_path.rstrip("/")
        self.out = Result()
        self._seen: set = set()

    def read(self) -> Result:
        modules = {rel: sf for rel, sf in self.project.files.items() if self._pattern_lists(sf)}
        if not modules:
            return self.out
        included = set()
        for sf in modules.values():
            for module in self._included_modules(sf):
                included.add(module.rel)
        roots = self._root_urlconfs(modules) or [sf for rel, sf in sorted(modules.items()) if rel not in included]
        for sf in roots:
            self._expand(sf, "", 0)
        return self.out

    # ---- finding the url modules -----------------------------------------------------------------------------------

    def _pattern_lists(self, sf: PyFile) -> list:
        """The module-level `urlpatterns` expressions, in order, joining `+=` additions."""
        found = []
        for stmt in sf.tree.body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in stmt.targets):
                found.append(stmt.value)
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == "urlpatterns":
                found.append(stmt.value)
        return found

    def _root_urlconfs(self, modules: dict) -> list:
        roots = []
        for sf in self.project.files.values():
            for stmt in sf.tree.body:
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "ROOT_URLCONF" for t in stmt.targets):
                    name = self.consts.text(stmt.value, sf)
                    module = self.project.find_module(name) if name else None
                    if module is not None and module.rel in modules and module not in roots:
                        roots.append(module)
        return roots

    def _included_modules(self, sf: PyFile) -> list:
        out = []
        for node in ast.walk(sf.tree):
            if isinstance(node, ast.Call) and (dotted(node.func) or "").split(".")[-1] == "include" and node.args:
                module = self._include_target(sf, node.args[0])
                if module is not None:
                    out.append(module)
        return out

    def _include_target(self, sf: PyFile, node):
        if isinstance(node, (ast.Tuple, ast.List)) and node.elts:
            node = node.elts[0]
        text = self.consts.text(node, sf)
        if text:
            return self.project.find_module(text)
        name = dotted(node)
        if name and name.endswith(".urls"):
            target = self.project.resolve_dotted(sf, name[:-len(".urls")])
            if target and target[0] == "module":
                return target[1]
        if name:
            target = self.project.resolve_dotted(sf, name)
            if target and target[0] == "module":
                return target[1]
        return None

    # ---- walking the patterns --------------------------------------------------------------------------------------

    def _expand(self, sf: PyFile, prefix: str, depth: int) -> None:
        key = (sf.rel, prefix)
        if depth > MAX_DEPTH or key in self._seen:
            return
        self._seen.add(key)
        routers = self._routers(sf)
        for expression in self._pattern_lists(sf):
            for item in self._items(expression):
                self._pattern(sf, item, prefix, depth, routers)

    def _items(self, node):
        """The entries of a urlpatterns expression: a list, a sum of lists, or a list wrapped by a helper."""
        if isinstance(node, (ast.List, ast.Tuple)):
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    yield from self._items(element.value)
                else:
                    yield element
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            yield from self._items(node.left)
            yield from self._items(node.right)
        elif isinstance(node, ast.Call) and node.args:
            yield from self._items(node.args[0])  # format_suffix_patterns([...])

    def _pattern(self, sf: PyFile, item, prefix: str, depth: int, routers: dict) -> None:
        if not (isinstance(item, ast.Call) and (dotted(item.func) or "").split(".")[-1] in URL_CALLS and len(item.args) >= 2):
            return
        kind = (dotted(item.func) or "").split(".")[-1]
        route = self.consts.text(item.args[0], sf)
        if route is None:
            return
        template, converters = _to_template(route, regex=kind != "path")
        full = join_url(prefix, template) if prefix or template else "/"
        target = item.args[1]
        if isinstance(target, ast.Call) and (dotted(target.func) or "").split(".")[-1] == "include" and target.args:
            self._include(sf, target, full, depth, routers)
            return
        for view, methods in self._views(sf, target):
            if isinstance(view, ClassInfo):
                self._generic(view, full, converters)
            else:
                self._entry(view, methods, full, converters)

    def _include(self, sf: PyFile, call, prefix: str, depth: int, routers: dict) -> None:
        arg = call.args[0]
        if isinstance(arg, ast.Attribute) and arg.attr == "urls" and dotted(arg.value) in routers:
            self._router_routes(sf, routers[dotted(arg.value)], prefix)
            return
        module = self._include_target(sf, arg)
        if module is not None:
            self._expand(module, prefix, depth + 1)
            return
        if isinstance(arg, ast.Name):  # include(extra_patterns): a list defined in this module
            for stmt in sf.tree.body:
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg.id for t in stmt.targets):
                    for item in self._items(stmt.value):
                        self._pattern(sf, item, prefix, depth + 1, routers)

    # ---- views -----------------------------------------------------------------------------------------------------

    def _views(self, sf: PyFile, node) -> list:
        """[(FuncDef, methods)] for what a pattern points at."""
        while isinstance(node, ast.Call):
            if (dotted(node.func) or "").split(".")[-1] == "as_view":
                target = self.project.resolve_dotted(sf, dotted(node.func.value) or "")
                if target and target[0] == "class":
                    return self._class_views(target[1])
                return []
            if not node.args:
                return []
            node = node.args[0]  # login_required(view), csrf_exempt(view), cache_page(60)(view)
        target = self.project.resolve_dotted(sf, dotted(node) or "") if dotted(node) else None
        if target and target[0] == "func":
            return [(target[1], _function_methods(target[1]))]
        if target and target[0] == "class":
            return self._class_views(target[1])
        return []

    def _class_views(self, info: ClassInfo) -> list:
        views = []
        for name in HTTP_METHODS:
            fd = self.project.class_methods(info, name)
            if fd is not None:
                views.append((fd, [name.upper()]))
        if self._generic_kind(info) is not None:
            views.append((info, []))  # the framework's own behaviour, read from the class attributes
        return views

    def _entry(self, fd: FuncDef, methods: list, template: str, converters: dict, form_fields=None, hook: bool = False) -> None:
        seeds, everything = _view_seeds(fd, converters, form_fields, hook)
        full = join_url(self.base_path, template) if self.base_path else template
        self.out.entries.append(Entry(_normalise(full), methods, fd, seeds, everything, hook))

    # ---- generic class-based views ---------------------------------------------------------------------------------

    def _generic_kind(self, info: ClassInfo):
        for base, kind in GENERIC_KINDS:
            if self.project.class_has_base(info, {base}):
                return kind
        return None

    def _attribute(self, info: ClassInfo, name: str, depth: int = 0):
        """The value assigned to a class attribute in this class or one of its project base classes."""
        for stmt in info.node.body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                return stmt.value, info.file
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == name and stmt.value is not None:
                return stmt.value, info.file
        if depth < 5:
            for base in info.bases:
                target = self.project.resolve_dotted(info.file, base) if base else None
                if target and target[0] == "class":
                    found = self._attribute(target[1], name, depth + 1)
                    if found is not None:
                        return found
        return None

    def _generic(self, info: ClassInfo, template: str, converters: dict) -> None:
        kind = self._generic_kind(info)
        g = Generic(_normalise(join_url(self.base_path, template) if self.base_path else template), info, kind, converters)
        found = self._attribute(info, "model")
        if found is None:  # queryset = Review.objects.all()
            queryset = self._attribute(info, "queryset")
            if queryset is not None:
                chain = queryset[0]
                while isinstance(chain, (ast.Call, ast.Attribute)):
                    chain = chain.func if isinstance(chain, ast.Call) else chain.value
                    if isinstance(chain, ast.Attribute) and chain.attr == "objects":
                        found = (chain.value, queryset[1])
                        break
        if found is not None and dotted(found[0]):
            g.model = self.project.lookup_class(found[1], dotted(found[0]))
        form = self._attribute(info, "form_class")
        fields = self._attribute(info, "fields")
        if form is not None and dotted(form[0]):
            form_info = self.project.lookup_class(form[1], dotted(form[0]))
            if form_info is not None:
                g.fields, g.typed = _declared_fields(form_info, self.project, form_declared=True)
        elif fields is not None and isinstance(fields[0], (ast.List, ast.Tuple)):
            g.fields = [e.value for e in fields[0].elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if g.model is not None:
                g.typed = {name for name, typed in _model_fields(g.model, self.project).items() if typed}
        elif fields is not None and g.model is not None:  # fields = "__all__"
            model_fields = _model_fields(g.model, self.project)
            g.fields, g.typed = list(model_fields), {name for name, typed in model_fields.items() if typed}
        if kind not in ("create", "update", "form"):
            g.fields, g.typed = [], set()
        name = self._attribute(info, "template_name")
        g.template_name = self.consts.text(name[0], name[1]) if name is not None else None
        context = self._attribute(info, "context_object_name")
        if context is not None and self.consts.text(context[0], context[1]):
            g.context_names.add(self.consts.text(context[0], context[1]))
        g.paginated = self._attribute(info, "paginate_by") is not None
        self.out.generics.append(g)
        # The methods the project overrides are real code to read. The framework calls them with the request's input.
        form_fields = {name: Seed(name, "body", numeric=name in g.typed) for name in g.fields}
        for hook, methods in HOOKS.items():
            fd = self.project.class_methods(info, hook)
            if fd is not None:
                self._entry(fd, methods, template, converters, form_fields, hook=True)

    # ---- Django REST framework routers -----------------------------------------------------------------------------

    def _routers(self, sf: PyFile) -> dict:
        """{router variable: [(url prefix, viewset class)]} for routers built in this module."""
        names = {}
        for stmt in sf.tree.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call) \
                    and (dotted(stmt.value.func) or "").split(".")[-1] in ROUTER_CLASSES:
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        names[target.id] = []
        if not names:
            return {}
        for node in ast.walk(sf.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "register" \
                    and dotted(node.func.value) in names and len(node.args) >= 2:
                url = self.consts.text(node.args[0], sf)
                target = self.project.resolve_dotted(sf, dotted(node.args[1]) or "")
                if url is not None and target and target[0] == "class":
                    names[dotted(node.func.value)].append((url, target[1]))
        return names

    def _router_routes(self, sf: PyFile, registrations: list, prefix: str) -> None:
        for url, info in registrations:
            for action, method, suffix in VIEWSET_ACTIONS:
                fd = self.project.class_methods(info, action)
                if fd is None:
                    continue
                template = join_url(prefix, url.strip("/") + suffix + "/")
                self._entry(fd, [method], template, {"pk": False})


# ---- route text ------------------------------------------------------------------------------------------------------


def _to_template(route: str, regex: bool):
    """('/orders/{pk}/', {'pk': validated?}) for a path() or re_path() pattern."""
    converters: dict = {}
    if not regex:
        def replace(match):
            converters[match.group("name")] = (match.group("conv") or "str") in VALIDATED_CONVERTERS
            return "{" + match.group("name") + "}"
        return _PATH_CONVERTER.sub(replace, route), converters
    text = route.lstrip("^").rstrip("$").replace("\\Z", "")
    counter = [0]

    def named(match):
        pattern = match.group(2)
        converters[match.group(1)] = bool(_NUMERIC_GROUP.match(pattern) or _SAFE_GROUP.match(pattern))
        return "{" + match.group(1) + "}"

    def plain(match):
        counter[0] += 1
        name = f"p{counter[0]}"
        converters[name] = bool(_NUMERIC_GROUP.match(match.group(1)) or _SAFE_GROUP.match(match.group(1)))
        return "{" + name + "}"

    text = _NAMED_GROUP.sub(named, text)
    text = _PLAIN_GROUP.sub(plain, text)
    text = re.sub(r"\\(.)", r"\1", text).replace("/?", "").replace("?", "")
    return text, converters


def _normalise(path: str) -> str:
    return "/" + path.lstrip("/") if path else "/"


def _function_methods(fd: FuncDef) -> list:
    """Which methods a function view answers: the decorators say, or else any."""
    for decorator in fd.node.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        name = (dotted(call.func if call else decorator) or "").split(".")[-1]
        if name in REQUIRE_METHODS:
            return list(REQUIRE_METHODS[name])
        if name in ("require_http_methods", "api_view") and call is not None and call.args:
            listed = [e.value.upper() for e in getattr(call.args[0], "elts", []) if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if listed:
                return listed
        if name == "api_view":
            return ["GET"]
    return ["GET", "POST"]


def _declared_fields(info: ClassInfo, project: Project, form_declared: bool = False):
    """(field names, names that parse to a number/date/choice) from a Form's declared fields."""
    names, typed = [], set()
    for stmt in info.node.body:
        target, value = None, None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            target, value = stmt.target.id, stmt.value
        if target and isinstance(value, ast.Call):
            kind = (dotted(value.func) or "").split(".")[-1]
            if kind.endswith("Field"):
                names.append(target)
                if kind in MODEL_TYPED | {"ChoiceField", "TypedChoiceField", "ModelChoiceField", "SlugField", "MultipleChoiceField"}:
                    typed.add(target)
    return names, typed


def _model_fields(model: ClassInfo, project: Project) -> dict:
    """{field name: parsed into a number, date or key} for a model's own columns."""
    out = {}
    for stmt in model.node.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name) and isinstance(stmt.value, ast.Call):
            kind = (dotted(stmt.value.func) or "").split(".")[-1]
            if kind.endswith(("Field", "Key")) and not kind.endswith("AutoField"):
                out[stmt.targets[0].id] = kind in MODEL_TYPED
    return out


def _view_seeds(fd: FuncDef, converters: dict, form_fields=None, hook: bool = False):
    """({view parameter: Seed}, [Seed for the route]) for a function or method view."""
    params = list(fd.params)
    seeds: dict = {}
    everything = [Seed(name, "path", numeric=numeric) for name, numeric in converters.items()]
    kwargs = {name: Seed(name, "path", numeric=numeric) for name, numeric in converters.items()}
    is_method = fd.cls is not None
    if is_method and params:
        seeds[params.pop(0)] = Seed("", "any", kind="view", fields=dict(kwargs))
    if params and not hook:  # a hook the framework calls (form_valid, get_queryset) is not handed the request
        seeds[params.pop(0)] = Seed("", "any", kind="request")
    positional = [seed for name, seed in kwargs.items() if name.startswith("p") and name[1:].isdigit()]
    for name in params:
        if name == "form" and form_fields:
            seeds[name] = Seed("", "body", kind="form", fields=dict(form_fields))
        elif name in kwargs:
            seeds[name] = kwargs[name]
        elif positional:
            seeds[name] = positional.pop(0)
    return seeds, everything
