"""Finds routes declared in code rather than by file name: router calls such as
`$app->get('/x', 'handler')`, route attributes such as `#[Route('/x')]` and docblock
annotations. It goes by the shape of the declaration, not by which framework wrote it.
"""
from __future__ import annotations

import re

from sast.core.model import Param
from sast.lang.php.values import RequestRole, Taint, Val

VERBS = {"get", "post", "put", "patch", "delete", "any", "options", "match", "map"}
RESOURCE_CALLS = {"resource": 0, "apiresource": 1}
# Conventional actions of a resource controller: (action, HTTP method, path suffix).
RESOURCE_ACTIONS = [
    ("index", "GET", ""), ("store", "POST", ""), ("show", "GET", "/{id}"),
    ("update", "PUT", "/{id}"), ("destroy", "DELETE", "/{id}"),
]
ROUTE_ATTRS = {"route", "get", "post", "put", "patch", "delete", "any", "getmapping", "postmapping", "requestmapping"}
ROUTE_HINT = re.compile(rb"(::|->)\s*(get|post|put|patch|delete|any|options|match|map|resource|apiresource)\s*\(\s*['\"]", re.I)
ROUTER_RECEIVER = re.compile(r"\b(route|routes|router|app|group|r)\b", re.I)
PATH_PARAM = re.compile(r"\{(\w+)\??(?::[^}]*)?\}|<(\w+)>|(?<![\w/]):(\w+)|/:(\w+)")
# An untyped handler parameter with one of these names holds all the route's values.
ROUTE_VALUE_ARRAYS = {"args", "params", "parameters", "vars", "matches"}
DOC_ROUTE = re.compile(r"""@(?:\w+\\)*(Route|Get|Post|Put|Patch|Delete|Any)\s*\(\s*(?:path\s*=\s*)?["']([^"']*)["']""", re.I)
API_ROUTES_FILE = re.compile(r"(^|/)routes/api\.php$")
HTTP_VERB = re.compile(r"""["'](GET|POST|PUT|PATCH|DELETE)["']""", re.I)


class FrameworkRoute:
    """One declared route, and how to run its handler with its parameters marked as input."""

    def __init__(self, fd, route, constraints=None):
        self.fd, self.route = fd, route
        self.constraints = constraints or {}  # path parameter -> sanitiser label, from ->whereNumber('id') and the like

    def run(self, interp):
        path_names = {next(g for g in groups if g) for groups in PATH_PARAM.findall(self.route.path)}
        seed = {}
        for param in self.fd.params.kids if self.fd.params is not None else []:
            name = param.f("name") if param.type in ("simple_parameter", "variadic_parameter", "property_promotion_parameter") else None
            if name is None:
                continue
            type_node = param.f("type")
            hint = type_node.text.lstrip("?").split("\\")[-1] if type_node is not None else ""
            short = name.text.lstrip("$")
            if interp._is_request_type(hint):
                seed[name.text] = Val(closure=RequestRole())
                continue
            step = (self.fd.sf.rel, param.line, f"route parameter {short}")
            if short in path_names:
                taint = Taint(short, "path", (step,))
                constrained = self.constraints.get(short)
                self.route.params.setdefault((short, "path"), Param(short, "path", type="validated" if constrained else None))
                if constrained:
                    taint = taint.sanitized(constrained)
            elif not hint and short.lower() in ROUTE_VALUE_ARRAYS:
                taint = Taint("*", "path", (step,))
            elif not hint or hint == "string":
                # Could be a route value, or something the framework injects. Unknown, so it ranks lower.
                taint = Taint(short, "any", (step,), penalty=1)
            else:
                continue
            if hint in ("int", "float", "bool"):
                taint = taint.sanitized("int")
            seed[name.text] = Val.of(taint)
        interp.run_function(self.fd, [self.route], seed)


def detect(project, routes, interp) -> list:
    found = []
    for sf in project.files.values():
        if ROUTE_HINT.search(sf.data):
            found.extend(_call_routes(sf, project, routes, interp))
    found.extend(_attribute_routes(project, routes))
    return found


def _add(project, routes, handler, path, methods) -> FrameworkRoute:
    route = routes.get(routes.prefix + path, None, kind="framework", handler=handler.sf.rel)
    route.methods.update(methods)
    route.handler_function, route.start_line, route.end_line = handler.label, handler.node.line, handler.node.end_line
    return FrameworkRoute(handler, route)


def _call_routes(sf, project, routes, interp) -> list:
    """Reads calls like Route::get('/x', [C::class, 'm']) and $app->post('/x', 'handler')."""
    found = []
    prefixes = _prefixes(sf.tree)
    stack = [sf.tree]
    while stack:
        cur = stack.pop()
        stack.extend(cur.kids)
        if cur.type not in ("scoped_call_expression", "member_call_expression"):
            continue
        name = cur.f("name")
        lowered = name.text.lower() if name is not None else ""
        if lowered not in VERBS and lowered not in RESOURCE_CALLS:
            continue
        args = interp._arg_nodes(cur)
        methods = None
        if lowered == "match" and len(args) >= 3 and args[0].type == "array_creation_expression":
            methods = {verb.upper() for verb in HTTP_VERB.findall(args[0].text)} or None
            args = args[1:]
        if len(args) < 2 or args[0].type not in ("string", "encapsed_string"):
            continue
        path = interp._literal(args[0])
        # Lots of methods are called get(), so without a leading slash the receiver has to look like a router.
        receiver = cur.f("scope") if cur.type == "scoped_call_expression" else cur.f("object")
        if not path.startswith("/") and not (receiver is not None and ROUTER_RECEIVER.search(receiver.text)):
            continue
        full = _with_prefix(prefixes.get(cur.sb, ""), path)
        if API_ROUTES_FILE.search(sf.rel):  # Laravel mounts routes/api.php under /api
            full = _with_prefix("api", full)
        if lowered in RESOURCE_CALLS:
            found.extend(_resource_routes(args[1], full, project, routes, sf))
            continue
        handler = _handler(args[1], project, sf)
        if handler is not None:
            if methods is None:
                methods = {"GET", "POST"} if lowered == "any" else {"GET"} if lowered in ("match", "map") else {lowered.upper()}
            found.append(_add(project, routes, handler, full, methods))
            found[-1].constraints = _constraints(sf, cur)
    return found


_WHERE_CALL = re.compile(r"""\A\s*->\s*(\w+)\s*\(([^)]*)\)""", re.S)
_NUMERIC_PATTERN = re.compile(r"""^\^?(?:\[0-9\]|\\d)[+*]?\$?$|^\^?\(?\[0-9\]\+\)?\$?$""")


def _constraints(sf, node) -> dict:
    """Reads the calls chained onto a route that restrict a path parameter: ->whereNumber('id'), ->whereUuid('id'),
    ->where('id', '[0-9]+'). The framework answers 404 to anything else, so no text reaches the handler."""
    out = {}
    text = sf.data[node.eb:node.eb + 600].decode("utf-8", "replace")
    while True:
        match = _WHERE_CALL.match(text)
        if not match:
            return out
        name, arguments = match.group(1).lower(), match.group(2)
        quoted = re.findall(r"""['"]([^'"]*)['"]""", arguments)
        if name in ("wherenumber", "whereuuid", "whereulid", "wherealpha", "wherealphanumeric") and quoted:
            for param in quoted:
                out[param] = "int" if name == "wherenumber" else "allowlist"
        elif name == "where" and len(quoted) >= 2 and _NUMERIC_PATTERN.match(quoted[1].replace(" ", "")):
            out[quoted[0]] = "int"
        elif name == "where" and len(quoted) >= 2 and _pattern_is_harmless(quoted[1]):
            out[quoted[0]] = "allowlist"
        elif name == "wherein" and quoted:
            out[quoted[0]] = "allowlist"
        text = text[match.end():]


def _pattern_is_harmless(pattern: str) -> bool:
    """Whether a route's where() pattern, which Laravel anchors at both ends, can't match any character that does harm
    in SQL, HTML, a shell or a path."""
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False
    unsafe = "'\"<>/\\;&|`$(){}%# .\n"
    return not any(compiled.fullmatch(sample) for char in unsafe for sample in (char, "a" + char + "a"))


def _resource_routes(node, path, project, routes, sf) -> list:
    match = re.search(r"([\w\\]+)::class", node.text) or re.fullmatch(r"""\s*['"]([\w\\]+)['"]\s*""", node.text)
    if not match:
        return []
    cls = _class_name(match.group(1), sf)
    out = []
    for action, method, suffix in RESOURCE_ACTIONS:
        handler = project.find_method(cls, action)
        if handler is not None:
            out.append(_add(project, routes, handler, path + suffix, {method}))
    return out


def _attribute_routes(project, routes) -> list:
    """Reads #[Route('/x')] on a method, and its docblock form, with a class-level prefix if any."""
    found = []
    for info in project.classes.values():
        node = info.get("node")
        body = node.f("body") if node is not None else None
        if body is None:
            continue
        prefix = next((path for path, _ in _attributes_of(node)), "")
        last_comment = ""
        for kid in body.kids:
            if kid.type == "comment":
                last_comment = kid.text
                continue
            if kid.type == "method_declaration" and kid.f("name") is not None:
                handler = info["methods"].get(kid.f("name").text.lower())
                declared = _attributes_of(kid) + _docblock_routes(last_comment)
                for path, methods in declared if handler is not None else ():
                    found.append(_add(project, routes, handler, _with_prefix(prefix, path), methods))
            last_comment = ""
    return found


def _attributes_of(node) -> list:
    out = []
    for attributes in node.fl("attributes"):
        stack = [attributes]
        while stack:
            cur = stack.pop()
            stack.extend(cur.kids)
            if cur.type != "attribute" or not cur.kids:
                continue
            name = cur.kids[0].text.split("\\")[-1].lower()
            match = re.search(r"""["']([^"']*)["']""", cur.text)
            if name in ROUTE_ATTRS and match:
                out.append((match.group(1), _methods_for(name, cur.text)))
    return out


def _docblock_routes(comment: str) -> list:
    return [(path, _methods_for(name.lower(), comment)) for name, path in DOC_ROUTE.findall(comment)]


def _methods_for(name: str, text: str) -> set:
    if name in ("get", "post", "put", "patch", "delete"):
        return {name.upper()}
    if name.endswith("mapping") and name != "requestmapping":
        return {name[: -len("mapping")].upper()}
    named = re.search(r"methods?\s*[:=]\s*(.*)", text, re.I | re.S)
    verbs = {verb.upper() for verb in HTTP_VERB.findall(named.group(1))} if named else set()
    return verbs or {"GET"}


def _with_prefix(prefix, path):
    joined = "/".join(part.strip("/") for part in (prefix, path) if part.strip("/"))
    return "/" + joined


def _prefixes(tree) -> dict:
    """Maps a call inside a route group to the group's prefix: Route::prefix('x')->group(...),
    Route::group(['prefix' => 'x'], ...) and $app->group('/x', ...)."""
    out = {}
    stack = [(tree, "")]
    while stack:
        node, prefix = stack.pop()
        if node.type in ("member_call_expression", "scoped_call_expression") and node.f("name") is not None \
                and node.f("name").text.lower() == "group":
            inner = node.f("object")
            arguments = node.f("arguments")
            first = arguments.kids[0].text if arguments is not None and arguments.kids else ""
            match = (re.search(r"""prefix\(\s*['"]([^'"]+)""", inner.text) if inner is not None else None) \
                or re.search(r"""['"]prefix['"]\s*=>\s*['"]([^'"]+)""", first) \
                or re.fullmatch(r"""\s*['"](/[^'"]*)['"]\s*""", first)
            if match:
                prefix = prefix + "/" + match.group(1).strip("/")
        out[node.sb] = prefix
        stack.extend((kid, prefix) for kid in node.kids)
    return out


def _class_name(text: str, sf) -> str:
    name = text.split("\\")[-1]
    return sf.aliases.get(name, name)


def _handler(node, project, sf):
    """Finds the function a route points at: [C::class, 'm'], 'C@m', 'C::m', 'C:m', 'name' or a closure."""
    if node.type in ("anonymous_function", "arrow_function") and node.f("body") is not None:
        from sast.lang.php.project import FuncDef
        return FuncDef(f"closure@{node.line}", None, node, sf) if node.f("body").type == "compound_statement" else None
    text = node.text
    match = re.search(r"\[\s*\\?([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]", text) \
        or re.search(r"\[\s*['\"]([\w\\]+)['\"]\s*,\s*['\"](\w+)['\"]\s*\]", text) \
        or re.search(r"['\"]([\w\\]+)(?:@|::|:)(\w+)(?:/[^'\"]*)?['\"]", text)
    if match:
        return project.find_method(_class_name(match.group(1), sf), match.group(2).lower())
    match = re.fullmatch(r"\s*['\"](\w+)['\"]\s*", text)
    if match:
        functions = project.functions.get(match.group(1).lower())
        return functions[0] if functions else None
    return None
