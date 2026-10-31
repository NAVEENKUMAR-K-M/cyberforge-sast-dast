"""Finds routes declared in code, such as Laravel, Lumen, Slim or a hand-written router."""
from __future__ import annotations

import re

from sast.core.model import Param
from sast.lang.php.values import Taint, Val

VERBS = {"get", "post", "put", "patch", "delete", "any", "options", "match", "map"}
REQUEST_TYPES = {"Request", "ServerRequest", "ServerRequestInterface", "FormRequest"}
ROUTE_HINT = re.compile(rb"(::|->)\s*(get|post|put|patch|delete|any|options|match|map)\s*\(\s*['\"]", re.I)
PATH_PARAM = re.compile(r"\{(\w+)\??\}|:(\w+)")


class FrameworkRoute:
    """One declared route, and how to run its handler with its parameters marked as input."""

    def __init__(self, fd, route):
        self.fd, self.route = fd, route

    def run(self, interp):
        seed = {}
        path_names = {a or b for a, b in PATH_PARAM.findall(self.route.path)}
        if self.fd.params is not None:
            for param in self.fd.params.kids:
                name = param.f("name") if param.type in ("simple_parameter", "variadic_parameter") else None
                if name is None:
                    continue
                type_node = param.f("type")
                hint = type_node.text.lstrip("?").split("\\")[-1] if type_node is not None else ""
                short = name.text.lstrip("$")
                if hint in REQUEST_TYPES or hint.endswith("Request"):
                    seed[name.text] = Val(cls=None, closure="request")
                elif short in path_names or not hint or hint in ("string", "int", "mixed"):
                    step = (self.fd.sf.rel, param.line, f"route parameter {short}")
                    seed[name.text] = Val.of(Taint(short, "path", (step,)))
                    self.route.params.setdefault((short, "path"), Param(short, "path"))
        interp.run_function(self.fd, [self.route], seed)


def detect(project, routes, interp) -> list:
    """Reads calls like Route::get('/x', [C::class, 'm']) and $app->post('/x', 'handler')."""
    found = []
    for sf in project.files.values():
        if not ROUTE_HINT.search(sf.data):
            continue
        prefix_stack = _prefixes(sf.tree)
        stack = [sf.tree]
        while stack:
            cur = stack.pop()
            stack.extend(cur.kids)
            if cur.type not in ("scoped_call_expression", "member_call_expression"):
                continue
            name = cur.f("name")
            if name is None or name.text.lower() not in VERBS:
                continue
            args = interp._arg_nodes(cur)
            if len(args) < 2 or args[0].type not in ("string", "encapsed_string"):
                continue
            path = interp._literal(args[0])
            if not path.startswith("/") and cur.type != "scoped_call_expression":
                continue
            handler = _handler(args[1], project, sf)
            if handler is None:
                continue
            full = routes.prefix + _with_prefix(prefix_stack.get(cur.sb, ""), path)
            route = routes.get(full, None, kind="framework", handler=handler.sf.rel)
            route.methods.add("GET" if name.text.lower() in ("any", "match", "map") else name.text.upper())
            route.handler_function, route.start_line, route.end_line = handler.label, handler.node.line, handler.node.end_line
            found.append(FrameworkRoute(handler, route))
    return found


def _with_prefix(prefix, path):
    joined = "/".join(part.strip("/") for part in (prefix, path) if part.strip("/"))
    return "/" + joined


def _prefixes(tree) -> dict:
    """Maps a call inside Route::prefix('x')->group(...) to its prefix."""
    out = {}
    stack = [(tree, "")]
    while stack:
        node, prefix = stack.pop()
        if node.type == "member_call_expression" and node.f("name") is not None and node.f("name").text.lower() == "group":
            inner = node.f("object")
            match = re.search(r"prefix\(\s*['\"]([^'\"]+)", inner.text) if inner is not None else None
            if match:
                prefix = prefix + "/" + match.group(1).strip("/")
        out[node.sb] = prefix
        stack.extend((kid, prefix) for kid in node.kids)
    return out


def _handler(node, project, sf):
    """Finds the function a route points at: [C::class, 'm'], 'C@m', 'name' or a closure."""
    if node.type in ("anonymous_function", "arrow_function") and node.f("body") is not None:
        from sast.lang.php.project import FuncDef
        return FuncDef(f"closure@{node.line}", None, node, sf) if node.f("body").type == "compound_statement" else None
    text = node.text
    match = re.search(r"\[\s*\\?([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]", text)
    if match:
        return project.find_method(match.group(1).split("\\")[-1], match.group(2).lower())
    match = re.search(r"['\"]([\w\\]+)@(\w+)['\"]", text) or re.search(r"['\"]([\w\\]+):(\w+)['\"]", text)
    if match:
        return project.find_method(match.group(1).split("\\")[-1], match.group(2).lower())
    match = re.fullmatch(r"\s*['\"](\w+)['\"]\s*", text)
    if match:
        functions = project.functions.get(match.group(1).lower())
        return functions[0] if functions else None
    return None
