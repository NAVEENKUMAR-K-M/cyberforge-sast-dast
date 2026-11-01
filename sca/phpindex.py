"""Stage 5, part 1: a namespace-aware index of PHP code in the app and its dependencies, and the calls each function makes.

SAST's own PHP project indexes classes by short name, which is right inside one app but not across packages that each
declare a `Parser`. This reuses its parser (tree-sitter, through `SourceFile`) and resolves names the way PHP does:
namespaces, `use` imports, `self`, `parent` and `static`.

A call site resolves to its targets and says whether that resolution is **exact** (one target, no doubt) or only a
**candidate** set (an override might run instead, the method was found by name only, a closure may never be called).
Anything that can't be resolved at all is kept as an unresolved site, never dropped.
"""
from __future__ import annotations

import fnmatch
import os
import posixpath
import sys

_SAST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sast-engine")
if _SAST not in sys.path:
    sys.path.insert(0, _SAST)

from sast.lang.php.project import MAX_FILE_BYTES, SOURCE_EXTS, SourceFile  # noqa: E402

SKIP_DIRS = {"tests", "test", "__tests__", "docs", "doc", "examples", "example", "fixtures", "node_modules", ".git",
             "vendor", "bower_components"}
DECLARATIONS = {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}
NON_EXEC = DECLARATIONS | {"php_tag", "comment", "namespace_definition", "namespace_use_declaration", "function_definition",
                           "const_declaration", "declare_statement", "php_end_tag", "empty_statement", "text"}
NESTED_DECLARATIONS = {"function_definition", "method_declaration"} | DECLARATIONS
NESTED = NESTED_DECLARATIONS | {"anonymous_function", "arrow_function"}
# Builtins that call a callable they're given, and which argument it is.
CALLBACK_FUNCS = {"array_map": 0, "array_filter": 1, "array_walk": 1, "array_walk_recursive": 1, "array_reduce": 1,
                  "usort": 1, "uasort": 1, "uksort": 1, "iterator_apply": 1, "preg_replace_callback": 1,
                  "spl_autoload_register": 0, "register_shutdown_function": 0, "set_error_handler": 0,
                  "set_exception_handler": 0, "call_user_func": 0, "call_user_func_array": 0, "forward_static_call": 0,
                  "forward_static_call_array": 0}
INCLUDES = {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}
PRIMITIVE = {"array", "bool", "callable", "false", "float", "int", "iterable", "mixed", "never", "null", "object",
             "string", "true", "void"}


class Ctx:
    """What names mean in one part of a file: its namespace and `use` imports."""
    __slots__ = ("ns", "classes", "functions")

    def __init__(self, ns: str = ""):
        self.ns, self.classes, self.functions = ns, {}, {}

    def qualify(self, name: str) -> str:
        return f"{self.ns}\\{name}" if self.ns else name


class Func:
    __slots__ = ("key", "label", "name", "cls", "node", "body", "params", "ctx", "sf", "package", "kind", "static",
                 "public", "conditional", "owner", "line", "end_line")

    def __init__(self, kind, label, key, name, cls, node, body, params, ctx, sf, package, line, end_line):
        self.kind, self.label, self.key, self.name, self.cls = kind, label, key, name, cls
        self.node, self.body, self.params, self.ctx, self.sf, self.package = node, body, params, ctx, sf, package
        self.line, self.end_line = line, end_line
        self.static = self.conditional = False
        self.public = True
        self.owner = None


class ClassInfo:
    __slots__ = ("label", "key", "kind", "parents", "interfaces", "traits", "methods", "node", "ctx", "sf", "package",
                 "conditional")

    def __init__(self, label, kind, node, ctx, sf, package):
        self.label, self.key, self.kind, self.node, self.ctx, self.sf = label, label.lower(), kind, node, ctx, sf
        self.package = package
        self.parents, self.interfaces, self.traits, self.methods = [], [], [], {}
        self.conditional = False


class Site:
    """One call. `exact` means a single target with no doubt; otherwise the targets are candidates. `unresolved` is
    "any" when the target could be anything the code can see, or "missing:<package>" when the target names a class of
    that package that isn't in its source."""
    __slots__ = ("line", "text", "targets", "exact", "unresolved", "how", "file")

    def __init__(self, node, targets, exact, how, unresolved=None):
        self.line, self.file = node.line, node.sf.rel
        self.text = " ".join(node.text.split())[:140]
        self.targets, self.exact, self.how, self.unresolved = targets, exact, how, unresolved


def _child(node, *types):
    return next((k for k in node.kids if k.type in types), None)


ESCAPES = {"\\\\": "\\", "\\'": "'", '\\"': '"', "\\$": "$", "\\n": "\n", "\\t": "\t", "\\r": "\r"}


def _str_literal(node):
    """The value of a plain string literal (escapes undone), or None when it holds variables."""
    if node is None:
        return None
    if node.type in ("string", "encapsed_string"):
        if any(k.type not in ("string_content", "string_value", "escape_sequence") for k in node.kids):
            return None
        return "".join(ESCAPES.get(k.text, k.text) if k.type == "escape_sequence" else k.text for k in node.kids)
    return None


class Index:
    def __init__(self, app_root: str):
        self.app_root = os.path.abspath(app_root)
        self.files: dict[str, dict] = {}        # rel -> {"sf", "package", "top", "imports"}
        self.classes: dict[str, list] = {}      # class key -> [ClassInfo]
        self.functions: dict[str, list] = {}    # function key -> [Func]
        self.funcs: dict[str, Func] = {}        # every Func by key
        self.by_name: dict[str, list] = {}      # method name (lower) -> [Func]
        self.children: dict[str, set] = {}      # class key -> keys of classes that extend or implement it
        self.prefixes: list = []                # (namespace prefix lower, package) of analysed packages
        self.skipped: list = []
        self._calls, self._vars, self._props, self._closures = {}, {}, {}, {}

    # ----- loading -----

    def add_tree(self, root: str, package: str, rel_base: str, include=None, exclude_patterns=()):
        """Parses PHP files under `root`. `include` limits it to these paths (autoload dirs and files) when given."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d.lower() not in SKIP_DIRS)
            for name in sorted(filenames):
                if os.path.splitext(name)[1].lower() not in SOURCE_EXTS:
                    continue
                full = os.path.join(dirpath, name)
                inner = os.path.relpath(full, root).replace(os.sep, "/")
                if include is not None and not any(inner == p or inner.startswith(p.rstrip("/") + "/") or p in ("", ".")
                                                   for p in include):
                    continue
                if any(fnmatch.fnmatch("/" + inner, pattern) or fnmatch.fnmatch("/" + inner, pattern.rstrip("/") + "/*")
                       or fnmatch.fnmatch("/" + inner, "*" + pattern.rstrip("/") + "/*") for pattern in exclude_patterns):
                    continue
                self.add_file(full, posixpath.join(rel_base, inner) if rel_base else inner, package)

    def add_file(self, full: str, rel: str, package: str):
        try:
            if os.path.getsize(full) > MAX_FILE_BYTES:
                self.skipped.append(rel)
                return
            with open(full, "rb") as handle:
                data = handle.read()
        except OSError:
            self.skipped.append(rel)
            return
        sf = SourceFile(full, rel, data)
        info = {"sf": sf, "package": package, "imports": set(), "top": None}
        self.files[rel] = info
        statements = []
        self._walk(sf.tree.kids, Ctx(), sf, package, info, statements, conditional=False)
        top = Func("file", f"<{rel}>", f"file:{rel}", "<top-level>", None, sf.tree, statements, None, Ctx(), sf, package,
                   1, len(sf.lines))
        if statements:
            top.ctx = statements[0][1]
        top.body = statements
        info["top"] = top
        self.funcs[top.key] = top

    def _walk(self, nodes, ctx, sf, package, info, statements, conditional):
        for node in nodes:
            kind = node.type
            if kind == "namespace_definition":
                name = node.f("name")
                fresh = Ctx(name.text if name is not None else "")
                body = node.f("body")
                if body is not None:
                    self._walk(body.kids, fresh, sf, package, info, statements, conditional)
                else:
                    ctx = fresh
            elif kind == "namespace_use_declaration":
                self._use(node, ctx, info)
            elif kind in DECLARATIONS:
                self._class(node, ctx, sf, package, conditional)
            elif kind == "function_definition":
                self._function(node, ctx, sf, package, conditional)
            elif kind in ("if_statement", "else_clause", "else_if_clause", "compound_statement", "try_statement",
                          "catch_clause", "finally_clause", "switch_statement", "switch_block", "case_statement",
                          "default_statement", "colon_block"):
                # Declarations inside a condition only exist when it holds (polyfills); statements still run.
                inner = []
                self._walk(node.kids, ctx, sf, package, info, inner, conditional=True)
                statements.append((node, ctx))
            elif kind not in NON_EXEC:
                statements.append((node, ctx))

    def _use(self, node, ctx, info):
        text = node.text.lstrip()
        table = ctx.functions if text.startswith("use function") else None if text.startswith("use const") else ctx.classes
        prefix = ""
        group = node.f("body")
        clauses = [k for k in node.kids if k.type == "namespace_use_clause"]
        if group is not None:
            ns = _child(node, "namespace_name")
            prefix = (ns.text + "\\") if ns is not None else ""
            clauses = [k for k in group.kids if k.type == "namespace_use_clause"]
        for clause in clauses:
            target = _child(clause, "qualified_name", "name")
            if target is None:
                continue
            full = (prefix + target.text).lstrip("\\")
            alias = clause.f("alias")
            if table is not None:
                table[(alias.text if alias is not None else full.split("\\")[-1]).lower()] = full
            info["imports"].add(full)

    def _class(self, node, ctx, sf, package, conditional):
        name = node.f("name")
        if name is None:
            return
        info = ClassInfo(ctx.qualify(name.text), node.type.split("_")[0], node, ctx, sf, package)
        info.conditional = conditional
        for kid in node.kids:
            if kid.type == "base_clause":
                targets = [self.resolve_class(k.text, ctx, None) for k in kid.kids if k.type in ("name", "qualified_name")]
                (info.interfaces if info.kind == "interface" else info.parents).extend(targets)
            elif kid.type == "class_interface_clause":
                info.interfaces.extend(self.resolve_class(k.text, ctx, None) for k in kid.kids if k.type in ("name", "qualified_name"))
        body = node.f("body")
        for kid in body.kids if body is not None else []:
            if kid.type == "use_declaration":
                info.traits.extend(self.resolve_class(k.text, ctx, None) for k in kid.kids if k.type in ("name", "qualified_name"))
            elif kid.type == "method_declaration":
                mname = kid.f("name")
                if mname is None:
                    continue
                label = f"{info.label}::{mname.text}"
                fn = Func("method", label, label.lower(), mname.text, info.label, kid, kid.f("body"), kid.f("parameters"),
                          ctx, sf, package, kid.line, kid.end_line)
                fn.static = _child(kid, "static_modifier") is not None
                visibility = _child(kid, "visibility_modifier")
                fn.public = visibility is None or visibility.text == "public"
                fn.conditional = conditional
                info.methods[mname.text.lower()] = fn
                self.funcs.setdefault(fn.key, fn)
                if fn.body is not None:
                    self.by_name.setdefault(mname.text.lower(), []).append(fn)
        self.classes.setdefault(info.key, []).append(info)
        for parent in info.parents + info.interfaces:
            self.children.setdefault(parent.lower(), set()).add(info.key)

    def _function(self, node, ctx, sf, package, conditional):
        name = node.f("name")
        if name is None:
            return
        label = ctx.qualify(name.text)
        fn = Func("function", label, label.lower(), name.text, None, node, node.f("body"), node.f("parameters"), ctx, sf,
                  package, node.line, node.end_line)
        fn.conditional = conditional
        self.functions.setdefault(fn.key, []).append(fn)
        self.funcs.setdefault(fn.key, fn)

    # ----- names -----

    def resolve_class(self, text: str, ctx: Ctx, decl: str | None) -> str | None:
        text = text.strip()
        low = text.lower()
        if low in ("self", "static"):
            return decl
        if low == "parent":
            info = self.class_info(decl) if decl else None
            return info.parents[0] if info and info.parents else None
        if text.startswith("\\"):
            return text[1:]
        if low.startswith("namespace\\"):
            return ctx.qualify(text[10:])
        first, _, rest = text.partition("\\")
        alias = ctx.classes.get(first.lower())
        if alias:
            return alias + ("\\" + rest if rest else "")
        return ctx.qualify(text)

    def resolve_function(self, text: str, ctx: Ctx) -> Func | None:
        text = text.strip()
        if text.startswith("\\"):
            options = [text[1:]]
        elif "\\" in text:
            first, _, rest = text.partition("\\")
            alias = ctx.classes.get(first.lower())
            options = [alias + "\\" + rest] if alias else [ctx.qualify(text)]
        elif text.lower() in ctx.functions:
            options = [ctx.functions[text.lower()]]
        else:
            options = [ctx.qualify(text), text] if ctx.ns else [text]
        for option in options:
            found = self.functions.get(option.lower())
            if found:
                return found[0]
        return None

    def class_info(self, label: str | None):
        found = self.classes.get(label.lower()) if label else None
        return found[0] if found else None

    def owning_package(self, label: str) -> str | None:
        """The analysed package whose autoload namespace covers this name, even when the class isn't in its source."""
        low = label.lower()
        best = None
        for prefix, package in self.prefixes:
            if low.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
                best = (prefix, package)
        return best[1] if best else None

    # ----- classes -----

    def find_method(self, label: str | None, name: str) -> Func | None:
        """Through the class, its traits and its parents, the way PHP looks a method up."""
        seen, queue = set(), [label]
        name = name.lower()
        while queue:
            current = queue.pop(0)
            if not current or current.lower() in seen:
                continue
            seen.add(current.lower())
            info = self.class_info(current)
            if info is None:
                continue
            if name in info.methods:
                return info.methods[name]
            queue.extend(info.traits)
            queue.extend(info.parents)
            if info.kind == "interface":
                queue.extend(info.interfaces)
        return None

    def ancestors_complete(self, label: str) -> bool:
        seen, queue = set(), [label]
        while queue:
            current = queue.pop()
            if not current or current.lower() in seen:
                continue
            seen.add(current.lower())
            info = self.class_info(current)
            if info is None:
                return False
            queue.extend(info.parents + info.traits)
        return True

    def descendants(self, label: str) -> list:
        out, queue, seen = [], [label.lower()], set()
        while queue:
            for child in sorted(self.children.get(queue.pop(), ())):
                if child not in seen:
                    seen.add(child)
                    out.append(child)
                    queue.append(child)
        return out

    def overrides(self, label: str, name: str) -> list:
        found = []
        for child in self.descendants(label):
            info = self.class_info(child)
            method = info.methods.get(name.lower()) if info else None
            if method is not None and method.body is not None:
                found.append(method)
        return found

    def all_methods(self, label: str, public_only: bool) -> list:
        out, seen, queue, names = [], set(), [label], set()
        while queue:
            current = queue.pop(0)
            if not current or current.lower() in seen:
                continue
            seen.add(current.lower())
            info = self.class_info(current)
            if info is None:
                continue
            for lname, method in sorted(info.methods.items()):
                if lname not in names and method.body is not None and (method.public or not public_only):
                    names.add(lname)
                    out.append(method)
            queue.extend(info.traits + info.parents)
        return out

    def type_labels(self, node, ctx, decl):
        """Class names a type declaration allows, or None when it allows anything that isn't a class."""
        if node is None:
            return None
        if node.type in ("optional_type", "union_type", "intersection_type", "disjunctive_normal_form_type"):
            labels = []
            for kid in node.kids:
                if kid.type == "primitive_type" and kid.text.lower() == "null":
                    continue
                inner = self.type_labels(kid, ctx, decl)
                if inner is None:
                    return None
                labels.extend(inner)
            return labels or None
        if node.type == "named_type":
            name = _child(node, "name", "qualified_name")
            if name is None or name.text.lower() in PRIMITIVE:
                return None
            label = self.resolve_class(name.text, ctx, decl)
            return [label] if label else None
        return None

    def prop_types(self, label: str, prop: str):
        """[(class, exact)] for a property, from its declared type and what the class assigns to it."""
        key = (label.lower(), prop.lower())
        if key in self._props:
            return self._props[key]
        self._props[key] = None
        result, current, seen = None, label, set()
        while current and current.lower() not in seen:
            seen.add(current.lower())
            info = self.class_info(current)
            if info is None:
                break
            declared, news, other = None, [], False
            body = info.node.f("body")
            for kid in body.kids if body is not None else []:
                if kid.type == "property_declaration":
                    for element in kid.kids:
                        if element.type == "property_element":
                            var = element.f("name")
                            if var is not None and var.text.lstrip("$").lower() == prop.lower():
                                declared = self.type_labels(kid.f("type"), info.ctx, info.label) or declared
                elif kid.type == "method_declaration":
                    params = kid.f("parameters")
                    for param in params.kids if params is not None else []:
                        if param.type == "property_promotion_parameter":
                            var = param.f("name")
                            if var is not None and var.text.lstrip("$").lower() == prop.lower():
                                declared = self.type_labels(param.f("type"), info.ctx, info.label)
                                other = True       # set from an argument
                    for assign in self._assignments(kid.f("body")):
                        left, right = assign.f("left"), assign.f("right")
                        if (left is not None and left.type == "member_access_expression" and left.f("object") is not None
                                and left.f("object").text == "$this" and left.f("name") is not None
                                and left.f("name").text.lower() == prop.lower()):
                            made = self._new_class(right, info.ctx, info.label)
                            if made:
                                news.append(made)
                            else:
                                other = True
            if declared or news or other:
                if news and not other:
                    result = [(n, True) for n in sorted(set(news))]
                elif declared:
                    result = [(d, False) for d in declared]
                break
            current = info.parents[0] if info.parents else None
        self._props[key] = result
        return result

    @staticmethod
    def _assignments(body):
        out, stack = [], [body] if body is not None else []
        while stack:
            node = stack.pop()
            if node.type == "assignment_expression":
                out.append(node)
            stack.extend(k for k in node.kids if k.type not in NESTED)
        return out

    def _new_class(self, node, ctx, decl):
        if node is None or node.type != "object_creation_expression":
            return None
        name = _child(node, "name", "qualified_name")
        if name is None or name.text.lower() == "static":
            return None
        return self.resolve_class(name.text, ctx, decl)

    # ----- variables -----

    def _var_writes(self, fn: Func):
        """Every write to each local variable: the assigned expression, or None for a write we can't type."""
        if fn.key in self._vars:
            return self._vars[fn.key]
        writes: dict[str, list] = {}
        if fn.params is not None:
            for param in fn.params.kids:
                var = param.f("name")
                if var is not None:
                    writes.setdefault(var.text.lstrip("$"), []).append(("param", param.f("type")))
        if fn.kind == "closure":
            uses = _child(fn.node, "anonymous_function_use_clause")
            for var in uses.kids if uses is not None else []:
                if var.type == "variable_name":
                    writes.setdefault(var.text.lstrip("$"), []).append(("outer", var.text.lstrip("$")))
        bodies = [n for n, _ in fn.body] if fn.kind == "file" else ([fn.body] if fn.body is not None else [])
        stack = list(bodies)
        while stack:
            node = stack.pop()
            kind = node.type
            if kind == "assignment_expression":
                left = node.f("left")
                if left is not None and left.type == "variable_name":
                    writes.setdefault(left.text.lstrip("$"), []).append(("expr", node.f("right")))
                elif left is not None:
                    for var in self._variables(left):
                        writes.setdefault(var, []).append(("unknown", None))
            elif kind in ("reference_assignment_expression", "augmented_assignment_expression"):
                left = node.f("left")
                for var in self._variables(left) if left is not None else []:
                    writes.setdefault(var, []).append(("unknown", None))
            elif kind == "foreach_statement":
                for kid in node.kids[1:]:
                    if kid.type in ("variable_name", "pair", "list_literal", "by_ref"):
                        for var in self._variables(kid):
                            writes.setdefault(var, []).append(("unknown", None))
            elif kind == "catch_clause":
                var = node.f("name")
                if var is not None:
                    writes.setdefault(var.text.lstrip("$"), []).append(("param", node.f("type")))
            elif kind in ("global_declaration", "static_variable_declaration", "function_static_declaration"):
                for var in self._variables(node):
                    writes.setdefault(var, []).append(("unknown", None))
            if kind not in NESTED:
                stack.extend(node.kids)
        self._vars[fn.key] = writes
        return writes

    @staticmethod
    def _variables(node):
        out, stack = [], [node]
        while stack:
            cur = stack.pop()
            if cur.type == "variable_name":
                out.append(cur.text.lstrip("$"))
            stack.extend(k for k in cur.kids if k.type not in NESTED)
        return out

    def var_types(self, fn: Func, this, name: str, guard=frozenset()):
        if name == "this":
            if this:
                return [(this, True)]
            return [(fn.cls, False)] if fn.cls else None
        writes = self._var_writes(fn).get(name)
        if not writes or (fn.key, name) in guard:
            return None
        guard = guard | {(fn.key, name)}
        types = []
        for kind, value in writes:
            if kind == "param":
                labels = self.type_labels(value, fn.ctx, fn.cls)
                if labels is None:
                    return None
                types.extend((label, False) for label in labels)
            elif kind == "outer":
                outer = self.var_types(fn.owner, this, value, guard) if fn.owner else None
                if outer is None:
                    return None
                types.extend(outer)
            elif kind == "expr":
                got = self.expr_types(value, fn, this, guard)
                if got is None:
                    return None
                types.extend(got)
            else:
                return None
        return sorted(set(types)) or None

    def expr_types(self, node, fn: Func, this, guard=frozenset()):
        """[(class, exact)] the expression can evaluate to, or None when it isn't known."""
        if node is None or len(guard) > 40:
            return None
        kind = node.type
        if kind == "variable_name":
            return self.var_types(fn, this, node.text.lstrip("$"), guard)
        if kind == "object_creation_expression":
            name = _child(node, "name", "qualified_name")
            if name is None:
                return None
            if name.text.lower() == "static":
                return [(this, True)] if this else ([(fn.cls, False)] if fn.cls else None)
            label = self.resolve_class(name.text, fn.ctx, fn.cls)
            return [(label, True)] if label else None
        if kind in ("parenthesized_expression", "clone_expression"):
            return self.expr_types(node.kids[0], fn, this, guard) if node.kids else None
        if kind in ("member_access_expression", "nullsafe_member_access_expression"):
            obj, name = node.f("object"), node.f("name")
            owners = self.expr_types(obj, fn, this, guard) if obj is not None else None
            if owners is None or name is None or name.type != "name":
                return None
            types = []
            for owner, _ in owners:
                got = self.prop_types(owner, name.text)
                if got is None:
                    return None
                types.extend(got)
            return sorted(set(types)) or None
        if kind in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression",
                    "function_call_expression"):
            site = self._resolve_call(node, fn, this, guard)
            if site is None or not site.targets or site.unresolved:
                return None
            types = []
            for target, target_this in site.targets:
                returned = target.node.f("return_type") if target.node is not None else None
                if returned is None:
                    return None
                if returned.type == "named_type" and returned.text.lower() == "static":
                    types.append((target_this, True) if target_this else (target.cls, False))
                    continue
                labels = self.type_labels(returned, target.ctx, target.cls)
                if labels is None:
                    return None
                types.extend((label, False) for label in labels)
            return sorted(set(types)) or None
        return None

    # ----- calls -----

    def closure(self, node, fn: Func) -> Func:
        key = f"closure:{node.sf.rel}:{node.line}:{node.sb}"
        found = self._closures.get(key)
        if found is None:
            body = node.f("body")
            found = Func("closure", f"{{closure}} {node.sf.rel}:{node.line}", key, "{closure}", fn.cls, node, body,
                         node.f("parameters"), fn.ctx, node.sf, fn.package, node.line, node.end_line)
            found.owner = fn
            self._closures[key] = found
            self.funcs[key] = found
        return found

    def calls(self, fn: Func, this) -> list:
        """Every call site in the function's own body (closures are their own functions), resolved."""
        key = (fn.key, this)
        if key in self._calls:
            return self._calls[key]
        sites = []
        if fn.kind == "file":
            roots = [n for n, _ in fn.body]
        elif fn.kind == "closure" and fn.node.type == "arrow_function":
            roots = [fn.body] if fn.body is not None else []
        else:
            roots = [fn.body] if fn.body is not None else []
        stack = list(reversed(roots))
        while stack:
            node = stack.pop()
            kind = node.type
            if kind in ("anonymous_function", "arrow_function"):
                inner = self.closure(node, fn)
                sites.append(Site(node, [(inner, this)], False, "closure (may never be called)"))
                continue
            if kind in NESTED:
                continue
            site = None
            if kind in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression",
                        "function_call_expression", "object_creation_expression") or kind in INCLUDES:
                site = self._resolve_call(node, fn, this, frozenset(), record=True)
            if site is not None:
                sites.append(site)
            stack.extend(reversed(node.kids))
        self._calls[key] = sites
        return sites

    def references(self, fn: Func) -> set:
        """Class and function names the function's code mentions, closures included, resolved. Imports aren't counted
        here."""
        names = set()
        roots = [n for n, _ in fn.body] if fn.kind == "file" else ([fn.body] if fn.body is not None else [])
        if fn.params is not None:
            roots.append(fn.params)
        if fn.node is not None and fn.kind in ("method", "function") and fn.node.f("return_type") is not None:
            roots.append(fn.node.f("return_type"))
        stack = list(roots)
        while stack:
            node = stack.pop()
            kind = node.type
            if kind in ("named_type",):
                for label in self.type_labels(node, fn.ctx, fn.cls) or []:
                    names.add(label)
            elif kind in ("class_constant_access_expression", "scoped_property_access_expression", "scoped_call_expression"):
                scope = node.kids[0] if node.kids else None
                if scope is not None and scope.type in ("name", "qualified_name"):
                    label = self.resolve_class(scope.text, fn.ctx, fn.cls)
                    if label:
                        names.add(label)
            elif kind == "object_creation_expression":
                name = _child(node, "name", "qualified_name")
                if name is not None:
                    label = self.resolve_class(name.text, fn.ctx, fn.cls)
                    if label:
                        names.add(label)
            elif kind == "binary_expression" and node.op == "instanceof" and len(node.kids) == 2:
                if node.kids[1].type in ("name", "qualified_name"):
                    names.add(self.resolve_class(node.kids[1].text, fn.ctx, fn.cls))
            elif kind == "function_call_expression":
                func = node.f("function")
                if func is not None and func.type in ("name", "qualified_name"):
                    target = self.resolve_function(func.text, fn.ctx)
                    if target is not None:
                        names.add(target.label)
            if kind not in NESTED_DECLARATIONS or node in roots:
                stack.extend(node.kids)
        names.discard(None)
        return names

    def _resolve_call(self, node, fn: Func, this, guard, record=False):
        kind = node.type
        if kind == "object_creation_expression":
            return self._new(node, fn, this)
        if kind in INCLUDES:
            return self._include(node, fn) if record else None
        if kind == "function_call_expression":
            return self._function_call(node, fn, this, guard, record)
        name = node.f("name")
        if kind == "scoped_call_expression":
            return self._static_call(node, name, fn, this, guard)
        obj = node.f("object")
        types = self.expr_types(obj, fn, this, guard) if obj is not None else None
        is_this = obj is not None and obj.text == "$this"
        if name is None or name.type != "name":
            if types is None:
                return Site(node, [], False, "dynamic method on an unknown object", unresolved="any")
            targets = [(m, label if exact else None) for label, exact in types
                       for m in self.all_methods(label, public_only=not is_this)]
            return Site(node, targets, False, "dynamic method name: any method of the receiver")
        if types is None:
            targets = [(m, None) for m in self.by_name.get(name.text.lower(), []) if not m.static]
            return Site(node, targets, False, "method found by name only (receiver type unknown)")
        how = "$this" if is_this else "receiver created with new" if all(exact for _, exact in types) else "typed receiver"
        return self._dispatch(node, types, name.text, how, fn)

    def _dispatch(self, node, types, mname, how, fn):
        targets, doubt, missing = [], len(types) > 1, None
        for label, exact in types:
            method = self.find_method(label, mname)
            if method is not None and method.body is not None:
                targets.append((method, label if exact else None))
            if not exact:
                extra = self.overrides(label, mname)
                doubt = doubt or bool(extra)
                targets.extend((m, None) for m in extra)
            if method is None:
                magic = self.find_method(label, "__call")
                if magic is not None and magic.body is not None:
                    targets.append((magic, label if exact else None))
                    doubt = True
                elif self.class_info(label) is None and self.owning_package(label):
                    missing = self.owning_package(label)
        unique = list({(t.key, th): (t, th) for t, th in targets}.values())
        if missing and not unique:
            return Site(node, [], False, how, unresolved=f"missing:{missing}")
        exact = len(unique) == 1 and not doubt and not any(t.conditional for t, _ in unique)
        return Site(node, unique, exact, how)

    def _new(self, node, fn, this):
        name = _child(node, "name", "qualified_name")
        if name is None:
            how = "anonymous class" if _child(node, "declaration_list") is not None or "class" in node.text[:12] else "dynamic class name"
            return Site(node, [], False, how, unresolved="any")
        if name.text.lower() == "static":
            if this:
                types = [(this, True)]
            else:
                types = [(fn.cls, False)] if fn.cls else []
        else:
            label = self.resolve_class(name.text, fn.ctx, fn.cls)
            types = [(label, True)] if label else []
        if not types:
            return Site(node, [], False, "new", unresolved="any")
        label = types[0][0]
        if self.class_info(label) is None:
            owner = self.owning_package(label)
            return Site(node, [], False, "new", unresolved=f"missing:{owner}") if owner else None
        site = self._dispatch(node, types, "__construct", "new", fn)
        site.how = "new"
        return site

    def _static_call(self, node, name, fn, this, guard):
        scope = node.f("scope")
        if scope is None:
            return None
        if scope.type == "relative_scope":
            word = scope.text.lower()
            if word == "static":
                types = [(this, True)] if this else ([(fn.cls, False)] if fn.cls else None)
                how = "static::"
            else:
                label = fn.cls if word == "self" else self.resolve_class("parent", fn.ctx, fn.cls)
                if label is None:
                    return None
                method = self.find_method(label, name.text) if name is not None and name.type == "name" else None
                if method is None or method.body is None:
                    if name is None or name.type != "name":
                        return Site(node, [], False, "dynamic static method", unresolved="any")
                    owner = self.owning_package(label) if self.class_info(label) is None else None
                    return Site(node, [], False, f"{word}::", unresolved=f"missing:{owner}") if owner else None
                return Site(node, [(method, this)], not method.conditional, f"{word}::")
        elif scope.type in ("name", "qualified_name"):
            label = self.resolve_class(scope.text, fn.ctx, fn.cls)
            types = [(label, True)] if label else None
            how = "static call"
            if label and self.class_info(label) is None:
                owner = self.owning_package(label)
                return Site(node, [], False, how, unresolved=f"missing:{owner}") if owner else None
        else:
            types = self.expr_types(scope, fn, this, guard)
            how = "static call on an object"
        if types is None:
            return Site(node, [], False, "static call on an unknown class", unresolved="any")
        if name is None or name.type != "name":
            targets = [(m, label) for label, _ in types for m in self.all_methods(label, public_only=True)]
            return Site(node, targets, False, "dynamic static method name")
        return self._dispatch(node, types, name.text, how, fn)

    def _function_call(self, node, fn, this, guard, record):
        func = node.f("function")
        if func is None or func.type not in ("name", "qualified_name", "relative_name"):
            if self._holds_closures(fn, func):
                return None          # calls a closure this function made; the closure is already a candidate
            return Site(node, [], False, "dynamic function call", unresolved="any") if record else None
        short = func.text.split("\\")[-1].lower()
        target = self.resolve_function(func.text, fn.ctx)
        if target is not None:
            return Site(node, [(target, None)], not target.conditional, "function")
        if record and short in CALLBACK_FUNCS:
            return self._callbacks(node, fn, this, short)
        return None

    def _holds_closures(self, fn, value) -> bool:
        """A local variable that is only ever assigned closures written in this function."""
        if value is None or value.type != "variable_name":
            return False
        writes = self._var_writes(fn).get(value.text.lstrip("$"), [])
        return bool(writes) and all(k == "expr" and v is not None and v.type in ("anonymous_function", "arrow_function")
                                    for k, v in writes)

    def _callbacks(self, node, fn, this, short):
        """A callable handed to call_user_func or array_map runs code no call names directly."""
        args = node.f("arguments")
        values = [a.kids[0] for a in (args.kids if args is not None else []) if a.type == "argument" and a.kids]
        position = CALLBACK_FUNCS[short]
        values = values[position:position + 1]
        targets, unresolved = [], None
        for value in values:
            if value.type in ("anonymous_function", "arrow_function") or self._holds_closures(fn, value):
                continue                              # a closure node handles it
            literal = _str_literal(value)
            if literal is not None:
                if "::" in literal:
                    cls, _, method = literal.partition("::")
                    found = self.find_method(self.resolve_class(cls, Ctx(), fn.cls), method)
                else:
                    found = self.resolve_function("\\" + literal.lstrip("\\"), fn.ctx)
                if found is not None:
                    targets.append((found, None))
                continue
            if value.type == "array_creation_expression":
                items = [k.kids[0] for k in value.kids if k.type == "array_element_initializer" and k.kids]
                if len(items) == 2 and _str_literal(items[1]) is not None:
                    method = _str_literal(items[1])
                    owner = items[0]
                    if owner.type == "class_constant_access_expression" and owner.kids:
                        types = [(self.resolve_class(owner.kids[0].text, fn.ctx, fn.cls), False)]
                    elif _str_literal(owner) is not None:
                        types = [(self.resolve_class(_str_literal(owner), Ctx(), fn.cls), False)]
                    else:
                        types = self.expr_types(owner, fn, this)
                    if types:
                        for label, exact in types:
                            found = self.find_method(label, method)
                            if found is not None:
                                targets.append((found, label if exact else None))
                        continue
            unresolved = "any"        # a callable we can't read: anything the code can see could run
        return Site(node, targets, False, f"callable passed to {short}", unresolved=unresolved)

    def _include(self, node, fn):
        expr = node.kids[0] if node.kids else None
        path = self._eval_path(expr, fn.sf)
        if path is None:
            return Site(node, [], False, "dynamic include", unresolved="any")
        if path.replace("\\", "/").endswith("vendor/autoload.php"):
            return Site(node, [], True, "autoload")
        base = os.path.dirname(fn.sf.path)
        full = os.path.normpath(path if os.path.isabs(path) else os.path.join(base, path))
        rel = os.path.relpath(full, self.app_root).replace(os.sep, "/")
        info = self.files.get(rel)
        if info is None:
            return None
        return Site(node, [(info["top"], None)], True, "include")

    def _eval_path(self, node, sf):
        if node is None:
            return None
        kind = node.type
        if kind == "parenthesized_expression" and node.kids:
            return self._eval_path(node.kids[0], sf)
        literal = _str_literal(node)
        if literal is not None:
            return literal
        if kind == "name" and node.text == "__DIR__":
            return os.path.dirname(sf.path)
        if kind == "name" and node.text == "__FILE__":
            return sf.path
        if kind == "binary_expression" and node.op == "." and len(node.kids) == 2:
            left, right = self._eval_path(node.kids[0], sf), self._eval_path(node.kids[1], sf)
            return left + right if left is not None and right is not None else None
        if kind == "function_call_expression" and node.f("function") is not None and node.f("function").text == "dirname":
            args = node.f("arguments")
            values = [a.kids[0] for a in (args.kids if args is not None else []) if a.type == "argument" and a.kids]
            inner = self._eval_path(values[0], sf) if values else None
            levels = int(values[1].text) if len(values) > 1 and values[1].text.isdigit() else 1
            if inner is None:
                return None
            for _ in range(levels):
                inner = os.path.dirname(inner)
            return inner
        return None
