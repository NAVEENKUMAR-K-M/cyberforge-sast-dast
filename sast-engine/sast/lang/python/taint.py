"""Follows request input through a Python app's functions to the calls where it does harm.

An abstract interpreter over the standard `ast`: it runs each route handler with its parameters marked as
input, inlines the project's own functions and methods, and records an observation (a Hit) wherever a value
that came from a visitor reaches a dangerous call. A Hit carries the reason when something protects it, so
the safe cases stay visible instead of vanishing.
"""
from __future__ import annotations

import ast
import re
import string

from sast.core.model import Param

from . import rules, templates
from .project import FuncDef, Project, PyFile, dotted
from .values import EMPTY, MAX_STR_LEN, MAX_STRS, Comp, Instance, Taint, Val, union

MAX_DEPTH = 7
ENTRY_BUDGET = 40_000
BUILTIN_PASSTHROUGH = {"str", "repr", "bytes", "bytearray", "list", "dict", "tuple", "set", "frozenset", "sorted", "reversed",
                       "iter", "next", "enumerate", "zip", "map", "filter", "min", "max", "format", "ascii", "vars", "getattr"}
MUTATORS = {"append", "extend", "add", "update", "insert", "setdefault", "appendleft"}
EXIT_CALLS = {"abort", "exit", "sys.exit", "os._exit", "flask.abort", "quit"}
_PERCENT = re.compile(r"%(?:\((\w+)\))?[-#0 +]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]?([sdiouxXeEfFgGcrab%])")
_NUMERIC_SPEC = re.compile(r"[bdoxXneEfFgG%]$")


class Budget(Exception):
    pass


class Hit:
    __slots__ = ("cwe", "file", "line", "func", "expr", "sink", "taint", "reason", "routes", "sink_step", "conditions")

    def __init__(self, cwe, file, line, func, expr, sink, taint, reason, routes):
        self.cwe, self.file, self.line, self.func, self.expr, self.sink = cwe, file, line, func, expr, sink
        self.taint, self.reason, self.routes = taint, reason, routes
        self.sink_step = (file, line, sink)
        self.conditions: list = []


class Frame:
    __slots__ = ("sf", "fd", "env", "routes", "label", "returns", "handler")

    def __init__(self, sf, fd, env, routes, label, handler=None):
        self.sf, self.fd, self.env, self.routes, self.label = sf, fd, env, routes, label
        self.returns: list = []
        self.handler = handler


def terminates(stmts) -> bool:
    """Whether control can never fall out of the end of these statements."""
    for stmt in stmts:
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            name = dotted(stmt.value.func) or ""
            if name in EXIT_CALLS or name.split(".")[-1] in {"abort", "exit"}:
                return True
        if isinstance(stmt, ast.If) and stmt.orelse and terminates(stmt.body) and terminates(stmt.orelse):
            return True
        if isinstance(stmt, ast.Try) and terminates(stmt.body) and all(terminates(h.body) for h in stmt.handlers):
            return True
    return False


def source_text(node, limit=160) -> str:
    try:
        text = ast.unparse(node)
    except Exception:  # an odd node is not worth stopping the scan
        text = type(node).__name__
    return text if len(text) <= limit else text[:limit] + "..."


class Interpreter:
    def __init__(self, project: Project, route_map):
        self.project, self.route_map = project, route_map
        self.hits: list[Hit] = []
        self._hit_index: dict = {}
        self.stored: dict[str, dict] = {}
        self.module_envs: dict[str, dict] = {}
        self.executed_funcs: set = set()
        self.memo: dict = {}
        self.stack: list = []
        self.closure_env: dict = {}
        self.work = 0
        self.budget_hits = 0
        self.fd_by_node = {id(fd.node): fd for defs in project.defs_by_file.values() for fd in defs}
        self._const_collections: dict = {}
        self.REQUEST = Val(request=True)
        self.templates = templates.TemplateIndex(project)

    # ---- entry points --------------------------------------------------------------------------------------------

    def new_pass(self):
        self.hits, self._hit_index, self.memo, self.executed_funcs = [], {}, {}, set()

    def stored_count(self) -> int:
        return sum(len(entries) for entries in self.stored.values())

    def run_handler(self, handler):
        fd = handler.fd
        env: dict = {}
        for var, seed in handler.seeds.items():
            env[var] = self._seed_value(fd, seed, handler.view)
        fr = Frame(fd.file, fd, env, [handler.view], fd.label, handler)
        self._run_entry(fd, fr)

    def run_generic(self, gr) -> None:
        """A generic view does its work in Django's code: a CreateView stores the fields it was configured with, and a
        ListView shows the model's rows through a template. This acts that out from the class attributes."""
        g, view = gr.g, gr.view
        info, model = g.info, g.model
        if model is None:
            return
        fr = Frame(info.file, None, {}, [view], info.name)
        node = info.node
        if g.kind in ("create", "update") and g.fields:
            carried = []
            for name in g.fields:
                carried.extend(self.source(fr, node, name, "body", numeric=name in g.typed).all_taints())
            self.write_stored(fr, node, "orm:" + model.name, carried)
        if g.kind not in ("list", "detail", "update", "create", "delete"):
            return
        app = model.file.rel.rsplit("/", 1)[0] if "/" in model.file.rel else ""
        suffix = {"list": "list", "detail": "detail"}.get(g.kind, "form")
        candidates = [g.template_name] if g.template_name else [f"{app}/{model.name.lower()}_{suffix}.html".lstrip("/")]
        lowered = model.name.lower()
        names = set(g.context_names) | ({"object_list", f"{lowered}_list"} if g.kind == "list" else {"object", lowered, "form"})
        for template in candidates:
            info_t = self.templates.get(template) if template else None
            if info_t is None:
                continue
            tables = frozenset(self.orm_aliases("orm:" + model.name))
            rows = self.read_stored(fr, node, Val(tables=tables))
            for name in sorted(info_t.unescaped & names):
                self.sink(fr, node, 79, Val(taints=rows.taints), f"{template} prints {name} without escaping it")

    def _seed_value(self, fd, seed, route) -> Val:
        if seed.kind == "request":
            return self.REQUEST
        if seed.kind == "form":
            values = {name: self._seed_value(fd, inner, route) for name, inner in seed.fields.items()}
            form = Instance(fd.cls)
            form.attrs["cleaned_data"] = Val(fields=values)
            form.attrs["instance"] = Val(fields=values)
            return Val(obj=form, fields=values)
        if seed.kind == "view":
            view = Instance(fd.cls)
            view.attrs["request"] = self.REQUEST
            view.attrs["kwargs"] = Val(fields={name: self._seed_value(fd, inner, route) for name, inner in seed.fields.items()})
            view.attrs["args"] = EMPTY
            return Val(obj=view)
        if seed.kind == "model":
            fields = {}
            for var, inner in seed.fields.items():
                fields[var] = self._seed_value(fd, inner, route)
            return Val(fields=fields)
        step = (fd.file.rel, fd.node.lineno, f"{seed.location} parameter {seed.name} of handler {fd.label}()")
        taint = Taint(seed.name, seed.location, (step,))
        if seed.numeric:
            taint = taint.sanitized("int")
        return Val.of(taint)

    def run_unreached(self):
        """Analyses code no route runs, so its findings can be marked unreachable."""
        for sf in self.project.files.values():
            self.module_env(sf)
        for defs in self.project.defs_by_file.values():
            for fd in defs:
                if fd.id in self.executed_funcs:
                    continue
                env = {name: EMPTY for name in fd.params}
                fr = Frame(fd.file, fd, env, [], fd.label)
                if fd.cls is not None and fd.params:
                    fr.env[fd.params[0]] = Val(obj=Instance(fd.cls))
                self._run_entry(fd, fr)

    def _run_entry(self, fd, fr):
        self.work = 0
        self.stack.append(fd.id)
        try:
            self.executed_funcs.add(fd.id)
            self.exec_block(fd.node.body, fr)
        except Budget:
            self.budget_hits += 1
        finally:
            self.stack.pop()

    # ---- modules -------------------------------------------------------------------------------------------------

    def module_env(self, sf: PyFile) -> dict:
        got = self.module_envs.get(sf.rel)
        if got is not None:
            return got
        env: dict = {}
        self.module_envs[sf.rel] = env  # set first: modules that import each other must not loop
        fr = Frame(sf, None, env, [], "<module>")
        saved = self.work
        self.work = 0
        try:
            self.exec_block(sf.tree.body, fr)
        except Budget:
            self.budget_hits += 1
        finally:
            self.work = saved
        return env

    # ---- statements ----------------------------------------------------------------------------------------------

    def exec_block(self, stmts, fr):
        for stmt in stmts:
            self.work += 1
            if self.work > ENTRY_BUDGET:
                raise Budget()
            method = getattr(self, "s_" + type(stmt).__name__, None)
            if method is not None:
                method(stmt, fr)

    def s_Expr(self, stmt, fr):
        self.eval(stmt.value, fr)

    def s_Assign(self, stmt, fr):
        value = self.eval(stmt.value, fr)
        for target in stmt.targets:
            self.assign(target, value, fr, stmt)

    def s_AnnAssign(self, stmt, fr):
        if stmt.value is not None:
            self.assign(stmt.target, self.eval(stmt.value, fr), fr, stmt)

    def s_AugAssign(self, stmt, fr):
        right = self.eval(stmt.value, fr)
        left = self.eval(stmt.target, fr)
        if isinstance(stmt.op, ast.Add):
            value = self.concat(left, right, fr, stmt)
        else:
            value = union(left.flat(), right.flat())
        self.assign(stmt.target, value, fr, stmt)

    def s_Return(self, stmt, fr):
        if stmt.value is None:
            return
        value = self.eval(stmt.value, fr)
        fr.returns.append(value)
        if fr.handler is not None:
            self.check_response(fr, stmt, value)

    def s_If(self, stmt, fr):
        self.eval(stmt.test, fr)
        on_true, on_false = self.guards(stmt.test, fr)
        base = fr.env
        fr.env = self.guarded(base, on_true)
        self.exec_block(stmt.body, fr)
        after_body, body_exits = fr.env, terminates(stmt.body)
        fr.env = self.guarded(base, on_false)
        self.exec_block(stmt.orelse, fr)
        after_else, else_exits = fr.env, terminates(stmt.orelse)
        live = [env for env, exits in ((after_body, body_exits), (after_else, else_exits)) if not exits]
        fr.env = self.merge_envs(live) if live else after_body

    def s_Assert(self, stmt, fr):
        self.eval(stmt.test, fr)
        on_true, _ = self.guards(stmt.test, fr)
        fr.env = self.guarded(fr.env, on_true)

    def s_For(self, stmt, fr):
        element = self.element_of(self.eval(stmt.iter, fr))
        for _ in range(2):  # a second turn lets a value set late in the loop reach the top of it
            self.assign(stmt.target, element, fr, stmt)
            self.exec_block(stmt.body, fr)
        self.exec_block(stmt.orelse, fr)

    s_AsyncFor = s_For

    def s_While(self, stmt, fr):
        self.eval(stmt.test, fr)
        for _ in range(2):
            self.exec_block(stmt.body, fr)
        self.exec_block(stmt.orelse, fr)

    def s_With(self, stmt, fr):
        for item in stmt.items:
            value = self.eval(item.context_expr, fr)
            if item.optional_vars is not None:
                self.assign(item.optional_vars, value, fr, stmt)
        self.exec_block(stmt.body, fr)

    s_AsyncWith = s_With

    def s_Try(self, stmt, fr):
        before = dict(fr.env)
        self.exec_block(stmt.body, fr)
        after_body = fr.env
        outcomes = [after_body] if not terminates(stmt.body) else []
        for handler in stmt.handlers:
            fr.env = self.merge_envs([before, after_body])
            if handler.name:
                fr.env[handler.name] = EMPTY
            self.exec_block(handler.body, fr)
            if not terminates(handler.body):
                outcomes.append(fr.env)
        if stmt.orelse:
            fr.env = after_body
            self.exec_block(stmt.orelse, fr)
            outcomes.append(fr.env)
        fr.env = self.merge_envs(outcomes) if outcomes else after_body
        self.exec_block(stmt.finalbody, fr)

    s_TryStar = s_Try

    def s_Match(self, stmt, fr):
        subject = self.eval(stmt.subject, fr)
        base = fr.env
        outcomes = []
        for case in stmt.cases:
            fr.env = dict(base)
            for name in _pattern_names(case.pattern):
                fr.env[name] = subject.flat()
            self.exec_block(case.body, fr)
            outcomes.append(fr.env)
        fr.env = self.merge_envs(outcomes + [base])

    def s_FunctionDef(self, stmt, fr):
        fd = self.fd_by_node.get(id(stmt))
        if fd is None:
            return
        fr.env[stmt.name] = Val(func=fd)
        self.closure_env[fd.id] = fr.env

    s_AsyncFunctionDef = s_FunctionDef

    def s_ClassDef(self, stmt, fr):
        info = fr.sf.top_classes.get(stmt.name)
        if info is not None and info.node is stmt:
            fr.env[stmt.name] = Val(cls=info)

    def merge_envs(self, envs) -> dict:
        if len(envs) == 1:
            return dict(envs[0])
        out: dict = {}
        for name in sorted({n for env in envs for n in env}):
            vals = [env[name] for env in envs if name in env]
            out[name] = vals[0] if all(v is vals[0] for v in vals) else union(*vals)
        return out

    def guarded(self, env, guards) -> dict:
        out = dict(env)
        for name, label in guards:
            if name not in out:
                continue
            if label == "path_guard":
                out[name] = out[name].map_taints(lambda t: t.sanitized("path_real") if "resolved" in t.san else t)
            else:
                out[name] = out[name].map_taints(lambda t, label=label: t.sanitized(label))
        return out

    # ---- assignment ----------------------------------------------------------------------------------------------

    def assign(self, target, value, fr, stmt):
        if isinstance(target, ast.Name):
            fr.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for index, item in enumerate(target.elts):
                if isinstance(item, ast.Starred):
                    self.assign(item.value, value.flat(), fr, stmt)
                    continue
                part = value.fields.get(str(index)) if value.fields else None
                self.assign(item, part if part is not None else self.element_of(value), fr, stmt)
        elif isinstance(target, ast.Attribute):
            owner = self.eval(target.value, fr)
            if owner.obj is not None:
                owner.obj.attrs[target.attr] = value
            elif target.attr in ("mimetype", "content_type") and isinstance(target.value, ast.Name)                     and self._is_non_html_type(getattr(stmt, "value", None)):
                fr.env[target.value.id] = owner.derive(resp="other")  # resp.mimetype = "application/json"
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute) and target.value.attr == "headers"                 and isinstance(target.value.value, ast.Name) and str(_const(target.slice)).lower() == "content-type"                 and self._is_non_html_type(getattr(stmt, "value", None)):
            owner = self.eval(target.value.value, fr)
            fr.env[target.value.value.id] = owner.derive(resp="other")  # resp.headers["Content-Type"] = "application/json"
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            current = fr.env.get(target.value.id, EMPTY)
            key = _const(target.slice)
            if current.fields is not None and isinstance(key, str):
                fields = dict(current.fields)
                fields[key] = value
                fr.env[target.value.id] = current.derive(fields=fields)
            else:
                fr.env[target.value.id] = union(current, value.flat())
        elif isinstance(target, ast.Starred):
            self.assign(target.value, value, fr, stmt)

    @staticmethod
    def _is_non_html_type(node) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(rules.NON_HTML_TYPE.search(node.value))

    def element_of(self, value: Val) -> Val:
        """What iterating over a value hands out."""
        if value.bag:
            return Val(taints={t.key: t for t in value.all_taints()})
        flat = value.flat()
        return Val(taints=flat.taints, strs=frozenset(), tables=flat.tables, kind=flat.kind)

    # ---- guards --------------------------------------------------------------------------------------------------

    def guards(self, test, fr):
        """(names protected when the test is true, names protected when it is false), as (name, label)."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            true_set, false_set = self.guards(test.operand, fr)
            return false_set, true_set
        if isinstance(test, ast.BoolOp):
            parts = [self.guards(v, fr) for v in test.values]
            if isinstance(test.op, ast.And):
                return [g for t, _ in parts for g in t], []
            return [], [g for _, f in parts for g in f]
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name):
            op, right = test.ops[0], test.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)) and self.is_constant_collection(right, fr):
                found = [(test.left.id, "allowlist")]
                return (found, []) if isinstance(op, ast.In) else ([], found)
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(right, ast.Constant):
                found = [(test.left.id, "allowlist")]
                return (found, []) if isinstance(op, ast.Eq) else ([], found)
            return [], []
        if isinstance(test, ast.Call):
            return self.call_guard(test, fr), []
        return [], []

    def call_guard(self, call, fr):
        func = call.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            name = func.value.id
            if func.attr in ("isdigit", "isnumeric", "isdecimal"):
                return [(name, "int")]
            if func.attr in ("isalnum", "isalpha", "isidentifier"):
                return [(name, "allowlist")]
            if func.attr in ("startswith", "is_relative_to"):
                return [(name, "path_guard")]
        qual = self.qualify(fr, func) or dotted(func) or ""
        tail = qual.split(".")[-1]
        if qual in ("re.match", "re.fullmatch", "re.search") and len(call.args) >= 2 and isinstance(call.args[1], ast.Name):
            pattern = call.args[0]
            if isinstance(pattern, ast.Constant) and isinstance(pattern.value, str) and _safe_regex(pattern.value, tail):
                return [(call.args[1].id, "allowlist")]
        if tail in ("is_safe_url", "url_has_allowed_host_and_scheme", "is_safe_redirect", "is_safe_redirect_url") and call.args \
                and isinstance(call.args[0], ast.Name):
            return [(call.args[0].id, "allowlist")]
        if qual == "isinstance" and len(call.args) == 2 and isinstance(call.args[0], ast.Name):
            kinds = {dotted(n) for n in (call.args[1].elts if isinstance(call.args[1], ast.Tuple) else [call.args[1]])}
            if kinds and kinds <= {"int", "float", "bool"}:
                return [(call.args[0].id, "int")]
        return []

    def is_constant_collection(self, node, fr) -> bool:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(isinstance(e, ast.Constant) for e in node.elts)
        if isinstance(node, ast.Dict):
            return all(isinstance(k, ast.Constant) for k in node.keys if k is not None)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("keys", "values"):
            return self.is_constant_collection(node.func.value, fr)
        if isinstance(node, ast.Name):
            key = (fr.sf.rel, node.id)
            if key not in self._const_collections:
                self._const_collections[key] = self._find_constant_collection(fr.sf, node.id)
            return self._const_collections[key]
        return False

    def _find_constant_collection(self, sf, name) -> bool:
        for stmt in sf.tree.body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                v = stmt.value
                if isinstance(v, (ast.List, ast.Tuple, ast.Set)):
                    return all(isinstance(e, ast.Constant) for e in v.elts)
                if isinstance(v, ast.Dict):
                    return all(isinstance(k, ast.Constant) for k in v.keys if k is not None)
                if isinstance(v, ast.Call) and (dotted(v.func) or "") in ("frozenset", "set", "tuple", "list") and v.args:
                    inner = v.args[0]
                    return isinstance(inner, (ast.List, ast.Tuple, ast.Set)) and all(isinstance(e, ast.Constant) for e in inner.elts)
        return False

    # ---- expressions ---------------------------------------------------------------------------------------------

    def eval(self, node, fr) -> Val:
        self.work += 1
        if self.work > ENTRY_BUDGET:
            raise Budget()
        method = getattr(self, "e_" + type(node).__name__, None)
        return method(node, fr) if method is not None else EMPTY

    def e_Constant(self, node, fr):
        if isinstance(node.value, str):
            return Val.lit(node.value)
        if isinstance(node.value, bytes):
            return Val.lit(node.value.decode("utf-8", "replace"))
        return EMPTY

    def e_Name(self, node, fr):
        got = fr.env.get(node.id)
        if got is not None:
            return got
        if fr.fd is not None and fr.fd.parent is not None:
            outer = self.closure_env.get(fr.fd.id)
            if outer is not None and node.id in outer:
                return outer[node.id]
        module = self.module_env(fr.sf)
        if node.id in module:
            return module[node.id]
        if self.qualify(fr, node) in rules.REQUEST_QUALIFIED:
            return self.REQUEST
        imported = fr.sf.imports.get(node.id)
        if imported:
            target = self.project.resolve_dotted(fr.sf, node.id)
            if target and target[0] == "var" and target[1] is not fr.sf:
                return self.module_env(target[1]).get(target[2], EMPTY)
            if target and target[0] == "func":
                return Val(func=target[1])
            if target and target[0] == "class":
                return Val(cls=target[1])
        else:
            local = fr.sf.top_funcs.get(node.id)
            if local is not None:
                return Val(func=local)
            info = fr.sf.top_classes.get(node.id)
            if info is not None:
                return Val(cls=info)
        return EMPTY

    def e_Attribute(self, node, fr):
        if self.qualify(fr, node) in rules.REQUEST_QUALIFIED:
            return self.REQUEST
        base = self.eval(node.value, fr)
        attr = node.attr
        if base.request:
            if attr in rules.REQUEST_RAW:  # the body as one value, not a collection of named fields
                return self.source(fr, node, "*", rules.REQUEST_ATTRS[attr])
            if attr in rules.REQUEST_ATTRS:
                return Val(bag=rules.REQUEST_ATTRS[attr])
            if attr in rules.REQUEST_PATH_ATTRS:
                return self.source(fr, node, attr, "path")
            return EMPTY
        if base.obj is not None:
            return base.obj.attrs.get(attr, EMPTY)
        if base.fields and attr in base.fields:
            return base.fields[attr]
        if base.kind == "path" and attr in ("name", "stem"):
            return base.map_taints(lambda t: t.sanitized("path_base")).derive(kind=None)
        if base.cls is not None:
            if attr == "objects":  # Django: the manager of a model, which is where its rows are read and written
                return Val(tables=frozenset({"orm:" + base.cls.name}), kind="manager")
            return EMPTY
        if base is EMPTY or (not base.tainted and not base.bag):
            name = dotted(node)
            target = self.project.resolve_dotted(fr.sf, name) if name else None
            if target and target[0] == "var" and target[1] is not fr.sf:
                return self.module_env(target[1]).get(target[2], EMPTY)
            return EMPTY if not base.strs else base.derive(strs=frozenset())
        return base.derive(strs=frozenset(), bag=None, kind=base.kind if base.kind == "path" else None)

    def e_Subscript(self, node, fr):
        base = self.eval(node.value, fr)
        key = _const(node.slice)
        if not isinstance(node.slice, ast.Slice):
            self.eval(node.slice, fr)
        if base.bag:
            return self.source(fr, node, key if isinstance(key, str) else "*", base.bag, required=True)
        if base.request:
            return EMPTY
        if base.fields is not None and key is not None and str(key) in base.fields:
            return base.fields[str(key)]
        if base.fields is not None:
            return base.flat().derive(strs=frozenset())
        return self.named(base.derive(strs=frozenset(), bag=None), key, fr, required=True)

    def e_Tuple(self, node, fr):
        fields = {}
        for index, elt in enumerate(node.elts):
            fields[str(index)] = self.eval(elt.value, fr).flat() if isinstance(elt, ast.Starred) else self.eval(elt, fr)
        return Val(fields=fields)

    e_List = e_Tuple
    e_Set = e_Tuple

    def e_Dict(self, node, fr):
        fields = {}
        for key, value in zip(node.keys, node.values):
            v = self.eval(value, fr)
            if key is None:
                for name, inner in (v.fields or {}).items():
                    fields[name] = inner
                continue
            k = _const(key)
            fields[str(k) if k is not None else f"?{len(fields)}"] = v
        return Val(fields=fields)

    def e_JoinedStr(self, node, fr):
        pieces = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                pieces.append(("lit", str(part.value)))
            elif isinstance(part, ast.FormattedValue):
                spec = ""
                if isinstance(part.format_spec, ast.JoinedStr):
                    spec = "".join(str(p.value) for p in part.format_spec.values if isinstance(p, ast.Constant))
                pieces.append(("val", self.eval(part.value, fr), bool(spec and _NUMERIC_SPEC.search(spec))))
        return self.build(pieces, fr, node)

    def e_BinOp(self, node, fr):
        if isinstance(node.op, ast.Add):
            return self.concat(self.eval(node.left, fr), self.eval(node.right, fr), fr, node)
        if isinstance(node.op, ast.Mod):
            return self.percent_format(node, fr)
        left, right = self.eval(node.left, fr), self.eval(node.right, fr)
        if isinstance(node.op, ast.Div) and left.kind == "path":  # Path / "name"
            return self.concat(left, right, fr, node).derive(kind="path")
        return union(left.flat(), right.flat()).derive(strs=frozenset())

    def e_BoolOp(self, node, fr):
        return union(*[self.eval(v, fr) for v in node.values])

    def e_UnaryOp(self, node, fr):
        value = self.eval(node.operand, fr)
        return EMPTY if isinstance(node.op, ast.Not) else value

    def e_Compare(self, node, fr):
        self.eval(node.left, fr)
        for c in node.comparators:
            self.eval(c, fr)
        return EMPTY

    def e_IfExp(self, node, fr):
        self.eval(node.test, fr)
        on_true, on_false = self.guards(node.test, fr)
        saved = fr.env
        fr.env = self.guarded(saved, on_true)
        body = self.eval(node.body, fr)
        fr.env = self.guarded(saved, on_false)
        orelse = self.eval(node.orelse, fr)
        fr.env = saved
        return union(body, orelse)

    def e_Await(self, node, fr):
        return self.eval(node.value, fr)

    def e_Starred(self, node, fr):
        return self.eval(node.value, fr).flat()

    def e_NamedExpr(self, node, fr):
        value = self.eval(node.value, fr)
        self.assign(node.target, value, fr, node)
        return value

    def e_Yield(self, node, fr):
        return self.eval(node.value, fr) if node.value is not None else EMPTY

    def _comprehension(self, node, fr, parts):
        saved = fr.env
        fr.env = dict(saved)
        try:
            for gen in node.generators:
                self.assign(gen.target, self.element_of(self.eval(gen.iter, fr)), fr, node)
                for cond in gen.ifs:
                    self.eval(cond, fr)
            return union(*[self.eval(p, fr).flat() for p in parts]).derive(strs=frozenset())
        finally:
            fr.env = saved

    def e_ListComp(self, node, fr):
        return self._comprehension(node, fr, [node.elt])

    e_SetComp = e_ListComp
    e_GeneratorExp = e_ListComp

    def e_DictComp(self, node, fr):
        return self._comprehension(node, fr, [node.value])

    # ---- building strings ----------------------------------------------------------------------------------------

    def build(self, pieces, fr, node) -> Val:
        """Joins literal text and values, noting the text in front of each input and what the result may read as."""
        strs = {""}
        taints: dict = {}
        comp = Comp(fr.sf.rel, getattr(node, "lineno", 0), fr.label, source_text(node, 200))
        for piece in pieces:
            if piece[0] == "lit":
                strs = _cap({s + piece[1] for s in strs})
                continue
            val, numeric = piece[1], piece[2]
            prefix = max(sorted(strs), key=len)
            for taint in val.all_taints():
                shaped = taint.sanitized("int") if numeric else taint
                shaped = shaped.composed(prefix, comp).step(fr.sf.rel, getattr(node, "lineno", 0), "built into a string")
                taints[shaped.key] = shaped
            known = {v for v in val.strs} if val.strs else set()
            options = (known | {"*"}) if (val.tainted or not known) else known
            strs = _cap({s + o for s in strs for o in sorted(options)})
        if not taints and not any("*" not in s for s in strs):
            return Val(strs=frozenset(strs))
        return Val(taints=taints, strs=frozenset(strs))

    def concat(self, left: Val, right: Val, fr, node) -> Val:
        if left.kind == "path" or right.kind == "path":
            out = self.build([("val", left, False), ("val", right, False)], fr, node)
            return out.derive(kind="path")
        if not (left.tainted or right.tainted or left.strs or right.strs):
            return union(left.flat(), right.flat()) if left.fields or right.fields else EMPTY
        if left.fields is not None and right.fields is not None and not left.strs and not right.strs:
            fields = dict(left.fields)
            offset = len(fields)
            for key, value in right.fields.items():
                fields[str(int(key) + offset) if key.isdigit() else key] = value
            return Val(fields=fields)
        return self.build([("val", left, False), ("val", right, False)], fr, node)

    def percent_format(self, node, fr) -> Val:
        left, right = self.eval(node.left, fr), self.eval(node.right, fr)
        text = node.left.value if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) else \
            (max(sorted(left.strs), key=len) if left.strs else None)
        if text is None:
            return union(left.flat(), right.flat()).derive(strs=frozenset())
        if right.fields is not None and all(not k.isdigit() for k in right.fields):
            positional = None
        else:
            positional = [right.fields[k] for k in sorted(right.fields, key=lambda x: int(x))] if right.fields is not None and \
                all(k.isdigit() for k in right.fields) else [right]
        pieces, last, index = [], 0, 0
        for match in _PERCENT.finditer(text):
            pieces.append(("lit", text[last:match.start()]))
            last = match.end()
            kind = match.group(2)
            if kind == "%":
                pieces.append(("lit", "%"))
                continue
            if match.group(1) is not None:
                val = (right.fields or {}).get(match.group(1), right.flat())
            else:
                val = positional[index] if positional is not None and index < len(positional) else right.flat()
                index += 1
            pieces.append(("val", val, kind in "diouxXeEfFgGc"))
        pieces.append(("lit", text[last:]))
        return self.build(pieces, fr, node)

    def str_format(self, text, args, kwargs, fr, node) -> Val:
        pieces, auto = [], 0
        try:
            parsed = list(string.Formatter().parse(text))
        except ValueError:
            return union(*[a.flat() for a in args], *[v.flat() for v in kwargs.values()])
        for literal, field, spec, _ in parsed:
            if literal:
                pieces.append(("lit", literal))
            if field is None:
                continue
            base = re.split(r"[.\[]", field, maxsplit=1)[0]
            if base == "":
                val = args[auto] if auto < len(args) else EMPTY
                auto += 1
            elif base.isdigit():
                val = args[int(base)] if int(base) < len(args) else EMPTY
            else:
                val = kwargs.get(base, kwargs.get("**", EMPTY))
            pieces.append(("val", val.flat(), bool(spec and _NUMERIC_SPEC.search(spec))))
        return self.build(pieces, fr, node)

    # ---- sources -------------------------------------------------------------------------------------------------

    def source(self, fr, node, name, location, required=False, numeric=False) -> Val:
        if location == "header" and name.startswith("HTTP_"):
            name = "-".join(part.capitalize() for part in name[5:].split("_"))
        label = source_text(node, 80)
        taint = Taint(name, location, ((fr.sf.rel, node.lineno, f"{location} input: {label}"),))
        if numeric:
            taint = taint.sanitized("int")
        for route in fr.routes:
            if name != "*":
                param = Param(name, location, type="validated" if numeric else None)
                route.params.setdefault((name, location), param)
                if required:
                    route.required.setdefault((name, location), param)
        return Val.of(taint)

    def named(self, value: Val, key, fr=None, required=False) -> Val:
        """A value read out of an unnamed collection takes the name it was read by, and that name is an input of the route."""
        if not isinstance(key, str) or not value.taints or not all(t.name == "*" for t in value.taints.values()):
            return value
        if fr is not None:
            for taint in value.taints.values():
                self.note_param(fr, key, taint.location, required)
        return value.map_taints(lambda t: t.renamed(key))

    def note_param(self, fr, name, location, required=False, numeric=False):
        for route in fr.routes:
            param = Param(name, location, type="validated" if numeric else None)
            route.params.setdefault((name, location), param)
            if required:
                route.required.setdefault((name, location), param)

    # ---- calls ---------------------------------------------------------------------------------------------------

    def qualify(self, fr, node) -> str | None:
        """The full dotted name a call or reference points at, following imports; None for local objects."""
        name = dotted(node)
        if not name:
            return None
        head, _, rest = name.partition(".")
        if head in fr.env or (fr.fd is not None and fr.fd.parent is not None and head in self.closure_env.get(fr.fd.id, {})):
            return None
        if head in self.module_envs.get(fr.sf.rel, {}):
            return None
        imported = fr.sf.imports.get(head)
        if imported:
            return f"{imported}.{rest}" if rest else imported
        return name

    def e_Call(self, node, fr):
        func = node.func
        recv = self.eval(func.value, fr) if isinstance(func, ast.Attribute) else None
        args, kwargs = [], {}
        for arg in node.args:
            args.append(self.eval(arg.value, fr).flat() if isinstance(arg, ast.Starred) else self.eval(arg, fr))
        for kw in node.keywords:
            value = self.eval(kw.value, fr)
            kwargs[kw.arg or "**"] = value if kw.arg else value.flat()
        result = self.dispatch(node, fr, func, recv, args, kwargs)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.attr in MUTATORS:
            current = fr.env.get(func.value.id, EMPTY)
            if func.attr != "setdefault" or len(args) > 1:
                fr.env[func.value.id] = union(current, *[a.flat() for a in args[-1:]]) if args else current
        return result

    def dispatch(self, node, fr, func, recv, args, kwargs) -> Val:
        method = func.attr if isinstance(func, ast.Attribute) else None
        qual = self.qualify(fr, func)
        # 1. request objects and the collections they hold
        if recv is not None:
            special = self.receiver_call(node, fr, func, recv, method, args, kwargs)
            if special is not None:
                return special
        # 2. the project's own functions, methods and classes
        target = self.resolve_callable(fr, func, recv)
        if target is not None:
            return self.call_target(node, fr, target, args, kwargs, recv)
        # 3. library calls
        if qual is not None:
            got = self.library_call(node, fr, qual, args, kwargs)
            if got is not None:
                return got
        if method is not None:
            got = self.method_call(node, fr, method, recv, args, kwargs)
            if got is not None:
                return got
        return self.fallback(node, fr, func, recv, args, kwargs)

    def receiver_call(self, node, fr, func, recv, method, args, kwargs):
        if recv.request:
            if method in rules.REQUEST_RAW_CALLS:
                return self.source(fr, node, "*", rules.REQUEST_CALLS[method])
            if method in rules.REQUEST_CALLS:
                return Val(bag=rules.REQUEST_CALLS[method])
            return EMPTY
        if recv.bag:
            if method in rules.BAG_GET:
                key = _const(node.args[0]) if node.args else None
                numeric = any(dotted(kw.value) in ("int", "float") for kw in node.keywords if kw.arg == "type")
                got = self.source(fr, node, key if isinstance(key, str) else "*", recv.bag, numeric=numeric)
                default = args[1] if len(args) > 1 else kwargs.get("default")
                return union(got, default) if default is not None and default.tainted else got
            if method in rules.BAG_ALL:
                return self.source(fr, node, "*", recv.bag)
            return recv
        if any(t.startswith("orm:") for t in recv.tables) and method not in ("raw", "extra", "execute"):
            return self.orm_call(node, fr, method, recv, args, kwargs)
        if recv.obj is not None and method == "save" and self.project.class_has_base(recv.obj.cls, {"Model"}):
            carried = list(recv.all_taints()) + [t for v in recv.obj.attrs.values() for t in v.all_taints()]
            self.write_stored(fr, node, "orm:" + recv.obj.cls.name, carried)
            return EMPTY
        if recv.fields is not None and method in ("get", "pop") and node.args and isinstance(_const(node.args[0]), str) \
                and _const(node.args[0]) in recv.fields:
            found = recv.fields[_const(node.args[0])]
            return union(found, args[1]) if len(args) > 1 and args[1].tainted else found
        if recv.tables and method in rules.FETCH_METHODS:
            return self.read_stored(fr, node, recv)
        if recv.tables and method in ("execute", "executemany"):
            return None
        if recv.kind == "path":
            if method in rules.PATH_METHODS:
                self.sink(fr, node, 22, recv, f"{method}() on a path built from input")
                return EMPTY
            if method in rules.SANITIZER_METHODS:
                return recv.map_taints(lambda t: t.sanitized(rules.SANITIZER_METHODS[method]))
            if method in ("joinpath", "with_name", "with_suffix"):
                return self.concat(recv, union(*[a for a in args]), fr, node).derive(kind="path")
            return recv
        if recv.fields is not None and method in ("dict", "model_dump", "copy", "json", "model_dump_json", "values", "items"):
            return recv.flat()
        return None

    def resolve_callable(self, fr, func, recv):
        """The project function, method or class a call refers to, as ('func', fd, self Val) / ('class', info)."""
        if isinstance(func, ast.Name):
            local = fr.env.get(func.id)
            if local is None and fr.fd is not None and fr.fd.parent is not None:
                local = self.closure_env.get(fr.fd.id, {}).get(func.id)
            if local is None:
                local = self.module_envs.get(fr.sf.rel, {}).get(func.id)
            if local is not None:
                if local.func is not None:
                    return "func", local.func, None
                if local.cls is not None:
                    return "class", local.cls
                return None
            target = self.project.resolve_dotted(fr.sf, func.id)
            if target and target[0] in ("func", "class"):
                return target
            return None
        if isinstance(func, ast.Attribute):
            if recv is not None and recv.obj is not None:
                fd = self.project.class_methods(recv.obj.cls, func.attr)
                return ("func", fd, recv) if fd is not None else None
            if recv is not None and recv.cls is not None:
                fd = self.project.class_methods(recv.cls, func.attr)
                return ("func", fd, recv) if fd is not None else None
            if recv is not None and recv.func is None and (recv.tainted or recv.bag or recv.request):
                return None
            name = dotted(func)
            if name and self.qualify(fr, func) is not None:
                target = self.project.resolve_dotted(fr.sf, name)
                if target and target[0] in ("func", "class"):
                    return target
        return None

    def call_target(self, node, fr, target, args, kwargs, recv):
        if target[0] == "class" and self.project.class_has_base(target[1], {"Form", "ModelForm", "BaseForm"}):
            return self.make_form(node, fr, target[1], args, kwargs)
        if target[0] == "class":
            info = target[1]
            instance = Instance(info)
            value = Val(obj=instance)
            init = self.project.class_methods(info, "__init__")
            if init is not None:
                self.invoke(node, fr, init, args, kwargs, value)
            elif args or kwargs:
                value = value.derive(taints={t.key: t for a in [*args, *kwargs.values()] for t in a.all_taints()})
            return value
        fd, self_val = target[1], (target[2] if len(target) > 2 else None)
        return self.invoke(node, fr, fd, args, kwargs, self_val)

    def invoke(self, node, fr, fd: FuncDef, args, kwargs, self_val) -> Val:
        if fd.id in self.stack or len(self.stack) >= MAX_DEPTH:
            return union(*[a.flat() for a in [*args, *kwargs.values()]]).derive(strs=frozenset()) if (args or kwargs) else EMPTY
        routes = tuple(sorted(f"{r.path}|{','.join(sorted(r.methods))}" for r in fr.routes))
        key = (fd.id, tuple(a.sig() for a in args), tuple(sorted((k, v.sig()) for k, v in kwargs.items())),
               self_val.sig() if self_val is not None else None, routes)
        cached = self.memo.get(key)
        if cached is not None:
            return cached
        env = dict(self.closure_env.get(fd.id, {})) if fd.parent is not None else {}
        spec = fd.node.args
        positional = [*spec.posonlyargs, *spec.args]
        decorators = {dotted(d) for d in fd.node.decorator_list}
        through_class = self_val is not None and self_val.obj is None and self_val.cls is not None
        if fd.cls is not None and positional and "staticmethod" not in decorators and                 (not through_class or "classmethod" in decorators):
            first = positional.pop(0)
            env[first.arg] = self_val if self_val is not None else Val(obj=Instance(fd.cls))
        defaults = [None] * (len(positional) - len(spec.defaults)) + list(spec.defaults)
        for index, (param, default) in enumerate(zip(positional, defaults)):
            if index < len(args):
                env[param.arg] = args[index]
            elif param.arg in kwargs:
                env[param.arg] = kwargs[param.arg]
            else:
                env[param.arg] = self._default(default)
        for param, default in zip(spec.kwonlyargs, spec.kw_defaults):
            env[param.arg] = kwargs.get(param.arg, self._default(default))
        if spec.vararg is not None:
            env[spec.vararg.arg] = union(*args[len(positional):]).flat() if len(args) > len(positional) else EMPTY
        if spec.kwarg is not None:
            named = {k for k in kwargs} - {p.arg for p in [*positional, *spec.kwonlyargs]}
            env[spec.kwarg.arg] = union(*[kwargs[k].flat() for k in sorted(named)]) if named else EMPTY
        inner = Frame(fd.file, fd, env, fr.routes, fd.label)
        self.stack.append(fd.id)
        self.executed_funcs.add(fd.id)
        try:
            self.exec_block(fd.node.body, inner)
        finally:
            self.stack.pop()
        result = union(*inner.returns) if inner.returns else EMPTY
        self.memo[key] = result
        return result

    def _default(self, node) -> Val:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return Val.lit(node.value)
        return EMPTY

    # ---- library calls -------------------------------------------------------------------------------------------

    def library_call(self, node, fr, qual, args, kwargs):
        sink = rules.SINK_FUNCS.get(qual)
        if sink is None and "." not in qual:
            sink = rules.SINK_BY_TAIL.get(qual)
        if qual in rules.SUBPROCESS_FUNCS:
            return self.subprocess_call(node, fr, qual, args, kwargs)
        if qual in ("yaml.load", "yaml.load_all", "yaml.unsafe_load"):
            loader = kwargs.get("Loader")
            loader_node = next((kw.value for kw in node.keywords if kw.arg == "Loader"), node.args[1] if len(node.args) > 1 else None)
            safe = loader_node is not None and (dotted(loader_node) or "").split(".")[-1] in ("SafeLoader", "CSafeLoader", "BaseLoader")
            if qual == "yaml.unsafe_load" or not safe:
                self.sink(fr, node, 502, args[0] if args else EMPTY, "yaml load without a safe loader")
            return args[0].flat().derive(strs=frozenset()) if args else EMPTY
        if sink is not None:
            cwe, index, name = sink
            value = args[index] if len(args) > index else kwargs.get(name, EMPTY)
            self.sink(fr, node, cwe, value, f"{qual}()")
            if cwe == 601:
                return Val(resp="other")
            if cwe == 22 and qual.endswith(("send_file", "FileResponse")):
                return Val(resp="other")
            if cwe == 79:
                return Val(resp="html")
            return EMPTY
        if qual in rules.JSON_RESPONSES:
            return Val(resp="json")
        if qual in rules.TEMPLATE_RENDERS:
            self.unescaped_template_output(node, fr, qual, args, kwargs)
            return Val(resp="other")
        if qual in rules.HTML_RESPONSES:
            return self.response_object(node, args, kwargs)
        if qual in rules.PATH_CONSTRUCTORS or qual in rules.PATH_JOINERS:
            pieces = []
            for index, arg in enumerate(args):
                if index:
                    pieces.append(("lit", "/"))
                pieces.append(("val", arg.flat(), False))
            return self.build(pieces, fr, node).derive(kind="path") if pieces else Val(kind="path")
        if qual in rules.SANITIZERS:
            label = rules.SANITIZERS[qual]
            if qual == "html.escape" and _false_keyword(node, "quote", 1):
                label = "html_escape_nq"
            if not args:
                return EMPTY
            return args[0].flat().map_taints(lambda t: t.sanitized(label, fr.sf.rel, node.lineno, f"{qual}()")).derive(strs=frozenset())
        if qual in rules.NUMERIC_FUNCS:
            if not args:
                return EMPTY
            return args[0].flat().map_taints(lambda t: t.sanitized("int", fr.sf.rel, node.lineno, f"{qual}()")).derive(strs=frozenset())
        if qual in rules.KILL_FUNCS or qual.startswith(rules.KILL_PREFIXES):
            return EMPTY
        if qual in ("django.utils.safestring.mark_safe", "markupsafe.Markup", "flask.Markup", "jinja2.Markup") and args:
            return args[0].flat().map_taints(lambda t: t.sanitized("safe_string")).derive(strs=frozenset(), bag=None)
        if qual in ("json.loads", "json.load") and args and args[0].taints and all(
                t.name == "*" and t.location == "body" for t in args[0].taints.values()):
            return args[0].map_taints(lambda t: t._copy(location="json")).derive(strs=frozenset())
        if qual in BUILTIN_PASSTHROUGH or qual in rules.PASSTHROUGH_FUNCS:
            if args and args[0].bag:  # dict(request.form)
                return self.source(fr, node, "*", args[0].bag)
            if args and args[0].fields is not None and qual in ("dict", "list", "tuple", "set"):
                return args[0]
            return union(*[a.flat() for a in args]).derive(strs=frozenset()) if args else EMPTY
        return None

    def unescaped_template_output(self, node, fr, qual, args, kwargs) -> None:
        """Jinja escapes what it prints, except where the template says `| safe` or turns escaping off. A visitor's
        text handed to one of those spots is a cross-site scripting sink at the render call."""
        # Flask: render_template("t.html", a=1). Django: render(request, "t.html", {"a": 1}).
        position = next((i for i, a in enumerate(node.args[:2]) if isinstance(a, ast.Constant) and isinstance(a.value, str)), None)
        if position is None:
            return
        first = node.args[position]
        context = dict(kwargs)
        for later in args[position + 1:position + 2]:
            context.update(later.fields or {})
        if "context" in kwargs and kwargs["context"].fields:
            context.update(kwargs["context"].fields)
        if qual.endswith("render_template_string"):
            info = templates.analyse_text(first.value)
        else:
            info = self.templates.get(first.value)
        if info is None:
            return
        names = info.unescaped
        for name in sorted(names):
            if name in context:
                self.sink(fr, node, 79, context[name], f"{first.value} prints {name} without escaping it")
        if "**" in context and names:
            self.sink(fr, node, 79, context["**"], f"{first.value} prints values without escaping them")
        # mark_safe() / Markup() text is printed as is wherever the template shows it.
        for name, value in sorted(context.items()):
            if name not in names and any("safe_string" in t.san for t in value.all_taints()):
                self.sink(fr, node, 79, value.map_taints(lambda t: t if "safe_string" in t.san else None),
                          f"{first.value} prints {name}, which was marked safe")

    def response_object(self, node, args, kwargs) -> Val:
        body = args[0] if args else kwargs.get("response", kwargs.get("content", EMPTY))
        for name in ("mimetype", "content_type", "media_type"):
            kw = next((k.value for k in node.keywords if k.arg == name), None)
            if isinstance(kw, ast.Constant) and isinstance(kw.value, str) and rules.NON_HTML_TYPE.search(kw.value):
                return Val(resp="other")
        header_dicts = [kw.value for kw in node.keywords if kw.arg == "headers"] + list(node.args[2:])
        for headers in header_dicts:
            if not isinstance(headers, ast.Dict):
                continue
            for k, v in zip(headers.keys, headers.values):
                if isinstance(k, ast.Constant) and str(k.value).lower() == "content-type" and isinstance(v, ast.Constant) \
                        and rules.NON_HTML_TYPE.search(str(v.value)):
                    return Val(resp="other")
        return body.flat().derive(resp="html", strs=frozenset(), bag=None)

    def subprocess_call(self, node, fr, qual, args, kwargs) -> Val:
        shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
        shell_on = isinstance(shell, ast.Constant) and bool(shell.value)
        command = args[0] if args else kwargs.get("args", EMPTY)
        label = f"{qual}()"
        if shell_on or qual == "asyncio.create_subprocess_shell":
            self.sink(fr, node, 78, command, label + " with shell=True")
            return EMPTY
        # Without a shell only the program itself can be chosen: the first element of a list, or a whole string.
        first = command.fields.get("0") if command.fields is not None else None
        for taint in command.all_taints():
            chooses_program = (first is not None and any(t.key == taint.key for t in first.all_taints())) or \
                (command.fields is None and taint.comp is None)
            reason = None if chooses_program else rules.LABEL_TEXT["no_shell"]
            self.add_hit(fr, node, 78, taint, label, reason or self.verdict(78, taint))
        return EMPTY

    # ---- method calls on unknown objects -------------------------------------------------------------------------

    def method_call(self, node, fr, method, recv, args, kwargs):
        if method in ("execute", "executemany", "executescript") or (method in rules.SINK_METHODS and method != "save"):
            return self.sql_call(node, fr, method, args, kwargs)
        if method == "save" and args and args[0].tainted and not recv.bag:
            self.sink(fr, node, 22, args[0], "file save to a path built from input")
            return EMPTY
        if method in rules.SANITIZER_METHODS and args and rules.SANITIZER_METHODS[method] != "resolved":
            return args[0].flat().map_taints(lambda t: t.sanitized(rules.SANITIZER_METHODS[method])).derive(strs=frozenset())
        if method == "format" and (recv.strs and not recv.tainted):
            template = max(sorted(recv.strs), key=len)
            return self.str_format(template, args, kwargs, fr, node)
        if method == "join" and recv is not None and not recv.tainted and args:
            return args[0].flat().derive(strs=frozenset(), bag=None)
        if method in ("get", "pop") and recv.taints and node.args and isinstance(_const(node.args[0]), str) \
                and all(t.name == "*" for t in recv.taints.values()):
            got = self.named(recv.flat(), _const(node.args[0]), fr)
            return union(got, args[1]) if len(args) > 1 and args[1].tainted else got
        if method in rules.PASSTHROUGH_METHODS and (recv.tainted or recv.strs):
            extra = [a.flat() for a in args] if method in ("replace", "get", "pop", "setdefault", "format", "join", "append",
                                                              "extend", "add", "update", "insert", "translate", "removeprefix",
                                                              "removesuffix") else []
            return union(recv.flat(), *extra).derive(strs=frozenset(), bag=None, kind=None)
        if method in rules.PASSTHROUGH_METHODS:
            return EMPTY  # a string method or lookup on something that holds no input
        return None

    def sql_call(self, node, fr, method, args, kwargs) -> Val:
        sql = args[0] if args else next((kwargs[k] for k in ("sql", "query", "statement", "operation") if k in kwargs), EMPTY)
        params = args[1] if len(args) > 1 else kwargs.get("parameters", kwargs.get("params", EMPTY))
        self.sink(fr, node, 89, sql, f".{method}() with a built query")
        texts = sorted(sql.strs)
        writes = {m.group(1).lower() for t in texts for m in rules.SQL_WRITE_TABLE.finditer(t)}
        reads = set()
        for text in texts:
            if rules.SQL_STATEMENT.match(text) and text.lstrip().lower().startswith(("select", "(select")):
                reads |= {g.lower() for m in rules.SQL_READ_TABLE.finditer(text) for g in m.groups() if g}
        if writes:
            carried = {t.key: t for v in (sql, params) for t in v.all_taints()}
            for table in writes:
                self.write_stored(fr, node, table, list(carried.values()))
        return Val(tables=frozenset(reads))

    def write_stored(self, fr, node, table, taints):
        entries = self.stored.setdefault(table, {})
        routes = {(r.id, tuple(sorted(r.methods))): r for r in fr.routes}
        for taint in taints:
            if taint.stored is not None:
                continue
            meta = {"store": table, "write_file": fr.sf.rel, "write_line": node.lineno, "routes": routes}
            stored = taint._copy(stored=meta).step(fr.sf.rel, node.lineno, f"stored in table {table}")
            existing = entries.setdefault(stored.key, stored)
            if existing is not stored:  # the same value written by another route: both are writers
                existing.stored["routes"].update(routes)

    def orm_call(self, node, fr, method, recv: Val, args, kwargs) -> Val:
        """Django's ORM. Values written through create() and friends are stored by model name; reads give them back."""
        tables = frozenset(t for t in recv.tables if t.startswith("orm:"))
        if method in ("create", "get_or_create", "update_or_create", "bulk_create", "update"):
            carried = {t.key: t for v in [*args, *kwargs.values()] for t in v.all_taints()}
            for table in sorted(tables):
                self.write_stored(fr, node, table, list(carried.values()))
            return Val(taints=carried, tables=tables)
        if method in ("count", "exists", "delete", "aggregate"):
            return EMPTY
        rows = self.read_stored(fr, node, Val(tables=frozenset(a for t in tables for a in self.orm_aliases(t))))
        return Val(taints=rows.taints, tables=tables, kind="manager")

    def orm_aliases(self, table: str) -> list:
        """The ways one model's table is named: the ORM key, and `app_model` as raw SQL writes it."""
        name = table[len("orm:"):]
        infos = self.project.classes.get(name, [])
        folder = infos[0].file.rel.rsplit("/", 2)[-2] if infos and "/" in infos[0].file.rel else ""
        return [table] + ([f"{folder}_{name.lower()}"] if folder else [])

    def make_form(self, node, fr, info, args, kwargs) -> Val:
        """A Django form built from request.POST: cleaned_data holds one input per declared field, and a field that
        parses to a number, date or choice can't carry text."""
        data = args[0] if args else kwargs.get("data", EMPTY)
        location = data.bag or next(iter({t.location for t in data.all_taints()}), None)
        form = Instance(info)
        if location is None:
            return Val(obj=form)
        fields = {}
        for stmt in info.node.body:
            target, value = None, None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                target, value = stmt.targets[0].id, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                target, value = stmt.target.id, stmt.value
            if target is None or not isinstance(value, ast.Call):
                continue
            kind = (dotted(value.func) or "").split(".")[-1]
            if not kind.endswith("Field"):
                continue
            required = not any(kw.arg == "required" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in value.keywords)
            fields[target] = self.source(fr, node, target, location, required=required, numeric=kind in rules.TYPED_FORM_FIELDS)
        form.attrs["cleaned_data"] = Val(fields=fields)
        form.attrs["data"] = data
        return Val(obj=form)

    def read_stored(self, fr, node, cursor: Val) -> Val:
        taints = {}
        for table in sorted(cursor.tables):
            for taint in self.stored.get(table, {}).values():
                fresh = taint._copy(comp=None, html_ctx=None, url_prefix=None, sql_quoted=False)
                fresh = fresh.step(fr.sf.rel, node.lineno, f"read from table {table}")
                taints[fresh.key] = fresh
        return Val(taints=taints)

    def fallback(self, node, fr, func, recv, args, kwargs) -> Val:
        """A call nothing here knows. Inputs carry into the result through plain functions, and through methods
        called on tainted values; a method on a clean object (an ORM query, a logger) hands back clean data."""
        name = dotted(func) or ""
        if isinstance(func, ast.Attribute) and (recv is None or not recv.tainted):
            return EMPTY
        if name.split(".")[-1] in rules.LOGGING_METHODS:
            return EMPTY
        parts = [a.flat() for a in args] + [v.flat() for v in kwargs.values()]
        if recv is not None and recv.tainted:
            parts.insert(0, recv.flat())
        taints = {}
        for part in parts:
            for taint in part.all_taints():
                shaped = taint.penalised()
                taints[shaped.key] = shaped
        return Val(taints=taints) if taints else EMPTY

    # ---- sinks ---------------------------------------------------------------------------------------------------

    def sink(self, fr, node, cwe, value: Val, label):
        for taint in value.all_taints():
            self.add_hit(fr, node, cwe, taint, label, self.verdict(cwe, taint))

    def verdict(self, cwe, taint: Taint):
        """None when the input can still do harm here; otherwise the reason it can't."""
        protects = rules.PROTECTS.get(cwe, set())
        for label in sorted(taint.san):
            if label not in protects:
                continue
            if label == "sql_escape" and not taint.sql_quoted:
                continue
            if label == "html_escape" and taint.html_ctx in ("js", "attr_unquoted", "url_start"):
                continue
            if label == "html_escape_nq" and taint.html_ctx not in (None, "body"):
                continue
            return rules.LABEL_TEXT[label]
        if cwe == 601 and taint.url_prefix is not None and rules.SAFE_REDIRECT_PREFIX.match(taint.url_prefix):
            return rules.LABEL_TEXT["fixed_url"]
        return None

    def add_hit(self, fr, node, cwe, taint, sink, reason):
        expr = source_text(node, 220)
        key = (cwe, fr.sf.rel, node.lineno, fr.label, taint.key, reason)
        routes = {(r.id, tuple(sorted(r.methods))): r for r in fr.routes}
        existing = self._hit_index.get(key)
        if existing is not None:
            existing.routes.update(routes)
            return
        hit = Hit(cwe, fr.sf.rel, node.lineno, fr.label, expr, sink, taint, reason, routes)
        self._hit_index[key] = hit
        self.hits.append(hit)

    def check_response(self, fr, stmt, value: Val):
        """What a handler returns is the page, so tainted text in it is a cross-site scripting sink."""
        handler = fr.handler
        if value.resp in ("json", "other") or fr.fd is None:
            return
        node = stmt.value
        if isinstance(node, ast.Tuple) and value.fields and "0" in value.fields:
            value = value.fields["0"]
            if value.resp in ("json", "other"):
                return
        elif value.fields is not None:
            return  # a dict or list is sent as JSON
        if handler.framework in ("fastapi", "openapi", "django-hook") and not handler.html and value.resp != "html":
            return
        for taint in value.all_taints():
            self.add_hit(fr, stmt, 79, taint, "response body", self.verdict(79, taint))


# ---- helpers -----------------------------------------------------------------------------------------------------


def _const(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return node.value
    return None


def _cap(strs) -> set:
    out = sorted(s[:MAX_STR_LEN] for s in strs)
    return set(out[:MAX_STRS])


def _false_keyword(node, name, position) -> bool:
    for kw in node.keywords:
        if kw.arg == name:
            return isinstance(kw.value, ast.Constant) and kw.value.value is False
    if len(node.args) > position:
        arg = node.args[position]
        return isinstance(arg, ast.Constant) and arg.value is False
    return False


def _safe_regex(pattern: str, mode: str) -> bool:
    """Whether a regex used as a check only lets harmless characters through."""
    anchored_end = pattern.endswith(("$", "\\Z")) or mode == "fullmatch"
    anchored_start = pattern.startswith("^") or mode in ("match", "fullmatch")
    if not (anchored_end and anchored_start):
        return False
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False
    for char in rules.UNSAFE_REGEX_CHARS:
        if compiled.fullmatch("a" + char + "a") or compiled.fullmatch(char):
            return False
    return True


def _pattern_names(pattern) -> list:
    return [n.name for n in ast.walk(pattern) if isinstance(n, (ast.MatchAs, ast.MatchStar)) and getattr(n, "name", None)]
