"""Include-aware taint interpreter for PHP.

Runs each entry point abstractly, following includes with shared variables and
inlining user functions, and records where tainted input reaches a sink.
"""
from __future__ import annotations

import posixpath
import re

from sast.core.model import Param

from . import rules
from . import sql_columns
from .project import ABS, FuncDef, N, Project, SourceFile
from .values import EMPTY, ClosureRef, Comp, RequestRole, Taint, TemplateRef, Val, html_context, union

MAX_DEPTH = 9
NODE_BUDGET = 1_500_000
INCLUDES = {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}
ONCE = {"include_once_expression", "require_once_expression"}
EXTRACTED = "*extracted"
ROWS = "rows"
PASSWORD_NAME = re.compile(r"pass|pwd", re.I)
META_REFRESH = re.compile(r"http-equiv\s*=\s*[\"']?refresh[^>]*url\s*=\s*\*", re.I)
CASE_FOLDERS = {"strtolower", "strtoupper", "trim", "ltrim", "rtrim", "mb_strtolower", "mb_strtoupper", "strval"}
LOOPS = {"foreach_statement", "for_statement", "while_statement", "do_statement"}
COMPARISON_OPS = {"==", "===", "!=", "!==", "<>", "<", ">", "<=", ">=", "<=>", "&&", "||", "and", "or", "xor",
                  "instanceof"}
ARITHMETIC_OPS = {"+", "-", "*", "/", "%", "**", "&", "|", "^", "<<", ">>"}
ROUTING_PARAMS = {"action", "page", "op", "cmd", "do", "task", "view", "mode", "route", "r", "p", "a", "act", "module",
                  "controller", "method", "section", "tab", "func", "function"}
NUMERIC_CASTS = {"int", "integer", "float", "double", "bool", "boolean", "real"}
READ_TABLE = re.compile(r"\bfrom\s+[`\"\[]?([A-Za-z_]\w*)", re.I)
WRITE_TABLE = re.compile(r"\b(?:insert\s+(?:ignore\s+)?into|replace\s+into|update)\s+[`\"\[]?([A-Za-z_]\w*)", re.I)
STRICT_REGEX = re.compile(r"^(.)\^.*\$\1[a-zA-Z]*$", re.S)
NEGATED_CLASS = re.compile(r"^(.)\[\^(.*)\]\+?\1[a-zA-Z]*$", re.S)


def strict_regex_safe(pattern: str) -> bool:
    """True for anchored patterns made only of harmless characters."""
    if not STRICT_REGEX.match(pattern):
        return False
    body = pattern[2:pattern.rfind("$")]
    body = body.replace("\\d", "").replace("\\w", "").replace("\\-", "").replace("\\.", "")
    if "." in re.sub(r"\[[^\]]*\]", "", body):
        return False
    return not (set(body) & rules.UNSAFE_REGEX_CHARS)


def strict_replace_safe(pattern: str) -> bool:
    """True for `preg_replace('/[^a-z0-9]/', ...)`, which keeps only harmless characters."""
    match = NEGATED_CLASS.match(pattern)
    if not match:
        return False
    kept = match.group(2).replace("\\d", "").replace("\\w", "").replace("\\-", "").replace("\\s", "")
    return not (set(kept) & (rules.UNSAFE_REGEX_CHARS | {"."}))


class Frame:
    __slots__ = ("env", "sf", "func", "cls", "returns", "fd")

    def __init__(self, env, sf, func="<top-level>", cls=None, fd=None):
        self.env, self.sf, self.func, self.cls, self.fd = env, sf, func, cls, fd
        self.returns = []


class Hit:
    """One observation of tainted data reaching a sink. Findings are built by merging these."""
    __slots__ = ("cwe", "sink", "file", "line", "func", "expr", "taint", "reason", "routes", "conditions", "sink_step",
                 "penalty", "downgraded")


class Budget(Exception):
    pass


class Interpreter:
    def __init__(self, project: Project, routes):
        self.p = project
        self.routes = routes
        self.discover = False
        self.edges: dict[str, set] = {}
        self.hits: list[Hit] = []
        self.stored: dict[str, Val] = {}
        self.stored_meta: dict[str, dict] = {}
        self.props: dict[tuple, Val] = {}
        self.route_stack: list[list] = []
        self.conditions: list[str] = []
        self.include_stack: list[str] = []
        self.once: set = set()
        self.call_stack: list[str] = []
        self.memo: dict = {}
        self.collectors: list[list] = []
        self.executed_funcs: set = set()
        self.executed_files: set = set()
        self.file_routes: dict[str, dict] = {}
        self.html_tail = ""
        self.pending_echo = False
        self.non_html = False
        self.budget = NODE_BUDGET
        self.entry_rel: str | None = None
        self.low_conf = 0
        self.budget_hits = 0
        self.selector_targets: set = set()
        self.top_frame: Frame | None = None
        self.buffering = 0
        self.dynamic_include = False
        self.assigned: dict = {}
        self.cur_line = 1

    # ---- entry points ----

    def _reset(self, rel, route_list):
        self.route_stack = [route_list] if route_list else []
        self.conditions, self.include_stack, self.call_stack = [], [rel], []
        self.once, self.html_tail, self.pending_echo, self.non_html = set(), "", False, False
        self.budget, self.entry_rel, self.low_conf = NODE_BUDGET, rel, 0
        self.memo, self.props, self.collectors = {}, {}, []
        self.buffering = 0
        self.assigned = {}

    def run_entry(self, sf: SourceFile, route_list):
        self._reset(sf.rel, route_list)
        self._cover(sf.rel)
        self.executed_files.add(sf.rel)
        self.top_frame = Frame({}, sf)
        try:
            self.exec_block(sf.tree.kids, self.top_frame)
        except Budget:
            self.budget_hits += 1

    def run_function(self, fd: FuncDef, route_list, seed=None):
        """Runs a function on its own, for routed handlers and for code nothing calls."""
        self._reset(fd.sf.rel, route_list)
        self.executed_funcs.add(fd.id)
        self._cover(fd.sf.rel)
        env = dict(self._request_params(fd))
        env.update(seed or {})
        if fd.cls:
            env["$this"] = Val(cls=fd.cls)
        self.top_frame = Frame(env, fd.sf, fd.label, fd.cls, fd)
        try:
            self.exec_block(fd.body.kids, self.top_frame)
        except Budget:
            self.budget_hits += 1

    def discover_file(self, sf: SourceFile):
        """Evaluates a file one level deep, only to learn what it includes."""
        self.discover = True
        self.route_stack, self.include_stack, self.call_stack = [], [sf.rel], []
        self.entry_rel, self.budget, self.once = sf.rel, NODE_BUDGET, set()
        self.top_frame = Frame({}, sf)
        try:
            self.exec_block(sf.tree.kids, self.top_frame)
            for item in self.p.defs_by_file.get(sf.rel, []):
                env = {"$this": Val(cls=item.cls)} if item.cls else {}
                self.exec_block(item.body.kids, Frame(env, sf, item.label, item.cls))
        except Budget:
            pass
        self.discover = False

    def collect_constants(self):
        """Evaluates define() and const across the project, over a few rounds for chained constants."""
        self.discover = True
        for _ in range(3):
            for sf in self.p.files.values():
                frame = Frame({}, sf)
                stack = [sf.tree]
                while stack:
                    cur = stack.pop()
                    stack.extend(cur.kids)
                    if cur.type == "function_call_expression" and cur.f("function") is not None \
                            and cur.f("function").text.lower() == "define":
                        args = self._arg_nodes(cur)
                        if len(args) >= 2 and args[0].type in ("string", "encapsed_string"):
                            self._add_constant(self._literal(args[0]), args[1], frame)
                    elif cur.type == "const_element" and len(cur.kids) >= 2:
                        self._add_constant(cur.kids[0].text, cur.kids[1], frame)
        self.discover = False

    def _add_constant(self, name, node, frame):
        self.budget = NODE_BUDGET
        val = self.ev(node, frame)
        values = {s for s in val.strs if s} or {"*"}
        bucket = self.p.constants.setdefault(name, set())
        known = {s for s in bucket | values if s != "*"}
        bucket.clear()
        bucket.update(known or {"*"})

    def _cover(self, rel):
        if self.route_stack:
            bucket = self.file_routes.setdefault(rel, {})
            for route in self.route_stack[-1]:
                bucket[route.id] = route

    # ---- statements. Each returns True when control can't continue past it. ----

    def exec_block(self, stmts, fr: Frame) -> bool:
        for stmt in stmts:
            if self.exec(stmt, fr):
                return True
        return False

    def exec(self, node: N, fr: Frame) -> bool:
        self.budget -= 1
        if self.budget < 0:
            raise Budget()
        self.cur_line = node.line
        kind = node.type
        if kind == "expression_statement":
            if not node.kids:
                return False
            expr = node.kids[0]
            if self.pending_echo:
                self.pending_echo = False
                self.echo_sink(self.ev(expr, fr), expr, fr)
                return False
            self.ev(expr, fr)
            return self._terminal_expr(expr, fr)
        if kind == "text":
            self.html_tail = (self.html_tail + node.text)[-400:]
            return False
        if kind == "php_tag":
            self.pending_echo = node.text.startswith("<?=")
            return False
        if kind == "text_interpolation":
            for kid in node.kids:
                self.exec(kid, fr)
            return False
        if kind == "echo_statement":
            for expr in self._echo_args(node):
                self.echo_sink(self.ev(expr, fr), expr, fr)
            return False
        if kind == "if_statement":
            return self.exec_if(node, fr)
        if kind == "compound_statement" or kind == "colon_block":
            return self.exec_block(node.kids, fr)
        if kind in LOOPS:
            return self.exec_loop(node, fr)
        if kind == "switch_statement":
            return self.exec_switch(node, fr)
        if kind == "return_statement":
            if node.kids:
                fr.returns.append(self.ev(node.kids[0], fr))
            return True
        if kind == "exit_statement":
            for expr in node.kids:
                self.echo_sink(self.ev(expr, fr), expr, fr)
            return True
        if kind in ("break_statement", "continue_statement"):
            return True
        if kind == "try_statement":
            return self.exec_try(node, fr)
        if kind == "unset_statement":
            for kid in node.kids:
                if kid.type == "variable_name":
                    fr.env.pop(kid.text, None)
            return False
        if kind == "namespace_definition":
            body = node.f("body")
            if body is not None:
                return self.exec_block(body.kids, fr)
            return False
        if kind == "const_declaration" or kind in ("function_definition", "class_declaration", "interface_declaration",
                                                    "trait_declaration", "enum_declaration", "comment",
                                                    "namespace_use_declaration", "php_end_tag", "declare_statement",
                                                    "empty_statement", "named_label_statement", "goto_statement"):
            return False
        return False

    def _terminal_expr(self, expr, fr) -> bool:
        if expr.type in ("exit_statement", "throw_expression"):
            return True
        if expr.type == "function_call_expression" and expr.f("function") is not None:
            name = expr.f("function").text.lower()
            if name in ("die", "exit"):
                return True
            for fd in self.p.functions.get(name, []):
                if fd.always_exits:
                    return True
        return False

    def _echo_args(self, node):
        out = []
        for kid in node.kids:
            out.extend(kid.kids if kid.type == "sequence_expression" else [kid])
        return out

    def _materialise(self, cond, fr):
        """Copies a superglobal into the base scope before branching, so a check inside one
        branch can't look as though it applied after the `if`."""
        for truth in (True, False):
            for path in self.narrow(cond, truth, fr):
                if path[0] in rules.SUPERGLOBALS and len(path) > 1:
                    self.write_path(path, self.read_path(path, fr), fr)

    def exec_if(self, node, fr) -> bool:
        branches = []
        env = fr.env
        cond = node.f("condition")
        self._materialise(cond, fr)
        for alt in node.fl("alternative"):
            if alt.type == "else_if_clause":
                self._materialise(alt.f("condition"), fr)
        self._run_branch(cond, node.f("body"), fr, env, branches)
        pending = dict(env)
        self.apply_narrow(self.narrow(cond, False, fr), pending, fr)
        has_else = False
        for alt in node.fl("alternative"):
            if alt.type == "else_if_clause":
                alt_cond = alt.f("condition")
                self._run_branch(alt_cond, alt.f("body"), fr, pending, branches)
                pending = dict(pending)
                self.apply_narrow(self.narrow(alt_cond, False, fr), pending, fr)
            elif alt.type == "else_clause":
                has_else = True
                saved, fr.env = fr.env, pending
                ended = self.exec(alt.f("body"), fr) if alt.f("body") is not None else False
                fr.env = saved
                if not ended:
                    branches.append(pending)
        if not has_else:
            branches.append(pending)
        if not branches:
            return True
        self._merge_into(fr.env, branches)
        return False

    def _run_branch(self, cond, body, fr, base_env, branches):
        self.ev(cond, fr)
        self._note_guards(cond, fr)
        if self._const_false(cond) or body is None:
            return
        env = dict(base_env)
        self.apply_narrow(self.narrow(cond, True, fr), env, fr)
        saved, fr.env = fr.env, env
        dispatch = self._dispatch_route(cond, fr)
        if dispatch:
            self.route_stack.append(dispatch)
            self._cover(fr.sf.rel)
        ended = self.exec(body, fr)
        if dispatch:
            self.route_stack.pop()
        fr.env = saved
        if not ended:
            branches.append(env)

    @staticmethod
    def _const_false(cond):
        inner = cond.kids[0] if cond.type == "parenthesized_expression" and cond.kids else cond
        return inner.type == "boolean" and inner.text.lower() == "false" or (inner.type == "integer" and inner.text == "0")

    @staticmethod
    def _merge_into(env, branches):
        keys = set()
        for branch in branches:
            keys |= branch.keys()
        for key in keys:
            vals = [b[key] for b in branches if key in b]
            first = vals[0]
            env[key] = first if all(v is first for v in vals) else union(*vals)

    def exec_loop(self, node, fr) -> bool:
        kind = node.type
        if kind == "foreach_statement":
            subject = self.ev(node.kids[0], fr) if node.kids else EMPTY
            target = node.kids[1] if len(node.kids) > 1 else None
            flat = subject.flat()
            if subject.closure == ROWS:
                whole = subject  # each row keeps its columns
            else:
                whole = union(Val(flat.taints, tables=subject.tables), self._fetch(subject, node, fr))
            if target is not None:
                if target.type == "pair" and len(target.kids) >= 2:
                    self.assign(target.kids[0], whole, fr, node)
                    self.assign(target.kids[1], whole, fr, node)
                else:
                    self.assign(target, whole, fr, node)
        else:
            for name in ("initialize", "condition", "update"):
                for part in node.fl(name):
                    self.ev(part, fr)
        body = node.f("body")
        if body is None:
            body_kids = [k for k in node.kids if k.type in ("compound_statement", "colon_block", "expression_statement")]
            body = body_kids[-1] if body_kids else None
        if body is not None:
            for _ in range(2):  # twice, so taint carried across iterations is seen
                env = dict(fr.env)
                saved, fr.env = fr.env, env
                self.exec(body, fr)
                fr.env = saved
                self._merge_into(fr.env, [fr.env, env])
        return False

    def exec_switch(self, node, fr) -> bool:
        subject_node = node.f("condition")
        subject = self.ev(subject_node, fr) if subject_node is not None else EMPTY
        key = self.path_of(subject_node.kids[0] if subject_node is not None and subject_node.type == "parenthesized_expression"
                           and subject_node.kids else subject_node, fr) if subject_node is not None else None
        block = node.f("body")
        if block is None:
            return False
        branches, has_default = [], False
        for case in block.kids:
            if case.type not in ("case_statement", "default_statement"):
                continue
            env = dict(fr.env)
            value = None
            if case.type == "case_statement":
                value_node = case.f("value") or (case.kids[0] if case.kids else None)
                if value_node is not None:
                    value = self._single_literal(value_node, fr)
                stmts = [k for k in case.kids if k is not value_node]
            else:
                has_default = True
                stmts = case.kids
            if key and value is not None:
                if key[0] in rules.SUPERGLOBALS and len(key) > 1 and key[1] not in (env.get(key[0]) or EMPTY).fields_or_empty():
                    self.write_path(key, self.read_path(key, fr), fr)
                    env = dict(fr.env)
                self.apply_narrow({key: {"allowlist"}}, env, fr)
            saved, fr.env = fr.env, env
            dispatch = self._selector_for(subject, value) if value is not None and _does_work(stmts) else None
            if dispatch:
                self.route_stack.append(dispatch)
                self._cover(fr.sf.rel)
            ended = self._exec_case(stmts, fr)
            if dispatch:
                self.route_stack.pop()
            fr.env = saved
            if not ended:
                branches.append(env)
        if not has_default:
            branches.append(fr.env)
        if not branches:
            return True
        self._merge_into(fr.env, branches)
        return False

    def _exec_case(self, stmts, fr) -> bool:
        for stmt in stmts:
            if stmt.type in ("break_statement", "continue_statement"):
                return False
            if self.exec(stmt, fr):
                # An `if` may have ended on a break, which only leaves this case.
                return stmt.type != "if_statement"
        return False

    def exec_try(self, node, fr) -> bool:
        body = node.f("body")
        ended = self.exec(body, fr) if body is not None else False
        for kid in node.kids:
            if kid.type == "catch_clause" and kid.f("body") is not None:
                env = dict(fr.env)
                saved, fr.env = fr.env, env
                caught = self.exec(kid.f("body"), fr)
                fr.env = saved
                if not caught:
                    self._merge_into(fr.env, [fr.env, env])
                    ended = False
            elif kid.type == "finally_clause" and kid.kids:
                self.exec(kid.kids[0], fr)
        return ended

    # ---- route dispatch inside a file ----

    def _dispatch_route(self, cond, fr):
        inner = cond.kids[0] if cond.type == "parenthesized_expression" and cond.kids else cond
        if inner.type != "binary_expression" or inner.op not in ("==", "==="):
            return None
        left, right = inner.f("left"), inner.f("right")
        if left is None or right is None:
            return None
        for subject, other in ((left, right), (right, left)):
            literal = self._single_literal(other, fr)
            if literal is None:
                continue
            val = self.ev(subject, fr)
            names = {t.name.lower() for t in val.taints.values()}
            paths = {t.location for t in val.taints.values()}
            if not (names & ROUTING_PARAMS or "path" in paths):
                continue
            found = self._selector_for(val, literal)
            if found:
                return found
        return None

    def _selector_for(self, subject: Val, value: str):
        """A branch on an input's literal value acts like a route: `?action=view` or `/orders`."""
        if self.discover or not self.route_stack or not value or "*" in value:
            return None
        taints = [t for t in subject.taints.values() if t.location in ("query", "any", "body", "path") and not t.stored]
        if len(taints) != 1:
            return None
        taint = taints[0]
        base = self.route_stack[-1][0]
        if taint.location == "path":
            if not value.startswith("/"):
                return None
            route = self.routes.get(self.routes.prefix + value, None, kind="selector", handler=self.include_stack[-1])
        else:
            route = self.routes.get(base.path, f"{taint.name}={value}", kind="selector", handler=self.include_stack[-1],
                                    aliases=base.aliases)
        return [route]

    # ---- narrowing: what a condition proves about a value ----

    def narrow(self, cond, truth: bool, fr) -> dict:
        """Returns {path: labels} that hold when `cond` evaluates to `truth`."""
        if cond is None:
            return {}
        kind = cond.type
        if kind == "parenthesized_expression" and cond.kids:
            return self.narrow(cond.kids[0], truth, fr)
        if kind == "unary_op_expression" and cond.op == "!":
            arg = cond.f("argument") or (cond.kids[0] if cond.kids else None)
            return self.narrow(arg, not truth, fr)
        if kind == "binary_expression":
            left, right, op = cond.f("left"), cond.f("right"), cond.op
            if op in ("&&", "and", "||", "or"):
                a, b = self.narrow(left, truth, fr), self.narrow(right, truth, fr)
                if (op in ("&&", "and")) == truth:
                    return self._narrow_union(a, b)
                return self._narrow_intersect(a, b)
            if op in ("==", "===", "!=", "!==", "<>"):
                positive = (op in ("==", "===")) == truth
                return self._narrow_compare(left, right, op, positive, fr)
            return {}
        if kind == "function_call_expression" and truth:
            return self._narrow_call(cond, fr)
        return {}

    def _narrow_compare(self, left, right, op, positive, fr):
        # strpos($real, $base) === 0, the usual prefix check on a resolved path
        for call, other in ((left, right), (right, left)):
            if call is not None and call.type == "function_call_expression" and call.f("function") is not None \
                    and call.f("function").text.lower() in ("strpos", "strncmp") and other.text.strip() == "0" and positive:
                args = self._arg_nodes(call)
                key = self.path_of(args[0], fr) if args else None
                return {key: {"path_prefix"}} if key else {}
            if call is not None and call.type == "function_call_expression" and call.f("function") is not None \
                    and call.f("function").text.lower() in ("is_numeric", "ctype_digit", "in_array", "preg_match") \
                    and other.type == "boolean":
                is_true = other.text.lower() == "true"
                return self.narrow(call, positive == is_true, fr)
            if call is not None and call.type == "function_call_expression" and call.f("function") is not None \
                    and call.f("function").text.lower() == "preg_match" and other.text.strip() in ("1", "0"):
                return self.narrow(call, positive == (other.text.strip() == "1"), fr)
        if not positive:
            return {}
        for subject, other in ((left, right), (right, left)):
            if subject is None or other is None:
                continue
            if self._single_literal(other, fr) is None:
                continue
            key = self.path_of(subject, fr)
            if key:
                return {key: {"allowlist"}}
        return {}

    def _narrow_call(self, call, fr):
        func = call.f("function")
        if func is None:
            return {}
        name = func.text.lower().lstrip("\\")
        args = self._arg_nodes(call)
        if not args:
            return {}
        key = self.path_of(args[0], fr)
        if name in ("is_numeric", "ctype_digit", "is_int", "is_integer", "is_float", "ctype_xdigit", "is_bool"):
            return {key: {"int"}} if key else {}
        if name in ("ctype_alnum", "ctype_alpha"):
            return {key: {"allowlist"}} if key else {}
        if name == "in_array" and len(args) >= 2:
            haystack = self.ev(args[1], fr)
            return {key: {"allowlist"}} if key and not haystack.tainted else {}
        if name == "array_key_exists" and len(args) >= 2 and args[1].type == "variable_name":
            if args[1].text in rules.SUPERGLOBALS:
                return {}
            return {key: {"allowlist"}} if key and not self.ev(args[1], fr).tainted else {}
        if name == "preg_match" and len(args) >= 2:
            subject = self.path_of(args[1], fr)
            pattern = self._single_literal(args[0], fr)
            return {subject: {"allowlist"}} if subject and pattern and strict_regex_safe(pattern) else {}
        if name == "filter_var" and len(args) >= 2:
            flag = args[1].text
            if "VALIDATE_INT" in flag or "VALIDATE_FLOAT" in flag or "VALIDATE_BOOL" in flag:
                return {key: {"int"}} if key else {}
            if "VALIDATE_IP" in flag or "VALIDATE_EMAIL" in flag:
                return {key: {"allowlist"}} if key else {}
            return {}
        if name == "str_starts_with":
            return {key: {"path_prefix"}} if key else {}
        return {}

    @staticmethod
    def _narrow_union(a, b):
        out = {k: set(v) for k, v in a.items()}
        for key, labels in b.items():
            out.setdefault(key, set()).update(labels)
        return out

    @staticmethod
    def _narrow_intersect(a, b):
        out = {}
        for key in a.keys() & b.keys():
            shared = a[key] & b[key]
            if shared:
                out[key] = shared
        return out

    def apply_narrow(self, facts, env, fr):
        if not facts:
            return
        saved, fr.env = fr.env, env
        for path, labels in facts.items():
            current = self.read_path(path, fr)
            updated = current
            for label in sorted(labels):
                updated = updated.map_taints(lambda t, lb=label: t.sanitized(lb))
            self.write_path(path, updated, fr)
            if current.origin:
                origin_val = self.read_path(current.origin, fr)
                for label in sorted(labels):
                    origin_val = origin_val.map_taints(lambda t, lb=label: t.sanitized(lb))
                self.write_path(current.origin, origin_val, fr)
        fr.env = saved

    def _note_guards(self, cond, fr):
        """Records parameters an `if` requires, such as `isset($_POST['Submit'])`."""
        if self.discover or not self.route_stack:
            return
        stack = [cond]
        while stack:
            cur = stack.pop()
            if cur.type == "function_call_expression" and cur.f("function") is not None:
                name = cur.f("function").text.lower()
                args = self._arg_nodes(cur)
                if name in ("isset", "empty"):
                    for arg in args:
                        self._guard_param(arg, None, fr)
                elif name == "array_key_exists" and len(args) >= 2 and args[1].text in rules.SUPERGLOBALS:
                    key = self._single_literal(args[0], fr)
                    if key:
                        self._add_required(args[1].text, key, None)
                continue
            if cur.type == "binary_expression" and cur.op in ("==", "===", "!=", "!=="):
                left, right = cur.f("left"), cur.f("right")
                literal = self._single_literal(right, fr) if right is not None else None
                if left is not None and literal is not None:
                    self._guard_param(left, literal, fr)
                continue
            stack.extend(cur.kids)

    def _guard_param(self, node, value, fr):
        if node.type == "subscript_expression" and len(node.kids) >= 2 and node.kids[0].text in rules.SUPERGLOBALS:
            key = self._single_literal(node.kids[1], fr)
            if key:
                self._add_required(node.kids[0].text, key, value)

    def _add_required(self, superglobal, key, value):
        location = rules.SUPERGLOBALS.get(superglobal)
        if location not in ("query", "body", "any", "cookie"):
            return
        for route in self.route_stack[-1]:
            param = Param(key, location, value)
            existing = route.required.get((key, location))
            if existing is None or (existing.value is None and value is not None):
                route.required[(key, location)] = param

    # ---- variable paths ----

    def path_of(self, node, fr):
        """(root, key, key...) for a readable and writable place, or None."""
        if node is None:
            return None
        if node.type == "function_call_expression" and node.f("function") is not None \
                and node.f("function").text.lower() in CASE_FOLDERS:
            args = self._arg_nodes(node)
            return self.path_of(args[0], fr) if args else None
        if node.type == "parenthesized_expression" and node.kids:
            return self.path_of(node.kids[0], fr)
        if node.type == "variable_name":
            return (node.text,)
        if node.type == "subscript_expression" and node.kids:
            base = self.path_of(node.kids[0], fr)
            if base is None:
                return None
            if len(node.kids) < 2:
                return base + ("*",)
            literal = self._single_literal(node.kids[1], fr)
            return base + (literal if literal is not None else "*",)
        if node.type in ("member_access_expression", "nullsafe_member_access_expression"):
            base = self.path_of(node.f("object"), fr)
            name = node.f("name")
            if base is None or name is None:
                return None
            return base + ("->" + name.text,)
        return None

    def read_path(self, path, fr) -> Val:
        root = path[0]
        if root == "$this" and len(path) > 1 and path[1].startswith("->"):
            val = self._read_prop(fr.env.get("$this") or Val(cls=fr.cls), path[1][2:])
            return self._descend(val, path[2:])
        if root in rules.SUPERGLOBALS:
            if len(path) < 2 or path[1] == "*":
                return EMPTY
            return self._descend(self._read_superglobal(root, path[1], _Pos(self.cur_line), fr), path[2:])
        return self._descend(fr.env.get(root, EMPTY), path[1:])

    def _descend(self, val: Val, keys) -> Val:
        for key in keys:
            if key == "*":
                if val.fields:
                    val = union(Val(val.taints), *val.fields.values())
                continue
            if key.startswith("->") and val.cls and not (val.fields and key in val.fields):
                val = self._read_prop(val, key[2:])
                continue
            if val.closure == ROWS:
                val = _read_column(val, key)
                continue
            if val.fields and key in val.fields:
                val = val.fields[key]
            elif val.fields and "*" in val.fields:
                val = union(Val(val.taints), val.fields["*"])
            else:
                val = Val(_named_taints(val.taints, key), cls=None, tables=val.tables)
        return val

    def write_path(self, path, val, fr):
        root = path[0]
        if root == "$this" and len(path) > 1 and path[1].startswith("->"):
            cls = (fr.env.get("$this").cls if fr.env.get("$this") else None) or fr.cls
            if len(path) == 2:
                key = (cls, path[1][2:])
                self.props[key] = union(self.props[key], val) if key in self.props else val
            else:
                key = (cls, path[1][2:])
                self.props[key] = self._nest(self.props.get(key, EMPTY), path[2:], val)
            return
        if len(path) == 1:
            fr.env[root] = val
            return
        fr.env[root] = self._nest(fr.env.get(root, EMPTY), path[1:], val)

    def _nest(self, base: Val, keys, val) -> Val:
        fields = dict(base.fields or {})
        key = keys[0]
        fields[key] = val if len(keys) == 1 else self._nest(fields.get(key, EMPTY), keys[1:], val)
        return base.with_fields(fields)

    def _read_prop(self, recv: Val, name):
        cls = recv.cls
        seen = set()
        while cls and cls not in seen:
            seen.add(cls)
            if (cls, name) in self.props:
                return self.props[(cls, name)]
            info = self.p.classes.get(cls.lower())
            cls = info["parent"] if info else None
        return EMPTY

    def assign(self, left, val, fr, node):
        kind = left.type
        if kind in ("list_literal", "array_creation_expression"):
            for kid in left.kids:
                target = kid.kids[-1] if kid.type in ("array_element_initializer", "by_ref") and kid.kids else kid
                if target.type in ("variable_name", "subscript_expression", "member_access_expression"):
                    self.assign(target, val.flat(), fr, node)
            return
        if kind == "scoped_property_access_expression":
            scope, name = left.f("scope"), left.f("name")
            if scope is not None and name is not None:
                cls = self._scope_class(scope.text, fr)
                key = (cls, name.text.lstrip("$"))
                self.props[key] = union(self.props[key], val) if key in self.props else val
            return
        path = self.path_of(left, fr)
        if path is None:
            return
        if val.taints or val.fields:
            label = left.text[:40]
            val = val.map_taints(lambda t: t.step(fr.sf.rel, node.line, f"assigned to {label}"))
        if path[0] == "$_SESSION" and len(path) > 1 and path[1] != "*" and val.tainted:
            self._store_write(f"session:{path[1]}", val, fr, node)
        self.write_path(path, val, fr)

    def _store_write(self, store, val, fr, node):
        if self.discover:
            return
        known = self.stored.get(store)
        kept = val.with_fields(val.fields) if val.fields else Val(val.taints)
        self.stored[store] = union(known, kept) if known else kept
        meta = self.stored_meta.setdefault(store, {"file": fr.sf.rel, "line": node.line, "routes": {}})
        if self.route_stack:
            for route in self.route_stack[-1]:
                meta["routes"][route.id] = route

    def _store_read(self, store, fr, node) -> Val:
        known = self.stored.get(store)
        if known is None:
            return EMPTY
        meta = self.stored_meta[store]
        info = {"store": store, "write_file": meta["file"], "write_line": meta["line"], "meta": meta}
        def mark(taint):
            out = taint._copy(stored=info, penalty=taint.penalty + 1, comp=None, html_ctx=None, url_prefix=None)
            return out.step(fr.sf.rel, node.line, f"read back from {store}")
        return known.map_taints(mark)

    # ---- expressions ----

    def ev(self, node, fr) -> Val:
        if node is None:
            return EMPTY
        self.budget -= 1
        if self.budget < 0:
            raise Budget()
        handler = _EV.get(node.type)
        if handler:
            return handler(self, node, fr)
        if node.type in INCLUDES:
            return self.ev_include(node, fr)
        out = []
        for kid in node.kids:
            out.append(self.ev(kid, fr))
        return union(*out) if out else EMPTY

    def ev_var(self, node, fr):
        name = node.text
        if name in rules.SUPERGLOBALS:
            return self._whole_superglobal(name, node, fr)
        found = fr.env.get(name)
        if found is not None and found is not EMPTY:
            return found
        if name.lower() in rules.REQUEST_VAR_NAMES:
            return Val(closure=RequestRole(guessed=True))
        if found is not None:
            return found
        extracted = fr.env.get(EXTRACTED)
        if extracted is None:
            return EMPTY
        # extract($_GET) turns any variable that wasn't set into attacker input.
        return Val.of(self._source(name.lstrip("$"), next(iter(extracted.taints.values())).location, fr, node))

    def _whole_superglobal(self, name, node, fr):
        location = rules.SUPERGLOBALS[name]
        if location in (None, "session", "header"):
            return EMPTY
        return Val.of(self._source("*", location, fr, node))

    def _source(self, name, location, fr, node) -> Taint:
        if not self.discover and self.route_stack and name != "*":
            for route in self.route_stack[-1]:
                route.params.setdefault((name, location), Param(name, location))
                if location == "query":
                    route.methods.add("GET")
                elif location in ("body", "json"):
                    route.methods.add("POST")
                elif location == "any":
                    route.methods.update({"GET", "POST"})
        step = (fr.sf.rel, node.line, f"read from {location} parameter '{name}'")
        return Taint(name, location, (step,))

    def ev_subscript(self, node, fr):
        base_node = node.kids[0] if node.kids else None
        if base_node is None:
            return EMPTY
        if base_node.type == "variable_name" and base_node.text in rules.SUPERGLOBALS:
            key = self._single_literal(node.kids[1], fr) if len(node.kids) > 1 else None
            return self._read_superglobal(base_node.text, key, node, fr)
        if base_node.type == "subscript_expression" and base_node.kids and base_node.kids[0].text == "$_FILES":
            key = self._single_literal(node.kids[1], fr) if len(node.kids) > 1 else None
            if key == "name" or key == "type":
                outer = self._single_literal(base_node.kids[1], fr) if len(base_node.kids) > 1 else None
                return Val.of(self._source(outer or "*", "file", fr, node))
            return EMPTY
        index_node = node.kids[1] if len(node.kids) > 1 else None
        base = self.ev(base_node, fr)
        index = self.ev(index_node, fr) if index_node is not None else EMPTY
        literal = self._single_literal(index_node, fr) if index_node is not None else None
        if isinstance(base.closure, RequestRole):
            return self._request_source(literal, base.closure, "any", fr, node)
        if literal is None and index.tainted and base.fields and not base.taints:
            # A tainted key picks among known values, so the result isn't attacker text.
            taint = next(iter(index.taints.values()), None)
            values = union(*base.fields.values())
            mapping = {s: k for k, f in base.fields.items() for s in f.strs}
            selector = (taint.name, taint.location, mapping) if taint is not None else None
            return Val(values.taints, values.strs, selector=selector)
        path = self.path_of(node, fr)
        if path is not None:
            return self.read_path(path, fr)
        return self._descend(base, (literal if literal is not None else "*",))

    def _read_superglobal(self, name, key, node, fr):
        overlay = fr.env.get(name)
        if overlay is not None and overlay.fields and key in overlay.fields:
            return overlay.fields[key]
        location = rules.SUPERGLOBALS[name]
        if location is None:
            return EMPTY
        if name == "$_SESSION":
            return self._store_read(f"session:{key}", fr, node) if key else EMPTY
        if name == "$_FILES":
            return EMPTY
        if name == "$_SERVER":
            if key is None:
                return EMPTY
            if key == "DOCUMENT_ROOT":
                root = self.p.web_root
                return Val.lit(ABS + ("/" + root if root else ""))
            if key in rules.TAINTED_SERVER_KEYS:
                return Val.of(self._source(key, rules.TAINTED_SERVER_KEYS[key], fr, node))
            if key.startswith("HTTP_"):
                header = "-".join(p.capitalize() for p in key[5:].split("_"))
                return Val.of(self._source(header, "header", fr, node))
            return EMPTY
        return Val.of(self._source(key or "*", location, fr, node))

    def ev_member(self, node, fr):
        name = node.f("name")
        prop = name.text if name is not None and name.type == "name" else None
        recv = self.ev(node.f("object"), fr)
        if prop and isinstance(recv.closure, RequestRole):
            bag = rules.REQUEST_BAGS.get(prop.lower())
            if bag:
                return Val(closure=RequestRole(bag, recv.closure.guessed))
            if prop.lower() in rules.REQUEST_NON_INPUT_PROPS:
                return EMPTY
            return self._request_source(prop, recv.closure, "any", fr, node)
        path = self.path_of(node, fr)
        if path is not None:
            value = self.read_path(path, fr)
        elif name is not None and recv.cls:
            value = self._read_prop(recv, name.text)
        else:
            value = Val(recv.flat().taints)
        if prop and prop.lower() in rules.REQUEST_PROPS and not (value.tainted or value.cls or value.closure or value.fields or value.strs):
            return Val(closure=RequestRole(guessed=True))
        return value

    def _request_source(self, key, role, default_location, fr, node) -> Val:
        taint = self._source(key or "*", role.location or default_location, fr, node)
        return Val.of(taint._copy(penalty=1) if role.guessed else taint)

    def _request_value(self, role, method, arg_nodes, fr, node) -> Val:
        key = self._single_literal(arg_nodes[0], fr) if arg_nodes else None
        return self._request_source(key, role, rules.REQUEST_METHODS[method], fr, node)

    def _is_request_type(self, hint: str) -> bool:
        """A type named like a request, unless it's an unrelated class of the project's own."""
        lowered = hint.lower()
        if not lowered.endswith(rules.REQUEST_TYPE_SUFFIXES):
            return False
        return lowered not in self.p.classes or self.p.has_external_ancestor(hint)

    def _request_params(self, fd) -> dict:
        """Handlers that frameworks call directly still receive a real request object."""
        out = {}
        for param in fd.params.kids if fd.params is not None else []:
            name, type_node = param.f("name"), param.f("type")
            if name is not None and type_node is not None and self._is_request_type(type_node.text.lstrip("?").split("\\")[-1]):
                out[name.text] = Val(closure=RequestRole())
        return out

    def ev_scoped_prop(self, node, fr):
        scope, name = node.f("scope"), node.f("name")
        if scope is None or name is None:
            return EMPTY
        return self._read_prop(Val(cls=self._scope_class(scope.text, fr)), name.text.lstrip("$"))

    def _scope_class(self, scope, fr):
        lowered = scope.lower()
        if lowered in ("self", "static"):
            return fr.cls
        if lowered == "parent":
            info = self.p.classes.get((fr.cls or "").lower())
            return info["parent"] if info else None
        name = scope.split("\\")[-1]
        return fr.sf.aliases.get(name, name)

    def ev_assign(self, node, fr):
        left, right = node.f("left"), node.f("right")
        val = self.ev(right, fr)
        if left is not None:
            self.assign(left, val, fr, node)
        return val

    def ev_aug(self, node, fr):
        left, right = node.f("left"), node.f("right")
        if left is None:
            return EMPTY
        current = self.ev(left, fr)
        added = self.ev(right, fr)
        if node.op == ".=":
            result = self._join([current, added], node, fr)
        elif node.op == "??=":
            result = union(current, added)
        else:
            result = Val({t.key: t.sanitized("int") for t in union(current, added).all_taints()})
        self.assign(left, result, fr, node)
        return result

    def ev_binary(self, node, fr):
        op = node.op
        if op == ".":
            return self.ev_concat(node, fr)
        left, right = self.ev(node.f("left"), fr), self.ev(node.f("right"), fr)
        if op in COMPARISON_OPS:
            return EMPTY
        if op == "+" and (left.fields or right.fields):
            return union(left, right)  # `+` on arrays merges them
        if op in ARITHMETIC_OPS:
            return Val({t.key: t.sanitized("int") for t in union(left, right).all_taints()})
        return union(left, right)

    def ev_concat(self, node, fr):
        parts = []
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type == "binary_expression" and cur.op == ".":
                stack.append(cur.f("right"))
                stack.append(cur.f("left"))
            elif cur.type == "parenthesized_expression" and len(cur.kids) == 1 and cur.kids[0].type == "binary_expression" \
                    and cur.kids[0].op == ".":
                stack.append(cur.kids[0])
            elif cur is not None:
                parts.append(self.ev(cur, fr))
        return self._join(parts, node, fr)

    def _join(self, parts, node, fr):
        options = [""]
        taints = {}
        tables = frozenset()
        comp = None
        filled = []
        for part in parts:
            prefix = options[0]
            flat = part.flat()
            if not flat.strs or "*" in "".join(flat.strs):
                filled.append(frozenset((t.name, t.location) for t in flat.taints.values()))
            for taint in flat.taints.values():
                if comp is None:
                    comp = Comp(fr.sf.rel, node.line, fr.func, node.text[:300])
                new = taint.composed(prefix, comp)
                if len(taints) < 24:
                    taints.setdefault(new.key, new)
            piece = sorted(flat.strs)[:6] if flat.strs else ["*"]
            options = [(a + b)[:3000] for a in options for b in piece][:32]
            tables |= part.tables
        out = Val(taints, frozenset(options), tables=tables)
        out.parts = filled
        return out

    def ev_encapsed(self, node, fr):
        parts = []
        for kid in node.kids:
            if kid.type in ("string_content", "string_value", "heredoc_start", "heredoc_end", "nowdoc_string"):
                if kid.type in ("string_content", "string_value", "nowdoc_string"):
                    parts.append(Val.lit(kid.text))
            elif kid.type == "escape_sequence":
                parts.append(Val.lit(_ESCAPES.get(kid.text, kid.text[-1:])))
            elif kid.type in ("heredoc_body", "nowdoc_body"):
                return self.ev_encapsed(kid, fr)
            else:
                parts.append(self.ev(kid, fr))
        if not parts:
            return Val.lit("")
        if all(not p.taints and not p.fields and len(p.strs) == 1 for p in parts):
            return Val.lit("".join(next(iter(p.strs)) for p in parts))
        return self._join(parts, node, fr)

    def ev_string(self, node, fr):
        return Val.lit(self._literal(node))

    @staticmethod
    def _literal(node) -> str:
        if not node.kids:
            text = node.text
            return text[1:-1] if len(text) >= 2 and text[0] in "'\"" else text
        out = []
        for kid in node.kids:
            out.append(_ESCAPES.get(kid.text, kid.text[-1:]) if kid.type == "escape_sequence" else kid.text)
        return "".join(out)

    def _single_literal(self, node, fr):
        if node is None:
            return None
        if node.type in ("string", "encapsed_string", "integer", "name", "class_constant_access_expression",
                         "parenthesized_expression", "variable_name"):
            val = self.ev(node, fr)
            if len(val.strs) == 1 and not val.tainted:
                text = next(iter(val.strs))
                if "*" not in text:
                    return text
        return None

    def ev_name(self, node, fr):
        name = node.text
        lowered = name.lower()
        if name == "__DIR__":
            directory = posixpath.dirname(fr.sf.rel)
            return Val.lit(ABS + ("/" + directory if directory else ""))
        if name == "__FILE__":
            return Val.lit(ABS + "/" + fr.sf.rel)
        if lowered in ("true", "false", "null"):
            return EMPTY
        values = self.p.constants.get(name)
        if values:
            return Val(strs=frozenset(values))
        return Val(strs=frozenset({"*"}))

    def ev_integer(self, node, fr):
        return Val.lit(node.text)

    def ev_conditional(self, node, fr):
        cond, body, alt = node.f("condition"), node.f("body"), node.f("alternative")
        cond_val = self.ev(cond, fr)
        self._materialise(cond, fr)
        results, branches = [], []
        if body is not None:
            env = dict(fr.env)
            self.apply_narrow(self.narrow(cond, True, fr), env, fr)
            saved, fr.env = fr.env, env
            results.append(self.ev(body, fr))
            fr.env = saved
            branches.append(env)
        else:
            results.append(cond_val)
            branches.append(dict(fr.env))
        env = dict(fr.env)
        if alt is not None:
            self.apply_narrow(self.narrow(cond, False, fr), env, fr)
            saved, fr.env = fr.env, env
            results.append(self.ev(alt, fr))
            fr.env = saved
        branches.append(env)
        # Either side can assign: `$c ? $x = $a : $x = $b` is valid PHP.
        self._merge_into(fr.env, branches)
        return union(*results)

    def ev_cast(self, node, fr):
        kind = node.f("type")
        val = self.ev(node.f("value") or (node.kids[-1] if node.kids else None), fr)
        if kind is not None and kind.text.lower() in NUMERIC_CASTS:
            return Val({t.key: t.sanitized("int", fr.sf.rel, node.line, f"cast to {kind.text}") for t in val.all_taints()})
        return val

    def ev_unary(self, node, fr):
        arg = node.f("argument") or (node.kids[0] if node.kids else None)
        val = self.ev(arg, fr)
        return EMPTY if node.op == "!" else Val({t.key: t.sanitized("int") for t in val.all_taints()})

    def ev_array(self, node, fr):
        fields = {}
        index = 0
        for item in node.kids:
            if item.type != "array_element_initializer" or not item.kids:
                continue
            if len(item.kids) >= 2:
                key = self._single_literal(item.kids[0], fr)
                value = self.ev(item.kids[1], fr)
                fields[key if key is not None else "*"] = union(fields.get(key if key is not None else "*"), value)
            else:
                fields[str(index)] = self.ev(item.kids[0], fr)
                index += 1
        return Val(fields=fields) if fields else EMPTY

    def ev_shell(self, node, fr):
        val = self.ev_encapsed(node, fr)
        if val.tainted:
            self.sink(78, "backticks", val, node, fr)
        return Val({t.key: t for t in val.all_taints()})

    def ev_print(self, node, fr):
        for kid in node.kids:
            self.echo_sink(self.ev(kid, fr), kid, fr)
        return EMPTY

    def ev_exit(self, node, fr):
        for kid in node.kids:
            self.echo_sink(self.ev(kid, fr), kid, fr)
        return EMPTY

    def ev_closure(self, node, fr):
        """Runs a closure once with what it captures, so sinks inside are seen, and keeps it so
        that a later call can run it again with real arguments."""
        if self.discover or node.f("body") is None:
            return EMPTY
        ref = ClosureRef(node, dict(fr.env), fr.sf, fr.func, fr.cls, fr.fd)
        self._run_closure(ref, [], fr, node)
        return Val(closure=ref)

    def _run_closure(self, ref: ClosureRef, args, fr, node) -> Val:
        marker = f"closure@{id(ref.node)}"
        if self.discover or marker in self.call_stack or len(self.call_stack) >= MAX_DEPTH:
            return union(*[Val(a.flat().taints) for a in args]) if args else EMPTY
        env = dict(ref.env)
        position = 0
        params = ref.node.f("parameters")
        for param in params.kids if params is not None else []:
            name = param.f("name")
            if name is None:
                continue
            if position < len(args):
                env[name.text] = args[position]
            position += 1
        inner = Frame(env, ref.sf, ref.func, ref.cls, ref.fd)
        body = ref.node.f("body")
        self.call_stack.append(marker)
        try:
            if body.type == "compound_statement":
                self.exec_block(body.kids, inner)
                return union(*inner.returns) if inner.returns else EMPTY
            return self.ev(body, inner)
        finally:
            self.call_stack.pop()

    def _call_callable(self, callee: Val, args, fr, node):
        """Calls whatever a callable value refers to: a closure, a function name, `Class::method`
        or `[$object, 'method']`. Returns None when it can't tell what that is."""
        if isinstance(callee.closure, ClosureRef):
            return self._run_closure(callee.closure, args, fr, node)
        if callee.fields and "0" in callee.fields and "1" in callee.fields:
            method = next(iter(callee.fields["1"].strs), None)
            target = callee.fields["0"]
            if method is None or "*" in method:
                return None
            if not target.cls and target.closure is None and len(target.strs) == 1:
                cls = next(iter(target.strs)).split("\\")[-1]
                target = Val(cls=fr.sf.aliases.get(cls, cls))
            return self._dispatch_method(target, method, args, [], node, fr)
        blanks = [_BLANK] * len(args)
        for text in sorted(callee.strs):
            if "*" in text or not text:
                continue
            if "::" in text:
                cls, method = text.rsplit("::", 1)
                fd = self.p.find_method(self._scope_class(cls, fr), method.lower())
                if fd is not None:
                    return self.call_user(fd, args, fr, Val(cls=fd.cls), node)
                continue
            name = text.split("\\")[-1].lower()
            if name in self.p.functions:
                return union(*[self.call_user(fd, args, fr, None, node) for fd in self.p.functions[name][:2]])
            return self.call_builtin(name, args, blanks, node, fr)
        return None

    def _higher_order(self, name, args, node, fr):
        """Built-ins that call a function they're given. The data reaches that function's parameters."""
        position, style = rules.HIGHER_ORDER[name]
        callback = args[position] if len(args) > position else EMPTY
        data = [arg for index, arg in enumerate(args) if index != position]
        passthrough = union(*[Val(arg.flat().taints) for arg in data]) if data else EMPTY
        if style == "direct":
            result = self._call_callable(callback, data, fr, node)
        elif style == "spread":
            first = data[0] if data else EMPTY
            values = [first.fields[key] for key in sorted(first.fields)] if first.fields else [Val(first.flat().taints)]
            result = self._call_callable(callback, values, fr, node)
        elif style == "subject":
            result = self._call_callable(callback, [passthrough], fr, node)
        else:
            elements = [Val(arg.flat().taints) for arg in data]
            if name == "array_reduce":
                elements.reverse()
            result = self._call_callable(callback, elements, fr, node)
        if result is None or style == "keep":
            return passthrough
        return EMPTY if name in ("array_walk", "array_walk_recursive", "usort", "uasort", "uksort") else result

    def ev_new(self, node, fr):
        name_node = next((k for k in node.kids if k.type in ("name", "qualified_name")), None)
        args_node = next((k for k in node.kids if k.type == "arguments"), None)
        args = self._arg_vals(args_node, fr) if args_node is not None else []
        if name_node is None:
            return union(*args) if args else EMPTY
        cls = name_node.text.split("\\")[-1]
        cls = fr.sf.aliases.get(cls, cls)
        if self._is_request_type(cls):
            return Val(closure=RequestRole())
        recv = Val(cls=cls)
        ctor = self.p.find_method(cls, "__construct")
        if ctor is not None and not self.discover:
            self.call_user(ctor, args, fr, recv, node, args_node)
        elif ctor is None:
            statement = self._sql_call(f"new {cls}", args, node, fr)
            if statement is not None:
                return Val(cls=cls, tables=statement.tables)
        return recv

    # ---- calls ----

    def _arg_nodes(self, call):
        args = call.f("arguments") or next((k for k in call.kids if k.type == "arguments"), None)
        if args is None:
            return []
        out = []
        for arg in args.kids:
            if arg.type == "argument" and arg.kids:
                out.append(arg.kids[-1])
            elif arg.type not in ("comment",):
                out.append(arg)
        return out

    def _arg_vals(self, args_node, fr):
        out = []
        for arg in args_node.kids:
            if arg.type == "argument" and arg.kids:
                out.append(self.ev(arg.kids[-1], fr))
            elif arg.type != "comment":
                out.append(self.ev(arg, fr))
        return out

    def ev_call(self, node, fr):
        func = node.f("function")
        if func is None:
            return EMPTY
        arg_nodes = self._arg_nodes(node)
        first_class = _is_first_class(arg_nodes)
        if func.type not in ("name", "qualified_name", "relative_name"):
            callee = self.ev(func, fr)
            if first_class:
                return callee
            args = [self.ev(a, fr) for a in arg_nodes]
            result = self._call_callable(callee, args, fr, node)
            if result is not None:
                return result
            statement = self._sql_call("dynamic call", args, node, fr)
            if statement is not None:
                return statement
            return union(*[Val(a.flat().taints) for a in args]) if args else EMPTY
        name = func.text.split("\\")[-1]
        if first_class:
            return Val.lit(name)
        lowered = name.lower()
        if lowered in ("isset", "empty"):
            return EMPTY
        args = [self.ev(a, fr) for a in arg_nodes]
        if lowered in ("die", "exit"):
            for arg, arg_node in zip(args, arg_nodes):
                self.echo_sink(arg, arg_node, fr)
            return EMPTY
        if lowered in self.p.functions:
            results = [self.call_user(fd, args, fr, None, node, arg_nodes=arg_nodes) for fd in self.p.functions[lowered][:2]]
            return union(*results)
        return self.call_builtin(lowered, args, arg_nodes, node, fr)

    def call_builtin(self, name, args, arg_nodes, node, fr):
        file, line = fr.sf.rel, node.line
        flat_all = union(*[Val(a.flat().taints) for a in args]) if args else EMPTY
        first = args[0] if args else EMPTY

        if name in rules.HIGHER_ORDER:
            return self._higher_order(name, args, node, fr)
        if name == "header":
            return self._header_call(first, node, fr)
        if name in rules.BIND_FUNCS:
            index = rules.BIND_FUNCS[name]
            bound = union(*args[index:]) if len(args) > index else EMPTY
            self._bound(name, first, bound, node, fr)
            return EMPTY
        if name in ("file_get_contents", "fopen", "file") and any("php://input" in text for text in first.strs):
            return Val.of(self._source("*", "json", fr, node))
        if name in rules.SINK_FUNCS:
            cwe, index = rules.SINK_FUNCS[name]
            if cwe == 79 and name == "printf" and args and args[0].strs:
                self.echo_sink(self._format(args, arg_nodes, node, fr), node, fr)
                return EMPTY
            target = (union(*args) if args else EMPTY) if index is None else (args[index] if len(args) > index else EMPTY)
            if cwe == 89:
                return self._sql_sink(name, target, node, fr)
            if cwe == 79:
                self.echo_sink(target, node, fr)
                return EMPTY
            if target.tainted:
                self.sink(cwe, name, target, node, fr)
            return Val(flat_all.taints) if name == "unserialize" else EMPTY
        if name in rules.FETCH_FUNCS:
            return self._fetch(first, node, fr)
        if name in rules.NUMERIC_FUNCS:
            return Val({t.key: t.sanitized("int", file, line, f"{name}()") for t in first.all_taints()})
        if name in rules.SANITIZERS:
            label = rules.SANITIZERS[name]
            target = union(*args) if label == "sql_escape" and len(args) > 1 else first
            if name in ("htmlspecialchars", "htmlentities") and any("ENT_NOQUOTES" in n.text for n in arg_nodes[1:]):
                label = "html_noquotes"
            out = {t.key: t for t in (t.sanitized(label, file, line, f"{name}()") for t in target.all_taints())}
            return Val(out, target.strs if name != "realpath" else target.strs, origin=None)
        if name == "ob_start":
            self.buffering += 1
            return EMPTY
        if name in ("ob_get_clean", "ob_end_clean", "ob_end_flush", "ob_get_flush"):
            self.buffering = max(0, self.buffering - 1)
        if name in rules.KILL_FUNCS:
            self._weak_hash_check(name, args, arg_nodes, node, fr)
            return EMPTY
        if name in ("dirname",):
            return self._dirname(args, arg_nodes, fr)
        if name in ("sprintf", "vsprintf"):
            return self._format(args, arg_nodes, node, fr)
        if name == "filter_var" and len(args) >= 2:
            return self._filter_var(args, arg_nodes, file, line)
        if name == "filter_input" and len(args) >= 2:
            return self._filter_input(args, arg_nodes, node, fr)
        if name == "preg_replace" and len(args) >= 3:
            pattern = self._single_literal(arg_nodes[0], fr)
            if pattern and strict_replace_safe(pattern):
                return args[2].map_taints(lambda t: t.sanitized("allowlist", file, line, "preg_replace() keeps safe characters"))
            return Val({t.key: t.step(file, line, "preg_replace() filter") for t in args[2].all_taints()})
        if name in ("str_replace", "str_ireplace") and len(args) >= 3:
            return Val({t.key: t.step(file, line, f"{name}() filter, not a real protection") for t in args[2].all_taints()},
                       args[2].strs)
        if name == "strip_tags":
            return Val({t.key: t.step(file, line, "strip_tags()") for t in first.all_taints()})
        if name == "parse_url":
            origin = self.path_of(arg_nodes[0], fr) if arg_nodes else None
            return Val(first.flat().taints, origin=origin)
        if name == "parse_str" and len(arg_nodes) >= 2:
            self.assign(arg_nodes[1], Val(first.flat().taints), fr, node)
            return EMPTY
        if name == "preg_match" and len(arg_nodes) >= 3:
            self.assign(arg_nodes[2], Val(args[1].flat().taints), fr, node)
            return EMPTY
        if name in ("request", "input"):
            key = self._single_literal(arg_nodes[0], fr) if arg_nodes else None
            return Val.of(self._source(key, "any", fr, node)) if key else Val(closure=RequestRole())
        if name in ("getallheaders", "apache_request_headers"):
            return Val.of(self._source("*", "header", fr, node))
        if name == "extract":
            if first.fields:
                for key, value in first.fields.items():
                    if key != "*":
                        fr.env["$" + key] = value
            if first.taints:
                fr.env[EXTRACTED] = Val(first.taints)
            return EMPTY
        if name == "compact":
            fields = {}
            for arg in args:
                for text in arg.strs:
                    if "$" + text in fr.env:
                        fields[text] = fr.env["$" + text]
            return Val(fields=fields) if fields else EMPTY
        if name == "define":
            return EMPTY
        if name in rules.PASSTHROUGH_FUNCS:
            return Val(flat_all.taints)
        rendered = self._render_if_template(name, args, node, fr)
        if rendered is not None:
            return rendered
        statement = self._sql_call(name, args, node, fr)
        if statement is not None:
            return statement
        # An unknown function may or may not clean its input, so taint continues at lower confidence.
        if not flat_all.taints:
            return EMPTY
        return Val({t.key: t for t in (x._copy(penalty=x.penalty + 1).step(file, line, f"passed through {name}()")
                                       for x in flat_all.taints.values())})

    def _weak_hash_check(self, name, args, arg_nodes, node, fr):
        value = None
        if name in ("md5", "sha1") and args:
            value = args[0]
        elif name == "hash" and len(args) >= 2:
            algorithm = self._single_literal(arg_nodes[0], fr)
            if algorithm and algorithm.lower() in ("md5", "sha1", "crc32"):
                value = args[1]
        if value is None:
            return
        for arg_node in arg_nodes:
            if PASSWORD_NAME.search(arg_node.text):
                self.sink(328, name, value if value.tainted else Val.of(Taint("*", "unknown", ())), node, fr)
                return
        if any(PASSWORD_NAME.search(t.name) for t in value.all_taints()):
            self.sink(328, name, value, node, fr)

    def _filter_var(self, args, arg_nodes, file, line):
        flag = arg_nodes[1].text
        value = args[0]
        if "VALIDATE_INT" in flag or "VALIDATE_FLOAT" in flag or "NUMBER_INT" in flag or "NUMBER_FLOAT" in flag or "VALIDATE_BOOL" in flag:
            return value.map_taints(lambda t: t.sanitized("int", file, line, "filter_var() numeric filter"))
        if "SPECIAL_CHARS" in flag or "STRING" in flag:
            return value.map_taints(lambda t: t.sanitized("html_escape", file, line, "filter_var() escaping filter"))
        if "VALIDATE_IP" in flag or "VALIDATE_EMAIL" in flag:
            return value.map_taints(lambda t: t.sanitized("allowlist", file, line, "filter_var() strict format"))
        return value

    def _filter_input(self, args, arg_nodes, node, fr):
        kind = arg_nodes[0].text
        location = {"INPUT_GET": "query", "INPUT_POST": "body", "INPUT_COOKIE": "cookie"}.get(kind)
        key = self._single_literal(arg_nodes[1], fr)
        if location is None or key is None:
            return EMPTY
        value = Val.of(self._source(key, location, fr, node))
        if len(arg_nodes) >= 3:
            return self._filter_var([value, args[2]], [arg_nodes[0], arg_nodes[2]], fr.sf.rel, node.line)
        return value

    def _dirname(self, args, arg_nodes, fr):
        if not args:
            return EMPTY
        levels = 1
        if len(arg_nodes) > 1 and arg_nodes[1].type == "integer":
            levels = int(arg_nodes[1].text)
        out = set()
        for text in sorted(args[0].strs):
            for _ in range(levels):
                text = posixpath.dirname(text) if "/" in text else "."
            out.add(text)
        return Val(args[0].flat().taints, frozenset(out))

    def _format(self, args, arg_nodes, node, fr):
        """Treats sprintf as a concatenation, so `%d` counts as a numeric cast."""
        if not args:
            return EMPTY
        if not args[0].strs or len(args[0].strs) != 1:
            return Val(union(*args).flat().taints)
        fmt = next(iter(args[0].strs))
        pieces = re.split(r"(%(?:\d+\$)?[-+ 0']*\d*(?:\.\d+)?[a-zA-Z%])", fmt)
        parts = []
        index = 1
        values = list(args[1:])
        for piece in pieces:
            if not re.fullmatch(r"%(?:\d+\$)?[-+ 0']*\d*(?:\.\d+)?[a-zA-Z%]", piece):
                parts.append(Val.lit(piece))
                continue
            if piece == "%%":
                parts.append(Val.lit("%"))
                continue
            value = values[index - 1] if index - 1 < len(values) else EMPTY
            index += 1
            if piece[-1] in "dufFeEgGxXobc":
                value = Val({t.key: t.sanitized("int", fr.sf.rel, node.line, f"formatted with {piece}") for t in value.all_taints()})
            parts.append(value)
        return self._join(parts, node, fr)

    def _header_call(self, val, node, fr):
        for text in val.strs:
            lowered = text.lower()
            if lowered.startswith("content-type:") and any(k in lowered for k in rules.HEADER_SAFE_TYPES):
                self.non_html = True
        is_location = any(s.lower().lstrip().startswith("location") for s in val.strs)
        if val.tainted and is_location:
            self.sink(601, "header('Location')", val, node, fr)
        return EMPTY

    def _bound(self, name, stmt: Val, bound: Val, node, fr, pairs=None):
        """A bound value can't inject SQL, but it can still be stored and shown later."""
        if not bound.tainted:
            return
        self.sink(89, name, bound, node, fr, forced_safe="bound")
        for table in sorted(stmt.tables):
            if not table.startswith("w:"):
                continue
            columns = sql_columns.bound_columns(min(stmt.strs, default=""), pairs or [])
            self._store_write(f"db:{table[2:]}", Val(fields=columns) if columns else bound, fr, node)

    def _sql_call(self, name, args, node, fr):
        """Any call we can't see into, given a string that reads like SQL, is treated as running it.
        This covers database libraries and wrappers without having to list them, at lower
        confidence because the code doing the work isn't visible."""
        if name in rules.LOGGING_CALLS:
            return None
        for position, arg in enumerate(args):
            if arg.closure is ROWS:
                continue  # what a query returned, not a query: it only keeps the SQL text it came from
            if any(rules.SQL_STATEMENT.match(text) for text in arg.strs):
                result = self._sql_sink(name, arg, node, fr, penalty=1)
                # DB::insert($sql, [$a, $b]) hands its values over as a list. They can't inject, but they are stored.
                bindings = next((a for a in args[position + 1:] if a.fields), None)
                if bindings is not None:
                    self._bound(name, result, union(*bindings.fields.values()), node, fr, list(bindings.fields.items()))
                rows = self._fetch(result, node, fr)
                return Val(rows.taints, result.strs, rows.fields, tables=result.tables, closure=rows.closure)
        return None

    def _sql_sink(self, name, target, node, fr, penalty=0):
        tables = set()
        for text in sorted(target.strs):
            match = WRITE_TABLE.search(text)
            if match:
                if target.tainted:
                    columns = sql_columns.string_columns(text, target)
                    self._store_write(f"db:{match.group(1).lower()}", Val(fields=columns) if columns else target, fr, node)
                tables.add("w:" + match.group(1).lower())
            else:
                tables.update(t.lower() for t in READ_TABLE.findall(text))
        if target.tainted:
            self.sink(89, name, target, node, fr, penalty=penalty)
        return Val(strs=target.strs, tables=frozenset(tables))

    def _fetch(self, result: Val, node, fr):
        out = [self._store_read(f"db:{t}", fr, node) for t in sorted(result.tables) if not t.startswith("w:")]
        if not out:
            return EMPTY
        rows = union(*out)
        rows = Val(rows.taints, fields=rows.fields, closure=ROWS)
        return rows

    def ev_method_call(self, node, fr):
        recv_node = node.f("object")
        recv = self.ev(recv_node, fr)
        name_node = node.f("name")
        arg_nodes = self._arg_nodes(node)
        if _is_first_class(arg_nodes) and name_node is not None and name_node.type == "name":
            return Val(fields={"0": recv, "1": Val.lit(name_node.text)})
        args = [self.ev(a, fr) for a in arg_nodes]
        if name_node is None or name_node.type != "name":
            method = self._single_literal(name_node, fr)
            if method:
                return self._dispatch_method(recv, method, args, arg_nodes, node, fr)
            statement = self._sql_call("dynamic call", args, node, fr)
            if statement is not None:
                return statement
            return union(*[Val(a.flat().taints) for a in args]) if args else EMPTY
        return self._dispatch_method(recv, name_node.text, args, arg_nodes, node, fr)

    def ev_scoped_call(self, node, fr):
        scope, name_node = node.f("scope"), node.f("name")
        arg_nodes = self._arg_nodes(node)
        if scope is None or name_node is None:
            return EMPTY
        cls = self._scope_class(scope.text, fr)
        if _is_first_class(arg_nodes):
            return Val.lit(f"{cls}::{name_node.text}")
        args = [self.ev(a, fr) for a in arg_nodes]
        lowered = name_node.text.lower()
        if cls in ("Request", "Input") and lowered in rules.REQUEST_METHODS:
            return self._request_value(RequestRole(), lowered, arg_nodes, fr, node)
        if cls in ("Redirect",) and lowered in ("to", "away") and args and args[0].tainted:
            self.sink(601, f"Redirect::{lowered}", args[0], node, fr)
            return EMPTY
        fd = self.p.find_method(cls, lowered)
        if fd is not None:
            return self.call_user(fd, args, fr, Val(cls=fd.cls), node, arg_nodes=arg_nodes)
        return self._external_method(lowered, Val(cls=None), args, arg_nodes, node, fr)

    def _dispatch_method(self, recv, name, args, arg_nodes, node, fr):
        lowered = name.lower()
        if isinstance(recv.closure, RequestRole) and lowered in rules.REQUEST_METHODS:
            return self._request_value(recv.closure, lowered, arg_nodes, fr, node)
        if lowered in rules.ASSIGN_VERBS and not self.discover:
            self._assign_template_vars(args, arg_nodes, fr)
            if isinstance(recv.closure, TemplateRef):
                self._render(recv.closure.names, self.assigned, fr, node)
            if lowered not in self.p.methods_by_name:
                return recv
        if recv.cls:
            fd = self.p.find_method(recv.cls, lowered)
            if fd is not None:
                return self.call_user(fd, args, fr, recv, node, arg_nodes=arg_nodes)
            if recv.cls.lower() in self.p.classes:
                return self._external_method(lowered, recv, args, arg_nodes, node, fr)
        candidates = self.p.methods_by_name.get(lowered, [])
        external = self._external_method(lowered, recv, args, arg_nodes, node, fr) if (
            lowered in rules.SINK_METHODS or not candidates) else EMPTY
        if candidates and lowered not in rules.FETCH_METHODS and len(candidates) <= 4:
            penalty = 0 if len(candidates) == 1 else 1
            results = [self.call_user(fd, args, fr, Val(cls=fd.cls), node, penalty=penalty, arg_nodes=arg_nodes)
                       for fd in candidates]
            return union(external, *results)
        return external

    def _external_method(self, lowered, recv, args, arg_nodes, node, fr):
        file, line = fr.sf.rel, node.line
        rendered = self._render_if_template(lowered, args, node, fr)
        if rendered is not None:
            return rendered
        if lowered in rules.SINK_METHODS:
            cwe, index = rules.SINK_METHODS[lowered]
            target = args[index] if len(args) > index else EMPTY
            if cwe == 89:
                return self._sql_sink(lowered, target, node, fr)
            if target.tainted:
                self.sink(cwe, lowered, target, node, fr)
            return EMPTY
        # Before binding and fetching: `$db->execute("UPDATE ..." . $x)` runs SQL it was handed.
        statement = self._sql_call(lowered, args, node, fr)
        if statement is not None:
            return statement
        if lowered in rules.REQUEST_GETTERS and not args:
            return Val(closure=RequestRole(guessed=True))
        if lowered in rules.BIND_METHODS:
            index = rules.BIND_METHODS[lowered]
            bound = union(*args[index:]) if len(args) > index else EMPTY
            self._bound(lowered, recv, bound, node, fr, sql_columns.bound_pairs(lowered, args, self._single_literal, arg_nodes, fr))
            return recv
        if lowered in rules.SANITIZER_METHODS:
            label = rules.SANITIZER_METHODS[lowered]
            target = args[0] if args else EMPTY
            return Val({t.key: t.sanitized(label, file, line, f"{lowered}()") for t in target.all_taints()}, target.strs)
        if lowered in rules.FETCH_METHODS:
            return self._fetch(recv, node, fr)
        if lowered == "to" and args and args[0].tainted:
            self.sink(601, "redirect()->to", args[0], node, fr)
            return EMPTY
        flat = union(*[Val(a.flat().taints) for a in args]) if args else EMPTY
        if not flat.taints:
            return Val(tables=recv.tables)
        return Val({t.key: t for t in (x._copy(penalty=x.penalty + 1).step(file, line, f"passed through {lowered}()")
                                       for x in flat.taints.values())})

    def call_user(self, fd: FuncDef, args, fr, recv, node, args_node=None, penalty=0, arg_nodes=None):
        if self.discover:
            return union(*[Val(a.flat().taints) for a in args]) if args else EMPTY
        self.executed_funcs.add(fd.id)
        self._cover(fd.sf.rel)
        if fd.id in self.call_stack or len(self.call_stack) >= MAX_DEPTH:
            return union(*[Val(a.flat().taints) for a in args]) if args else EMPTY
        key = (fd.id, recv.cls if recv else None, penalty, tuple(a.sig() for a in args))
        cacheable = not fd.uses_global
        if cacheable and key in self.memo:
            result, hits = self.memo[key]
            for hit in hits:
                self._reattach(hit)
            return result
        env = {}
        if recv is not None:
            env["$this"] = recv
        self._bind_params(fd, args, env, fr, node)
        inner = Frame(env, fd.sf, fd.label, fd.cls, fd)
        if fd.uses_global and self.call_stack is not None:
            self._bind_globals(fd, env, fr)
        self.call_stack.append(fd.id)
        self.include_stack.append(fd.sf.rel)
        self.low_conf += penalty
        self.collectors.append([])
        saved_tail = self.html_tail
        try:
            self.exec_block(fd.body.kids, inner)
        finally:
            self.call_stack.pop()
            self.include_stack.pop()
            self.low_conf -= penalty
            gathered = self.collectors.pop()
            if self.collectors:
                self.collectors[-1].extend(gathered)
        self.html_tail = saved_tail
        result = union(*inner.returns) if inner.returns else EMPTY
        if result is not EMPTY:
            result = result.map_taints(lambda t: t.step(fr.sf.rel, node.line, f"returned from {fd.label}()"))
        if fd.uses_global:
            self._return_globals(fd, env, fr)
        if arg_nodes:
            self._write_back_refs(fd, env, arg_nodes, fr, node)
        if cacheable:
            self.memo[key] = (result, gathered)
        return result

    def _bind_params(self, fd, args, env, fr, node):
        if fd.params is None:
            return
        index = 0
        for param in fd.params.kids:
            if param.type not in ("simple_parameter", "variadic_parameter", "property_promotion_parameter"):
                continue
            name = param.f("name")
            if name is None:
                continue
            if param.type == "variadic_parameter":
                value = union(*args[index:]) if len(args) > index else EMPTY
            elif index < len(args):
                value = args[index]
            else:
                default = param.f("default_value")
                value = self.ev(default, Frame({}, fd.sf)) if default is not None else EMPTY
            index += 1
            if value is not EMPTY and value.tainted:
                label = name.text
                value = value.map_taints(lambda t: t.step(fr.sf.rel, node.line, f"passed to {fd.label}({label})"))
            env[name.text] = value
            if param.type == "property_promotion_parameter":
                self.props[(fd.cls, name.text.lstrip("$"))] = value
            type_node = param.f("type")
            if type_node is not None and value.cls is None and not value.tainted:
                hint = type_node.text.lstrip("?").split("\\")[-1]
                if value.closure is None and self._is_request_type(hint):
                    env[name.text] = Val(closure=RequestRole())
                elif hint.lower() in self.p.classes:
                    env[name.text] = value.with_fields(value.fields)
                    env[name.text].cls = hint

    def _write_back_refs(self, fd, env, arg_nodes, fr, node):
        if fd.params is None:
            return
        index = 0
        for param in fd.params.kids:
            if param.type not in ("simple_parameter", "variadic_parameter", "property_promotion_parameter"):
                continue
            has_ref = param.f("reference_modifier") is not None
            name = param.f("name")
            if has_ref and name is not None and index < len(arg_nodes):
                self.assign(arg_nodes[index], env.get(name.text, EMPTY), fr, node)
            index += 1

    def _globals_for(self, fd):
        names = []
        stack = [fd.body]
        while stack:
            cur = stack.pop()
            if cur.type == "global_declaration":
                names.extend(k.text for k in cur.kids if k.type == "variable_name")
            elif cur.type not in ("function_definition", "method_declaration", "class_declaration"):
                stack.extend(cur.kids)
        return names

    def _bind_globals(self, fd, env, fr):
        top = self._top_env(fr)
        for name in self._globals_for(fd):
            if name in top:
                env[name] = top[name]

    def _return_globals(self, fd, env, fr):
        top = self._top_env(fr)
        for name in self._globals_for(fd):
            if name in env:
                top[name] = env[name]

    def _top_env(self, fr):
        return self.top_frame.env if self.top_frame is not None else fr.env

    def _reattach(self, hit: Hit):
        if self.route_stack:
            for route in self.route_stack[-1]:
                hit.routes[route.id] = route
        if self.collectors:
            self.collectors[-1].append(hit)

    def _assign_template_vars(self, args, arg_nodes, fr):
        """Remembers `->with('name', $value)` and `->assign(['name' => $value])` for the next render."""
        if len(args) >= 2 and arg_nodes:
            key = self._single_literal(arg_nodes[0], fr)
            if key:
                self.assigned[key] = args[1]
        elif args and args[0].fields:
            self.assigned.update(args[0].fields)

    def _render_if_template(self, verb, args, node, fr):
        """Recognises a call that renders a template in this project, whichever library does it.
        A file name with a template extension is enough. A bare name also needs a verb like `render`,
        so that `$cache->get('home')` doesn't count just because a view is called home."""
        if self.discover:
            return None
        names = []
        for arg in args:
            for text in arg.strs:
                if text not in self.p.templates and text not in self.p.php_views:
                    continue
                if verb in rules.RENDER_VERBS or text.endswith((".twig", ".tpl", ".blade.php", ".phtml")):
                    names.append(text)
        if not names:
            return None
        fields = {key: value for arg in args for key, value in (arg.fields or {}).items()}
        self._render(names, {**self.assigned, **fields}, fr, node)
        return Val(closure=TemplateRef(names))

    def _render(self, names, fields, fr, node):
        for name in sorted(set(names)):
            rel = self.p.templates.get(name)
            if rel is not None:
                for line, variable, expr in self.p.template_raw.get(rel, ()):
                    value = fields.get(variable)
                    if value is not None and value.tainted:
                        for taint in value.all_taints():
                            self._record_at(79, "unescaped template output", taint, rel, line, expr, fr)
                continue
            rel = self.p.php_views.get(name)
            if rel in self.p.files:
                env = {"$" + key: value for key, value in fields.items() if key != "*"}
                if "$this" in fr.env:
                    env["$this"] = fr.env["$this"]
                self._run_included(rel, Frame(env, self.p.files[rel], cls=fr.cls, fd=fr.fd), False)

    # ---- includes ----

    def ev_include(self, node, fr):
        once = node.type in ONCE
        expr = node.kids[0] if node.kids else None
        if expr is None:
            return EMPTY
        val = self.ev(expr, fr)
        if val.tainted and not self.discover:
            self.sink(22, node.type.split("_")[0], val, node, fr)
        targets = self._include_targets(val, fr)
        # Files nothing names can still run through this, so they aren't known to be unreachable.
        if val.tainted or not val.strs or any("*" in text for text in val.strs):
            self.dynamic_include = True
        if self.discover:
            bucket = self.edges.setdefault(fr.sf.rel, set())
            bucket.update(rel for rel, _, _ in targets if not val.selector)
            return EMPTY
        if not targets:
            return EMPTY
        label = self._include_var(expr)
        many = len(targets) > 1
        branches = []
        base = fr.env
        for rel, selector_route, penalty in targets:
            env = dict(base) if many else base
            saved, fr.env = fr.env, env
            pushed = False
            if selector_route is not None:
                self.route_stack.append(selector_route)
                pushed = True
            if many and label:
                self.conditions.append(f"{label} == '{posixpath.basename(rel)}'")
            self.low_conf += penalty
            self._run_included(rel, fr, once)
            self.low_conf -= penalty
            if many and label:
                self.conditions.pop()
            if pushed:
                self.route_stack.pop()
            fr.env = saved
            branches.append(env)
        if many:
            self._merge_into(fr.env, branches + [base])
        return EMPTY

    @staticmethod
    def _include_var(expr):
        stack = [expr]
        while stack:
            cur = stack.pop()
            if cur.type == "variable_name":
                return cur.text
            stack.extend(cur.kids)
        return None

    def _run_included(self, rel, fr, once):
        if rel in self.include_stack or (once and rel in self.once):
            return
        self.once.add(rel)
        self.executed_files.add(rel)
        self._cover(rel)
        sf = self.p.files[rel]
        saved_sf, saved_func = fr.sf, fr.func
        saved_pending = self.pending_echo
        self.pending_echo = False
        fr.sf = sf
        self.include_stack.append(rel)
        try:
            self.exec_block(sf.tree.kids, fr)
        finally:
            self.include_stack.pop()
            fr.sf, fr.func = saved_sf, saved_func
            self.pending_echo = saved_pending

    def _include_targets(self, val: Val, fr):
        """Returns (file, selector routes or None, confidence penalty) for each possible include."""
        out, seen = [], set()
        cur = fr.sf.rel
        def add(rel, routes=None, penalty=0):
            if rel in self.p.files and rel not in seen:
                seen.add(rel)
                out.append((rel, routes, penalty))
        taints = [t for t in val.flat().taints.values()]
        if val.selector and not self.discover and self.route_stack:
            name, _, mapping = val.selector
            for text in sorted(val.strs):
                for rel in self.p.resolve_include(text, cur, self.entry_rel):
                    add(rel, self._selector_routes(name, mapping.get(text, text), rel))
        for text in sorted(val.strs):
            if text == "*" or not text:
                continue
            for rel in self.p.resolve_include(text, cur, self.entry_rel):
                is_pattern = "*" in text
                if is_pattern and taints:
                    continue
                add(rel, None, 1 if is_pattern else 0)
        if taints and not self.discover and self.route_stack:
            names = {t.name for t in taints if t.location in ("query", "any", "body")}
            for name in sorted(names):
                for value in sorted(self.p.links.get(name, ())):
                    patterns = sorted(s for s in val.strs if "*" in s) or ["*"]
                    for pattern in patterns:
                        candidate = pattern.replace("*", value, 1)
                        for rel in self.p.resolve_include(candidate, cur, self.entry_rel):
                            add(rel, self._selector_routes(name, value, rel))
        return out

    def _selector_routes(self, name, value, rel):
        base = self.route_stack[-1][0] if self.route_stack else None
        if base is None:
            return None
        self.selector_targets.add(rel)
        out = [self.routes.get(base.path, f"{name}={value}", kind="selector", handler=rel, aliases=base.aliases)]
        direct = self.routes.for_file(rel)
        if direct is not None:
            out.append(direct)
        return out

    # ---- sinks ----

    def echo_sink(self, val, node, fr):
        if self.discover or not val.tainted:
            return
        self.sink(79, "echo", val, node, fr)
        if any(META_REFRESH.search(text) for text in val.strs):
            self.sink(601, "meta refresh", val, node, fr)

    def sink(self, cwe, sink_name, val, node, fr, forced_safe=None, penalty=0):
        if self.discover:
            return
        for taint in val.all_taints():
            reason = None
            if forced_safe:
                reason = rules.LABEL_TEXT[forced_safe]
            else:
                reason = self._protection(cwe, taint, sink_name)
            self._record(cwe, sink_name, taint, reason, node, fr, penalty)

    def _protection(self, cwe, taint, sink_name=""):
        san = taint.san
        text = rules.LABEL_TEXT
        if "int" in san:
            return text["int"]
        if "allowlist" in san:
            return text["allowlist"]
        if cwe == 89:
            if "sql_quote" in san:
                return text["sql_quote"]
            if "sql_escape" in san and taint.sql_quoted:
                return text["sql_escape"]
        elif cwe == 79:
            if self.non_html:
                return text["non_html"]
            ctx = taint.html_ctx or html_context(self.html_tail)
            if "html_escape" in san and ctx in ("body", "attr_quoted"):
                return text["html_escape"]
            if "html_noquotes" in san and ctx == "body":
                return text["html_escape"]
        elif cwe == 78:
            if "shell_arg" in san:
                return text["shell_arg"]
        elif cwe == 22:
            if "path_base" in san:
                return text["path_base"]
            if "path_real" in san and "path_prefix" in san:
                return text["path_real"]
        elif cwe == 601:
            if not sink_name.startswith("meta") and _url_is_fixed(taint.url_prefix):
                return text["fixed_url"]
        return None

    def _record_at(self, cwe, sink_name, taint, rel, line, expr, fr):
        """Records a sink in a file this interpreter doesn't parse, such as a Blade template."""
        hit = Hit()
        protected = taint.san & {"int", "allowlist", "html_escape", "html_noquotes"}
        hit.cwe, hit.sink, hit.taint = cwe, sink_name, taint
        hit.reason = rules.LABEL_TEXT["html_escape"] if protected else None
        hit.file, hit.line, hit.func, hit.expr = rel, line, "<template>", expr
        hit.sink_step = (rel, line, f"reaches sink {sink_name}")
        hit.routes = {r.id: r for r in self.route_stack[-1]} if self.route_stack else {}
        hit.conditions, hit.penalty, hit.downgraded = [], taint.penalty, False
        self.hits.append(hit)
        if self.collectors:
            self.collectors[-1].append(hit)

    def _record(self, cwe, sink_name, taint, reason, node, fr, penalty=0):
        comp = taint.comp
        same_place = comp is not None and comp.file == fr.sf.rel and comp.line == node.line
        use_comp = comp is not None and not same_place and (cwe == 79 or comp.file != fr.sf.rel or comp.func != fr.func)
        hit = Hit()
        hit.cwe, hit.sink, hit.taint, hit.reason = cwe, sink_name, taint, reason
        if use_comp:
            hit.file, hit.line, hit.func, hit.expr = comp.file, comp.line, comp.func, comp.text
        else:
            hit.file, hit.line, hit.func, hit.expr = fr.sf.rel, node.line, fr.func, node.text[:300]
        if comp is not None and not use_comp:
            # `$db->query($sql)` can appear twice with different queries, and those are different bugs.
            hit.expr = f"{hit.expr}|{comp.text}"
        hit.sink_step = (fr.sf.rel, node.line, f"reaches sink {sink_name}")
        hit.routes = {r.id: r for r in self.route_stack[-1]} if self.route_stack else {}
        hit.conditions = list(self.conditions)
        hit.penalty = taint.penalty + self.low_conf + penalty
        if cwe == 79 and (taint.location == "header" or taint.name in ("REQUEST_URI", "QUERY_STRING")):
            hit.penalty += 1  # browsers encode these or won't let another site set them
        if cwe == 79 and self.buffering:
            hit.penalty += 1  # buffered output may never reach the page
        hit.downgraded = cwe == 78 and "shell_cmd" in taint.san
        self.hits.append(hit)
        if self.collectors:
            self.collectors[-1].append(hit)


def _read_column(row: Val, key):
    """Reads `$row['col']` or `$row->col`. A position could be any column, so it means all of them."""
    name = key[2:] if key.startswith("->") else key
    if row.fields and name.lower() in row.fields:
        return union(Val(row.taints), row.fields[name.lower()])
    if key.isdigit() or key == "*":
        return union(Val(row.taints), *(row.fields or {}).values())
    return Val(row.taints)


def _named_taints(taints, key):
    """`$data = json_decode(...); $data['id']` tells us the parameter is `id`."""
    if key.startswith("->") or key.isdigit():
        return taints
    out = {}
    for taint in taints.values():
        named = taint._copy(name=key) if taint.name == "*" else taint
        out[named.key] = named
    return out


def _does_work(stmts) -> bool:
    """False for case bodies that only set variables, which is configuration rather than routing."""
    stack = list(stmts)
    while stack:
        cur = stack.pop()
        if cur.type in ("echo_statement", "function_call_expression", "member_call_expression", "scoped_call_expression",
                        "print_intrinsic", "text", *INCLUDES):
            return True
        stack.extend(cur.kids)
    return False


def _is_first_class(arg_nodes) -> bool:
    """`strlen(...)` makes a callable out of a function instead of calling it."""
    return bool(arg_nodes) and arg_nodes[0].type == "variadic_placeholder"


class _BlankNode:
    """Stands in for an argument's syntax when a function is called through a callback."""
    type, text, kids, line = "", "", (), 0

    def f(self, name):
        return None


_BLANK = _BlankNode()


class _Pos:
    """Stands in for a node when only a line number is needed."""
    __slots__ = ("line",)

    def __init__(self, line):
        self.line = line


def _url_is_fixed(prefix) -> bool:
    """True when fixed text before the input stops it choosing where the redirect goes."""
    if prefix is None:
        return False
    rest = re.sub(r"^\s*location\s*:\s*", "", prefix, flags=re.I)
    if rest.startswith("*"):
        return True
    if rest in ("", "/", "//", "http://", "https://", "http:", "https:"):
        return False
    return True


_ESCAPES = {"\\n": "\n", "\\t": "\t", "\\r": "\r", '\\"': '"', "\\'": "'", "\\\\": "\\", "\\$": "$"}

_EV = {
    "variable_name": Interpreter.ev_var,
    "subscript_expression": Interpreter.ev_subscript,
    "member_access_expression": Interpreter.ev_member,
    "nullsafe_member_access_expression": Interpreter.ev_member,
    "scoped_property_access_expression": Interpreter.ev_scoped_prop,
    "assignment_expression": Interpreter.ev_assign,
    "reference_assignment_expression": Interpreter.ev_assign,
    "augmented_assignment_expression": Interpreter.ev_aug,
    "binary_expression": Interpreter.ev_binary,
    "encapsed_string": Interpreter.ev_encapsed,
    "heredoc": Interpreter.ev_encapsed,
    "nowdoc": Interpreter.ev_encapsed,
    "string": Interpreter.ev_string,
    "name": Interpreter.ev_name,
    "integer": Interpreter.ev_integer,
    "conditional_expression": Interpreter.ev_conditional,
    "cast_expression": Interpreter.ev_cast,
    "unary_op_expression": Interpreter.ev_unary,
    "array_creation_expression": Interpreter.ev_array,
    "shell_command_expression": Interpreter.ev_shell,
    "print_intrinsic": Interpreter.ev_print,
    "exit_statement": Interpreter.ev_exit,
    "anonymous_function": Interpreter.ev_closure,
    "arrow_function": Interpreter.ev_closure,
    "object_creation_expression": Interpreter.ev_new,
    "function_call_expression": Interpreter.ev_call,
    "member_call_expression": Interpreter.ev_method_call,
    "nullsafe_member_call_expression": Interpreter.ev_method_call,
    "scoped_call_expression": Interpreter.ev_scoped_call,
}
