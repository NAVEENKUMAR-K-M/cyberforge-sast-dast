"""Parses a PHP source tree and indexes its files, functions, classes and links."""
from __future__ import annotations

import fnmatch
import os
import posixpath
import re

import tree_sitter
import tree_sitter_php

SOURCE_EXTS = {".php", ".inc", ".phtml", ".php5", ".php7"}
# Parsed as PHP only when they really contain PHP.
MIXED_EXTS = {".tpl", ".html", ".htm"}
TEMPLATE_DIRS = {"views", "view", "templates", "template", "tpl"}
DEFAULT_EXCLUDES = {"vendor", "node_modules", "bower_components", ".git", "tests", "test", "__tests__", "docs"}
ABS = "<abs>"  # stands in for the project root when a path comes from __DIR__ and friends
MAX_FILE_BYTES = 1_500_000

_parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_php.language_php()))


class N:
    """A plain copy of a syntax node. Far faster to walk than tree-sitter's objects."""
    __slots__ = ("type", "kids", "fields", "line", "end_line", "sb", "eb", "op", "sf")

    def __init__(self, type_, line, end_line, sb, eb, sf):
        self.type, self.line, self.end_line, self.sb, self.eb, self.sf = type_, line, end_line, sb, eb, sf
        self.kids, self.fields, self.op = [], {}, None

    def f(self, name):
        got = self.fields.get(name)
        return got[0] if got else None

    def fl(self, name):
        return self.fields.get(name, [])

    @property
    def text(self) -> str:
        return self.sf.data[self.sb:self.eb].decode("utf-8", "replace")


def _convert(root, sf) -> N:
    """Copies the tree with a cursor, without recursion, so deep nesting is safe."""
    cursor = root.walk()
    top = None
    stack = []
    while True:
        node = cursor.node
        name = cursor.field_name
        if node.is_named:
            item = N(node.type, node.start_point[0] + 1, node.end_point[0] + 1, node.start_byte, node.end_byte, sf)
            if stack:
                stack[-1].kids.append(item)
                if name:
                    stack[-1].fields.setdefault(name, []).append(item)
            else:
                top = item
        else:
            if name == "operator" and stack:
                stack[-1].op = node.type
            item = None
        if item is not None and cursor.goto_first_child():
            stack.append(item)
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return top
            if stack and cursor.node.is_named:
                stack.pop()


class FuncDef:
    __slots__ = ("id", "name", "cls", "node", "params", "body", "sf", "uses_global", "always_exits")

    def __init__(self, name, cls, node, sf):
        self.name, self.cls, self.node, self.sf = name, cls, node, sf
        self.id = f"{cls or ''}::{name}@{sf.rel}:{node.line}"
        self.params = node.f("parameters")
        self.body = node.f("body")
        self.uses_global = _contains(self.body, {"global_declaration"}) if self.body else False
        self.always_exits = _always_exits(self.body) if self.body else False

    @property
    def label(self):
        return f"{self.cls}::{self.name}" if self.cls else self.name


def _contains(node, types) -> bool:
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type in types:
            return True
        stack.extend(cur.kids)
    return False


def _always_exits(body) -> bool:
    real = [k for k in body.kids if k.type not in ("comment", "text_interpolation", "php_tag")]
    if not real:
        return False
    last = real[-1]
    if last.type != "expression_statement" or not last.kids:
        return False
    expr = last.kids[0]
    if expr.type == "exit_statement":
        return True
    return expr.type == "function_call_expression" and expr.f("function") and expr.f("function").text.lower() in ("die", "exit")


class SourceFile:
    __slots__ = ("path", "rel", "data", "tree", "lines", "has_top_level_code", "direct_guard", "aliases")

    def __init__(self, path, rel, data):
        self.path, self.rel, self.data = path, rel, data
        self.lines = data.decode("utf-8", "replace").splitlines()
        self.tree = _convert(_parser.parse(data).root_node, self)
        self.has_top_level_code = _has_top_level_code(self.tree)
        self.direct_guard = _has_direct_access_guard(self.tree)
        self.aliases: dict[str, str] = {}

    def line_text(self, line) -> str:
        return self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""


_NON_EXEC = {
    "php_tag", "comment", "namespace_definition", "namespace_use_declaration", "class_declaration", "function_definition",
    "interface_declaration", "trait_declaration", "enum_declaration", "const_declaration", "declare_statement",
    "php_end_tag", "empty_statement",
}


def _has_top_level_code(tree) -> bool:
    for kid in tree.kids:
        if kid.type in _NON_EXEC:
            continue
        if kid.type == "text_interpolation":
            continue
        if kid.type == "text":
            if kid.text.strip():
                return True
            continue
        if kid.type == "expression_statement" and kid.kids:
            expr = kid.kids[0]
            is_call = expr.type == "function_call_expression" and expr.f("function") is not None
            if is_call and expr.f("function").text.lower() == "define":
                continue
        return True
    return False


def _has_direct_access_guard(tree) -> bool:
    """Spots `if (!defined('X')) exit;` and `basename(PHP_SELF) == basename(__FILE__)` at the top of a file."""
    for kid in tree.kids:
        if kid.type in ("php_tag", "comment", "text_interpolation", "namespace_definition"):
            continue
        if kid.type != "if_statement":
            return False
        cond = kid.f("condition")
        if cond is None or kid.f("body") is None:
            return False
        text = cond.text
        guarded = re.search(r"!\s*defined\s*\(", text) or ("__FILE__" in text and "basename" in text)
        return bool(guarded and _terminates_text(kid.f("body").text))
    return False


def _terminates_text(text) -> bool:
    return bool(re.search(r"\b(exit|die)\b", text))


# Calls that hand a function to other code by name, so the caller's arguments can be attacker input.
# Built-ins that take a callback are followed directly in the interpreter, with their real arguments.
_CALLBACK_RE = re.compile(r"""\b(?:register|add_function|add_action|add_filter)\s*\(\s*(?:['"][\w-]+['"]\s*,\s*)?['"]([A-Za-z_]\w*)['"]""")
_TEMPLATE_EXT = re.compile(r"(\.blade\.php|\.html\.twig|\.twig|\.tpl)$")
_BLADE_RAW = re.compile(r"\{!!(.*?)!!\}")
_TWIG_OUTPUT = re.compile(r"\{\{\s*([A-Za-z_]\w*)([^}]*)\}\}")
_SMARTY_OUTPUT = re.compile(r"\{\$(\w+)([^}]*)\}")
_LINK_RE = re.compile(r"[?&]([A-Za-z_]\w*)=([\w\-./]+)")
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_FORM_METHOD_RE = re.compile(r"method\s*=\s*\\?[\"']?(\w+)", re.I)
_FORM_ACTION_RE = re.compile(r"action\s*=\s*\\?[\"']?([^\"'\\\s>]*)", re.I)
_FIELD_RE = re.compile(r"<(?:input|select|textarea|button)\b[^>]*?\bname\s*=\s*\\?[\"']?([\w\-\[\]]+)", re.I)
_FIELD_TYPE_RE = re.compile(r"\btype\s*=\s*\\?[\"']?(\w+)", re.I)
_FIELD_VALUE_RE = re.compile(r"\bvalue\s*=\s*\\?[\"']([^\"'\\<$]*)", re.I)
_FIELD_TAG_RE = re.compile(r"<(?:input|select|textarea|button)\b[^>]*>", re.I)


def parse_forms(text: str) -> list:
    forms = []
    for attrs, body in _FORM_RE.findall(text):
        method = _FORM_METHOD_RE.search(attrs)
        action = _FORM_ACTION_RE.search(attrs)
        fields = []
        for tag in _FIELD_TAG_RE.findall(body):
            name = _FIELD_RE.search(tag)
            if not name:
                continue
            kind = _FIELD_TYPE_RE.search(tag)
            value = _FIELD_VALUE_RE.search(tag)
            entry = {"name": name.group(1), "type": kind.group(1).lower() if kind else "text"}
            if value and value.group(1):
                entry["value"] = value.group(1)
            fields.append(entry)
        if fields:
            forms.append({"method": method.group(1).upper() if method else "GET",
                          "action": action.group(1) if action else "", "fields": fields})
    return forms


def _view_names(rel: str) -> list:
    """The ways code can name a view: `orders.show`, `orders/show` or `orders/show.twig`."""
    parts = rel.split("/")
    start = next((i + 1 for i, part in enumerate(parts[:-1]) if part.lower() in TEMPLATE_DIRS), len(parts) - 1)
    full = "/".join(parts[start:])
    bare = _TEMPLATE_EXT.sub("", full)
    bare = re.sub(r"\.(php|phtml|inc|html?)$", "", bare)
    return [full, bare, bare.replace("/", "."), rel]


def _raw_outputs(name: str, lines: list) -> list:
    """Returns (line, variable, text) for each place a template prints a value without escaping it."""
    out = []
    if name.endswith(".blade.php"):
        for number, line in enumerate(lines, 1):
            for expr in _BLADE_RAW.findall(line):
                root = re.match(r"\s*\$(\w+)", expr)
                if root:
                    out.append((number, root.group(1), expr.strip()))
    elif name.endswith(".twig"):
        autoescape_off = False
        for number, line in enumerate(lines, 1):
            if re.search(r"\{%\s*autoescape\s+false\s*%\}", line):
                autoescape_off = True
            for variable, rest in _TWIG_OUTPUT.findall(line):
                if autoescape_off or re.search(r"\|\s*raw\b", rest):
                    out.append((number, variable, f"{variable}{rest}".strip()))
            if re.search(r"\{%\s*endautoescape\s*%\}", line):
                autoescape_off = False
    elif name.endswith(".tpl"):
        for number, line in enumerate(lines, 1):
            for variable, rest in _SMARTY_OUTPUT.findall(line):
                if not re.search(r"\|\s*(escape|htmlspecialchars|strip_tags)\b", rest):
                    out.append((number, variable, f"${variable}{rest}".strip()))
    return out


class Project:
    def __init__(self, root: str, web_root: str | None = None, exclude=None):
        self.root = os.path.abspath(root)
        self.exclude = set(DEFAULT_EXCLUDES) | set(exclude or [])
        self.files: dict[str, SourceFile] = {}
        self.functions: dict[str, list[FuncDef]] = {}
        self.classes: dict[str, dict] = {}
        self.methods_by_name: dict[str, list[FuncDef]] = {}
        self.defs_by_file: dict[str, list[FuncDef]] = {}
        self.constants: dict[str, set] = {}
        self.links: dict[str, set] = {}
        self.callbacks: set = set()
        self.templates: dict[str, str] = {}
        self.template_raw: dict[str, list] = {}
        self.php_views: dict[str, str] = {}
        # How code can run without a call we can see: "function" or "method".
        self.dynamic_calls: set = set()
        self.all_text_blobs: list[str] = []
        self.skipped: list[str] = []
        self._load()
        self._load_templates()
        self.web_root_certain = bool(web_root)
        self.web_root = self._web_root(web_root)
        self._rel_paths = sorted(self.files)
        self._index()

    def _load(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in self.exclude)
            for name in sorted(filenames):
                ext = os.path.splitext(name)[1].lower()
                if ext not in SOURCE_EXTS and ext not in MIXED_EXTS:
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                try:
                    if os.path.getsize(full) > MAX_FILE_BYTES:
                        self.skipped.append(rel)
                        continue
                    with open(full, "rb") as handle:
                        data = handle.read()
                except OSError:
                    self.skipped.append(rel)
                    continue
                if ext in SOURCE_EXTS or b"<?" in data:
                    self.files[rel] = SourceFile(full, rel, data)

    def _load_templates(self):
        """Template languages aren't PHP, so their unescaped output is read with patterns."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in self.exclude)
            for name in sorted(filenames):
                if not _TEMPLATE_EXT.search(name):
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                try:
                    with open(full, errors="replace") as handle:
                        lines = handle.read().splitlines()
                except OSError:
                    continue
                for key in _view_names(rel):
                    self.templates.setdefault(key, rel)
                self.template_raw[rel] = _raw_outputs(name, lines)

    def _web_root(self, explicit) -> str:
        if explicit:
            self.web_root_certain = True
            found = os.path.relpath(os.path.join(self.root, explicit), self.root).replace(os.sep, "/")
            return "" if found == "." else found
        for name in ("public/index.php", "web/index.php", "htdocs/index.php", "www/index.php", "public_html/index.php"):
            if name in self.files:
                self.web_root_certain = True
                return posixpath.dirname(name)
        index_dirs = sorted((posixpath.dirname(rel) for rel in self.files if posixpath.basename(rel) == "index.php"),
                            key=lambda d: (d.count("/") if d else -1, d))
        if index_dirs:
            return index_dirs[0]
        if not self.files:
            return ""
        dirs: dict[str, int] = {}
        for rel in self.files:
            dirs[posixpath.dirname(rel)] = dirs.get(posixpath.dirname(rel), 0) + 1
        return sorted(dirs, key=lambda d: (d.count("/") if d else -1, -dirs[d]))[0]

    def _index(self):
        for sf in self.files.values():
            self._index_node(sf.tree, sf, None)
            text = sf.data.decode("utf-8", "replace")
            self.all_text_blobs.append(text)
            self.callbacks.update(name.lower() for name in _CALLBACK_RE.findall(text))
            for name, value in _LINK_RE.findall(text):
                self.links.setdefault(name, set()).add(value)
            if any(part.lower() in TEMPLATE_DIRS for part in sf.rel.split("/")[:-1]) and not _TEMPLATE_EXT.search(sf.rel):
                for key in _view_names(sf.rel):
                    self.php_views.setdefault(key, sf.rel)

    def _index_node(self, node, sf, cls):
        stack = [(node, cls)]
        while stack:
            cur, owner = stack.pop()
            self._note_dynamic(cur)
            if cur.type == "namespace_use_clause" and " as " in cur.text:
                target, alias = cur.text.rsplit(" as ", 1)
                sf.aliases[alias.strip()] = target.strip().split("\\")[-1]
            if cur.type == "function_definition":
                name = cur.f("name")
                if name is not None and cur.f("body") is not None:
                    fd = FuncDef(name.text, None, cur, sf)
                    self.functions.setdefault(name.text.lower(), []).append(fd)
                    self.defs_by_file.setdefault(sf.rel, []).append(fd)
            elif cur.type == "method_declaration":
                name = cur.f("name")
                if name is not None and cur.f("body") is not None and owner:
                    fd = FuncDef(name.text, owner, cur, sf)
                    self.classes.setdefault(owner.lower(), {"name": owner, "parent": None, "methods": {}})["methods"][name.text.lower()] = fd
                    self.methods_by_name.setdefault(name.text.lower(), []).append(fd)
                    self.defs_by_file.setdefault(sf.rel, []).append(fd)
            elif cur.type in ("class_declaration", "trait_declaration"):
                name = cur.f("name")
                if name is not None:
                    owner = name.text
                    info = self.classes.setdefault(owner.lower(), {"name": owner, "parent": None, "methods": {}})
                    info["node"] = cur
                    for kid in cur.kids:
                        if kid.type == "base_clause" and kid.kids:
                            info["parent"] = kid.kids[0].text.split("\\")[-1]
                        elif kid.type == "class_interface_clause":
                            info.setdefault("interfaces", []).extend(k.text.split("\\")[-1] for k in kid.kids)
                    body = cur.f("body")
                    for kid in body.kids if body is not None else []:
                        if kid.type == "use_declaration":
                            info.setdefault("traits", []).extend(
                                k.text.split("\\")[-1] for k in kid.kids if k.type in ("name", "qualified_name"))
            for kid in cur.kids:
                stack.append((kid, owner))

    def _note_dynamic(self, node):
        """Records calls whose target is only known at runtime, because they can reach code nothing names."""
        kind = node.type
        if kind == "function_call_expression":
            func = node.f("function")
            if func is None or func.type not in ("name", "qualified_name", "relative_name"):
                self.dynamic_calls.add("function")
            elif func.text.split("\\")[-1].lower() in ("call_user_func", "call_user_func_array", "forward_static_call"):
                args = node.f("arguments")
                first = args.kids[0] if args is not None and args.kids else None
                if first is None or first.text[:1] not in ("'", '"'):
                    self.dynamic_calls.update({"function", "method"})
        elif kind in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"):
            name = node.f("name")
            if name is not None and name.type != "name":
                self.dynamic_calls.add("method")
        elif kind == "object_creation_expression":
            if any(k.type in ("variable_name", "member_access_expression", "subscript_expression", "parenthesized_expression",
                              "scoped_property_access_expression", "dynamic_variable_name") for k in node.kids):
                self.dynamic_calls.add("method")

    def find_method(self, cls: str | None, name: str):
        """Looks through a class, its traits and its parents."""
        seen = set()
        queue = [cls]
        while queue:
            current = queue.pop(0)
            if not current or current.lower() in seen or current.lower() not in self.classes:
                continue
            seen.add(current.lower())
            info = self.classes[current.lower()]
            if name in info["methods"]:
                return info["methods"][name]
            queue.extend(info.get("traits", []))
            queue.append(info["parent"])
        return None

    def has_external_ancestor(self, cls: str) -> bool:
        """True when a class extends or implements something outside the project, such as a
        framework's controller. Code we can't see may then call its methods."""
        seen = set()
        queue = [cls]
        while queue:
            current = queue.pop()
            if not current or current.lower() in seen:
                continue
            seen.add(current.lower())
            info = self.classes.get(current.lower())
            if info is None:
                return True
            queue.append(info["parent"])
            queue.extend(info.get("interfaces", []))
        return False

    def web_path(self, rel: str) -> str | None:
        """URL path for a source file, or None when it sits outside the web root."""
        if self.web_root and not rel.startswith(self.web_root + "/"):
            return None
        return "/" + (rel[len(self.web_root) + 1:] if self.web_root else rel)

    def is_blocked(self, rel: str) -> bool:
        """True when an .htaccess in the file's folder or above denies all access."""
        directory = posixpath.dirname(rel)
        while True:
            htaccess = os.path.join(self.root, directory, ".htaccess")
            if os.path.isfile(htaccess):
                try:
                    with open(htaccess, errors="replace") as handle:
                        content = handle.read()
                except OSError:
                    content = ""
                denied = re.search(r"^\s*(deny from all|require all denied)", content, re.I | re.M)
                allowed = re.search(r"^\s*(allow from|require (ip|host|local|all granted))", content, re.I | re.M)
                if denied and not allowed and "<Files" not in content:
                    return True
            if not directory:
                return False
            directory = posixpath.dirname(directory)

    def resolve_include(self, value: str, cur_rel: str, entry_rel: str | None) -> list[str]:
        """Maps an include path to project files. `*` marks a part only known at runtime."""
        if "*" in value:
            return self._resolve_pattern(value, cur_rel)
        if value.startswith(ABS):
            target = posixpath.normpath(value[len(ABS):].lstrip("/"))
            if target in self.files:
                return [target]
            return self._suffix_match(target, cur_rel)
        for base in (posixpath.dirname(cur_rel), posixpath.dirname(entry_rel or cur_rel), self.web_root, ""):
            target = posixpath.normpath(posixpath.join(base, value))
            if target in self.files:
                return [target]
        return self._suffix_match(value, cur_rel)

    def _suffix_match(self, value: str, cur_rel: str) -> list[str]:
        trimmed = re.sub(r"^(\.{1,2}/)+", "", value.lstrip("/"))
        if "/" not in trimmed and "." not in trimmed:
            return []
        hits = [rel for rel in self._rel_paths if rel == trimmed or rel.endswith("/" + trimmed)]
        return self._nearest(hits, cur_rel)

    def _nearest(self, hits, cur_rel):
        if len(hits) <= 1:
            return hits
        def shared(rel):
            return len(posixpath.commonprefix([posixpath.dirname(rel), posixpath.dirname(cur_rel)]))
        best = max(shared(h) for h in hits)
        return [h for h in hits if shared(h) == best][:1]

    def _resolve_pattern(self, pattern: str, cur_rel: str) -> list[str]:
        if pattern.startswith(ABS):
            pattern = pattern[len(ABS):].lstrip("/")
            bases = [""]
        else:
            bases = [posixpath.dirname(cur_rel), self.web_root, ""]
        fixed = pattern.lstrip("*").lstrip("/")
        if fixed and "*" not in fixed:
            return self.resolve_include(fixed, cur_rel, None)
        if not fixed or not re.search(r"[A-Za-z0-9]", fixed):
            return []
        for base in bases:
            full = posixpath.normpath(posixpath.join(base, fixed))
            hits = [rel for rel in self._rel_paths if fnmatch.fnmatchcase(rel, full)]
            if hits:
                return hits
        trimmed = re.sub(r"^(\.{1,2}/)+", "", fixed)
        return [rel for rel in self._rel_paths if fnmatch.fnmatchcase(rel, "*/" + trimmed)][:40]
