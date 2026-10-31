"""Parses a PHP source tree and indexes its files, functions, classes and links."""
from __future__ import annotations

import fnmatch
import os
import posixpath
import re

import tree_sitter
import tree_sitter_php

SOURCE_EXTS = {".php", ".inc", ".phtml", ".php5", ".php7"}
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
    __slots__ = ("path", "rel", "data", "tree", "lines", "has_top_level_code", "direct_guard")

    def __init__(self, path, rel, data):
        self.path, self.rel, self.data = path, rel, data
        self.lines = data.decode("utf-8", "replace").splitlines()
        self.tree = _convert(_parser.parse(data).root_node, self)
        self.has_top_level_code = _has_top_level_code(self.tree)
        self.direct_guard = _has_direct_access_guard(self.tree)

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
_CALLBACK_RE = re.compile(r"""\b(?:register|add_function|call_user_func(?:_array)?|array_map|array_walk|add_action|add_filter)\s*\(\s*(?:['"][\w-]+['"]\s*,\s*)?['"]([A-Za-z_]\w*)['"]""")
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
        self.blade_views: dict[str, str] = {}
        self.blade_raw: dict[str, list] = {}
        self.all_text_blobs: list[str] = []
        self.skipped: list[str] = []
        self._load()
        self._load_blade()
        self.web_root = self._web_root(web_root)
        self._rel_paths = sorted(self.files)
        self._index()

    def _load(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in self.exclude)
            for name in sorted(filenames):
                if os.path.splitext(name)[1].lower() not in SOURCE_EXTS:
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                try:
                    if os.path.getsize(full) > MAX_FILE_BYTES:
                        self.skipped.append(rel)
                        continue
                    with open(full, "rb") as handle:
                        self.files[rel] = SourceFile(full, rel, handle.read())
                except OSError:
                    self.skipped.append(rel)

    def _load_blade(self):
        """Blade isn't PHP, so its raw-output tags are read with a pattern."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in self.exclude)
            for name in sorted(filenames):
                if not name.endswith(".blade.php"):
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                try:
                    with open(full, errors="replace") as handle:
                        lines = handle.read().splitlines()
                except OSError:
                    continue
                view = re.sub(r"^.*?views/", "", rel)[: -len(".blade.php")].replace("/", ".")
                self.blade_views[view] = rel
                self.blade_raw[rel] = [(number, match.strip()) for number, line in enumerate(lines, 1)
                                       for match in re.findall(r"\{!!(.*?)!!\}", line)]

    def _web_root(self, explicit) -> str:
        if explicit:
            found = os.path.relpath(os.path.join(self.root, explicit), self.root).replace(os.sep, "/")
            return "" if found == "." else found
        for name in ("public/index.php", "web/index.php", "htdocs/index.php", "www/index.php", "public_html/index.php"):
            if name in self.files:
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

    def _index_node(self, node, sf, cls):
        stack = [(node, cls)]
        while stack:
            cur, owner = stack.pop()
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
                    for kid in cur.kids:
                        if kid.type == "base_clause" and kid.kids:
                            info["parent"] = kid.kids[0].text.split("\\")[-1]
            for kid in cur.kids:
                stack.append((kid, owner))

    def find_method(self, cls: str | None, name: str):
        seen = set()
        while cls and cls.lower() in self.classes and cls.lower() not in seen:
            seen.add(cls.lower())
            info = self.classes[cls.lower()]
            if name in info["methods"]:
                return info["methods"][name]
            cls = info["parent"]
        return None

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
