"""Parses a Python source tree and indexes its files, functions, classes and imports."""
from __future__ import annotations

import ast
import os
import warnings

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".venv", "venv", "env", ".env", "virtualenv", "site-packages", "__pycache__", "node_modules",
    "build", "dist", ".tox", ".mypy_cache", ".pytest_cache", "migrations", "tests", "test", "docs", "vendor",
}
MAX_FILE_BYTES = 1_500_000
HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")


def _is_test_file(name: str) -> bool:
    """Django keeps a tests.py in every app, and others use test_*.py: fixtures full of fake passwords, not the app."""
    return name in ("tests.py", "conftest.py") or name.startswith("test_") or name.endswith("_test.py")


class PyFile:
    __slots__ = ("rel", "path", "source", "tree", "lines", "module", "imports", "top_funcs", "top_classes")

    def __init__(self, rel, path, source, tree):
        self.rel, self.path, self.source, self.tree = rel, path, source, tree
        self.lines = source.splitlines()
        self.module = _module_name(rel)
        self.imports: dict[str, str] = {}
        self.top_funcs: dict[str, "FuncDef"] = {}
        self.top_classes: dict[str, "ClassInfo"] = {}

    def line_text(self, line: int) -> str:
        return self.lines[line - 1].strip() if 1 <= line <= len(self.lines) else ""


class FuncDef:
    __slots__ = ("id", "name", "cls", "node", "file", "label", "params", "is_async", "parent")

    def __init__(self, node, file, cls, parent):
        self.node, self.file, self.cls, self.parent = node, file, cls, parent
        self.name = node.name
        if cls is not None:
            self.label = f"{cls.name}.{node.name}"
        elif parent is not None:
            self.label = f"{parent.label}.{node.name}"
        else:
            self.label = node.name
        self.id = f"{file.rel}:{self.label}@{node.lineno}"
        self.is_async = isinstance(node, ast.AsyncFunctionDef)
        args = node.args
        self.params = [a.arg for a in [*args.posonlyargs, *args.args]]
        self.params += [a.arg for a in args.kwonlyargs]

    @property
    def end_line(self) -> int:
        return getattr(self.node, "end_lineno", None) or self.node.lineno

    @property
    def start_line(self) -> int:
        decorators = [d.lineno for d in self.node.decorator_list]
        return min([self.node.lineno, *decorators])


class ClassInfo:
    __slots__ = ("name", "node", "file", "bases", "methods", "id")

    def __init__(self, node, file):
        self.node, self.file, self.name = node, file, node.name
        self.id = f"{file.rel}:{node.name}"
        self.bases = [dotted(b) or "" for b in node.bases]
        self.methods: dict[str, FuncDef] = {}


def dotted(node) -> str | None:
    """`a.b.c` for a chain of names and attributes, or None for anything else."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _module_name(rel: str) -> str:
    stem = rel[:-3] if rel.endswith(".py") else rel
    parts = [p for p in stem.split("/") if p]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class Project:
    def __init__(self, source_root: str, exclude=()):
        self.root = os.path.abspath(source_root)
        self.excludes = set(DEFAULT_EXCLUDES) | set(exclude)
        self.files: dict[str, PyFile] = {}
        self.syntax_errors: list[str] = []
        self.skipped = 0
        self.defs_by_file: dict[str, list[FuncDef]] = {}
        self.classes: dict[str, list[ClassInfo]] = {}
        self._modules: dict[str, PyFile] = {}
        self.all_text = ""
        self._load()
        for sf in self.files.values():
            self._index(sf)
        self._index_modules()
        self.all_text = "\n".join(sf.source for sf in self.files.values())

    # ---- loading -------------------------------------------------------------------------------------------------

    def _load(self):
        for folder, dirs, names in os.walk(self.root):
            dirs[:] = sorted(d for d in dirs if d not in self.excludes)
            for name in sorted(names):
                if not name.endswith(".py") or _is_test_file(name):
                    continue
                path = os.path.join(folder, name)
                rel = os.path.relpath(path, self.root).replace(os.sep, "/")
                try:
                    if os.path.getsize(path) > MAX_FILE_BYTES:
                        self.skipped += 1
                        continue
                    with open(path, "rb") as handle:
                        source = handle.read().decode("utf-8", "replace")
                    with warnings.catch_warnings():  # a scanned app's own odd escapes are not our warning to print
                        warnings.simplefilter("ignore")
                        tree = ast.parse(source, filename=rel)
                except (SyntaxError, ValueError, RecursionError, OSError):
                    self.syntax_errors.append(rel)
                    continue
                self.files[rel] = PyFile(rel, path, source, tree)

    def _index(self, sf: PyFile):
        self._collect_imports(sf)
        defs: list[FuncDef] = []
        self.defs_by_file[sf.rel] = defs
        self._walk_defs(sf, sf.tree.body, None, None, defs, top=True)

    def _walk_defs(self, sf, body, cls, parent, defs, top):
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fd = FuncDef(stmt, sf, cls, parent)
                defs.append(fd)
                if cls is not None:
                    cls.methods.setdefault(stmt.name, fd)
                elif parent is None and top:
                    sf.top_funcs.setdefault(stmt.name, fd)
                self._walk_defs(sf, stmt.body, None, fd, defs, top=False)
            elif isinstance(stmt, ast.ClassDef) and cls is None:
                info = ClassInfo(stmt, sf)
                self.classes.setdefault(stmt.name, []).append(info)
                if parent is None and top:
                    sf.top_classes.setdefault(stmt.name, info)
                self._walk_defs(sf, stmt.body, info, parent, defs, top=top)
            elif isinstance(stmt, (ast.If, ast.Try, ast.With, ast.For, ast.While, ast.AsyncWith, ast.AsyncFor)):
                for field in ("body", "orelse", "finalbody"):
                    self._walk_defs(sf, getattr(stmt, field, []) or [], cls, parent, defs, top=top)
                for handler in getattr(stmt, "handlers", []):
                    self._walk_defs(sf, handler.body, cls, parent, defs, top=top)

    def _collect_imports(self, sf: PyFile):
        package = sf.module if sf.rel.endswith("__init__.py") else sf.module.rpartition(".")[0]
        for node in ast.walk(sf.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        sf.imports.setdefault(alias.asname, alias.name)
                    else:
                        root = alias.name.split(".")[0]
                        sf.imports.setdefault(root, root)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    parts = package.split(".") if package else []
                    parts = parts[:len(parts) - (node.level - 1)] if node.level > 1 else parts
                    base = ".".join([*parts, base] if base else parts)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    sf.imports.setdefault(alias.asname or alias.name, f"{base}.{alias.name}" if base else alias.name)

    def _index_modules(self):
        for rel in sorted(self.files):
            sf = self.files[rel]
            parts = sf.module.split(".") if sf.module else []
            # Imports may start above the folder that was scanned, so every tail of the name is a key.
            for i in range(len(parts)):
                self._modules.setdefault(".".join(parts[i:]), sf)

    # ---- lookups -------------------------------------------------------------------------------------------------

    def find_module(self, name: str):
        """The file for a dotted module name, or None. An import can start above the folder that was scanned, so a
        name that isn't a module as written is tried again without its leading parts."""
        parts = name.split(".")
        for i in range(len(parts)):
            got = self._modules.get(".".join(parts[i:]))
            if got is not None:
                return got
        return None

    def _exact_module(self, name: str):
        return self._modules.get(name)

    def resolve_qualified_name(self, name: str):
        """What a fully qualified name such as `api_views.users.login_user` refers to, or None."""
        return self._resolve_qualified(name, None, 0)

    def resolve_dotted(self, sf: PyFile, name: str):
        """What a dotted name in `sf` refers to: ('func', FuncDef) / ('class', ClassInfo) / ('module', PyFile) /
        ('var', PyFile, name), or None. Follows imports through the project."""
        head, _, rest = name.partition(".")
        if head in sf.top_funcs and not rest:
            return "func", sf.top_funcs[head]
        if head in sf.top_classes and not rest:
            return "class", sf.top_classes[head]
        qualified = sf.imports.get(head)
        if qualified is None:
            return ("var", sf, head) if not rest else None
        full = f"{qualified}.{rest}" if rest else qualified
        return self._resolve_qualified(full, sf, 0)

    def _resolve_qualified(self, full: str, origin: PyFile, depth: int):
        if depth > 4:
            return None
        parts = full.split(".")
        # Drop leading parts one at a time (an import may start above the scanned folder), and for each start,
        # take the longest leading part that is a module. `pkg.mod.name` is the name `name` inside `pkg.mod`.
        for drop in range(len(parts)):
            rest_parts = parts[drop:]
            for cut in range(len(rest_parts), 0, -1):
                module = self._exact_module(".".join(rest_parts[:cut]))
                if module is None:
                    continue
                if cut == len(rest_parts):
                    return "module", module
                member, tail = rest_parts[cut], rest_parts[cut + 1:]
                if member in module.top_funcs and not tail:
                    return "func", module.top_funcs[member]
                if member in module.top_classes:
                    info = module.top_classes[member]
                    if not tail:
                        return "class", info
                    if len(tail) == 1 and tail[0] in info.methods:
                        return "func", info.methods[tail[0]]
                    return None
                if member in module.imports and module is not origin:  # re-exported through an __init__
                    return self._resolve_qualified(".".join([module.imports[member], *tail]), module, depth + 1)
                if not tail:
                    return "var", module, member
                return None
        return None

    def class_methods(self, info: ClassInfo, name: str, depth=0):
        """A method on a class or on a base class found in the project."""
        if name in info.methods:
            return info.methods[name]
        if depth > 5:
            return None
        for base in info.bases:
            target = self.resolve_dotted(info.file, base) if base else None
            if target and target[0] == "class":
                got = self.class_methods(target[1], name, depth + 1)
                if got is not None:
                    return got
            else:
                for candidate in self.classes.get(base.split(".")[-1], []):
                    got = self.class_methods(candidate, name, depth + 1)
                    if got is not None:
                        return got
        return None

    def class_has_base(self, info: ClassInfo, wanted: set, depth=0) -> bool:
        """Whether a class descends from one of the named bases, such as BaseModel."""
        if depth > 6:
            return False
        for base in info.bases:
            if base.split(".")[-1] in wanted:
                return True
            target = self.resolve_dotted(info.file, base) if base else None
            candidates = [target[1]] if target and target[0] == "class" else self.classes.get(base.split(".")[-1], [])
            if any(self.class_has_base(c, wanted, depth + 1) for c in candidates):
                return True
        return False

    def lookup_class(self, sf: PyFile, name: str):
        target = self.resolve_dotted(sf, name)
        if target and target[0] == "class":
            return target[1]
        found = self.classes.get(name.split(".")[-1], [])
        return found[0] if len(found) == 1 else None
