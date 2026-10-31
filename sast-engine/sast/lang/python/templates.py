"""Which values a Jinja template prints without escaping them.

Flask turns escaping on for templates named *.html, so a value is only dangerous where the template says
`{{ value | safe }}` or sits inside `{% autoescape false %}`. This reads that off the template text; it does
not run it. A loop variable counts back to the collection it came from, so `{% for p in posts %}{{ p.text | safe }}`
makes `posts` an unescaped value.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

TEMPLATE_EXTS = (".html", ".htm", ".jinja", ".jinja2", ".j2", ".tpl", ".txt", ".xml")
MAX_BYTES = 400_000
_PRINT = re.compile(r"\{\{(.*?)\}\}", re.S)
_FOR = re.compile(r"\{%-?\s*for\s+(.+?)\s+in\s+(.+?)\s*-?%\}", re.S)
_INCLUDE = re.compile(r"\{%-?\s*(?:include|extends)\s+['\"]([^'\"]+)['\"]")
_AUTOESCAPE_OFF = re.compile(r"\{%-?\s*autoescape\s+(?:false|False|off)\s*-?%\}.*?\{%-?\s*endautoescape\s*-?%\}", re.S)
_SAFE_FILTER = re.compile(r"\|\s*safe\b")
_IDENT = re.compile(r"[A-Za-z_]\w*")


@dataclass
class TemplateInfo:
    unescaped: set = field(default_factory=set)   # context variables that reach the page unescaped


def _base_names(expression: str) -> list[str]:
    """The variables an expression starts from: `post.text` -> post, `a or b` -> a and b."""
    names = []
    for match in _IDENT.finditer(re.sub(r"(['\"]).*?\1", "", expression)):
        name = match.group(0)
        before = expression[:match.start()].rstrip()
        if before.endswith("."):
            continue  # an attribute, not a variable
        if name in ("if", "else", "or", "and", "not", "in", "is", "none", "None", "true", "false", "True", "False", "safe", "e"):
            continue
        names.append(name)
    return names


def analyse_text(text: str) -> TemplateInfo:
    unescaped: set = set()
    for match in _PRINT.finditer(text):
        expression = match.group(1)
        if _SAFE_FILTER.search(expression):
            unescaped.update(_base_names(_SAFE_FILTER.split(expression)[0]))
    for block in _AUTOESCAPE_OFF.finditer(text):
        for match in _PRINT.finditer(block.group(0)):
            unescaped.update(_base_names(match.group(1)))
    # A loop variable that prints unescaped makes the collection it came from unescaped too.
    loops = [(_base_names(target), _base_names(source)) for target, source in
             ((m.group(1), m.group(2)) for m in _FOR.finditer(text))]
    for _ in range(4):
        grew = False
        for targets, sources in loops:
            if unescaped & set(targets):
                before = len(unescaped)
                unescaped.update(sources)
                grew = grew or len(unescaped) != before
        if not grew:
            break
    return TemplateInfo(unescaped)


class TemplateIndex:
    """Looks templates up by the name they are rendered with, wherever they sit in the project."""

    def __init__(self, project):
        self.root = project.root
        self.excludes = project.excludes - {"build", "dist"}
        self._files: dict[str, str] | None = None
        self._cache: dict[str, TemplateInfo | None] = {}

    def _find_all(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for folder, dirs, names in os.walk(self.root):
            dirs[:] = sorted(d for d in dirs if d not in self.excludes)
            for name in sorted(names):
                if name.lower().endswith(TEMPLATE_EXTS):
                    full = os.path.join(folder, name)
                    found[os.path.relpath(full, self.root).replace(os.sep, "/")] = full
        return found

    def _locate(self, name: str):
        if self._files is None:
            self._files = self._find_all()
        wanted = name.lstrip("/")
        for rel in sorted(self._files):
            if rel == wanted or rel.endswith("/templates/" + wanted) or rel.endswith("/" + wanted):
                return self._files[rel]
        return None

    def get(self, name: str, depth: int = 0) -> TemplateInfo | None:
        if name in self._cache:
            return self._cache[name]
        path = self._locate(name)
        info = None
        if path is not None and depth < 4:
            try:
                if os.path.getsize(path) <= MAX_BYTES:
                    with open(path, encoding="utf-8", errors="replace") as handle:
                        text = handle.read()
                    info = analyse_text(text)
                    for include in _INCLUDE.findall(text):
                        inner = self.get(include, depth + 1)
                        if inner is not None:
                            info.unescaped |= inner.unescaped
            except OSError:
                info = None
        self._cache[name] = info
        return info
