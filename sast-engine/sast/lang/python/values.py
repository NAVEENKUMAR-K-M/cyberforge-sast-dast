"""Abstract values tracked by the Python analysis: taint plus the text a string may hold."""
from __future__ import annotations

import re

MAX_TAINTS = 12
MAX_STRS = 32
MAX_STR_LEN = 3000
MAX_STEPS = 14


class Comp:
    """The place where tainted input was first added to a larger string."""
    __slots__ = ("file", "line", "func", "text")

    def __init__(self, file, line, func, text):
        self.file, self.line, self.func, self.text = file, line, func, text


class Taint:
    """One path from a source. Treated as immutable: changes return a copy."""
    __slots__ = ("name", "location", "steps", "san", "sql_quoted", "html_ctx", "url_prefix", "comp", "penalty",
                 "stored", "_key")

    def __init__(self, name, location, steps=(), san=frozenset(), sql_quoted=False, html_ctx=None, url_prefix=None,
                 comp=None, penalty=0, stored=None):
        self.name, self.location, self.steps, self.san = name, location, steps, san
        self.sql_quoted, self.html_ctx, self.url_prefix = sql_quoted, html_ctx, url_prefix
        self.comp, self.penalty, self.stored = comp, penalty, stored
        self._key = None

    def _copy(self, **changes):
        out = Taint(self.name, self.location, self.steps, self.san, self.sql_quoted, self.html_ctx, self.url_prefix,
                    self.comp, self.penalty, self.stored)
        for name, value in changes.items():
            setattr(out, name, value)
        return out

    @property
    def key(self):
        if self._key is None:
            comp = (self.comp.file, self.comp.line) if self.comp else None
            stored = self.stored["store"] if self.stored else None
            self._key = (self.name, self.location, self.san, self.sql_quoted, self.html_ctx, self.url_prefix, comp,
                         stored, self.penalty)
        return self._key

    def step(self, file, line, note):
        if len(self.steps) >= MAX_STEPS or (self.steps and self.steps[-1] == (file, line, note)):
            return self
        return self._copy(steps=self.steps + ((file, line, note),))

    def sanitized(self, label, file=None, line=None, note=None):
        if label in self.san:
            return self
        out = self._copy(san=self.san | {label})
        return out.step(file, line, note) if note else out

    def renamed(self, name):
        return self._copy(name=name)

    def penalised(self):
        return self._copy(penalty=self.penalty + 1)

    def composed(self, prefix, comp):
        """Records the literal text before this input, the first time it's added to a string."""
        quoted = self.sql_quoted or _in_sql_quote(prefix)
        if self.comp is None:
            return self._copy(sql_quoted=quoted, html_ctx=html_context(prefix), url_prefix=prefix, comp=comp)
        return self._copy(sql_quoted=quoted) if quoted != self.sql_quoted else self


def _in_sql_quote(prefix: str) -> bool:
    cleaned = re.sub(r"\\.", "", prefix)
    return cleaned.count("'") % 2 == 1 or cleaned.count('"') % 2 == 1


_TAG_OPEN = re.compile(r"<([a-zA-Z][\w-]*)\b([^<>]*)$", re.S)
_ATTR = re.compile(r"([\w:-]+)\s*=\s*(\"[^\"]*|'[^']*|[^\s\"'>]*)$", re.S)
# Attributes where a javascript: URL runs. An <img src> or <script src> needs more than a scheme.
_URL_ATTRS = {"href", "action", "formaction", "data", "xlink:href"}
_URL_SRC_TAGS = {"iframe", "embed", "frame"}


def html_context(prefix: str) -> str:
    """Where text sits within HTML: body, attr_quoted, attr_unquoted, url_start or js."""
    lowered = prefix.lower()
    last_script = lowered.rfind("<script")
    if last_script != -1 and lowered.rfind("</script", last_script) == -1:
        return "js"
    last_style = lowered.rfind("<style")
    if last_style != -1 and lowered.rfind("</style", last_style) == -1:
        return "js"
    tag = _TAG_OPEN.search(prefix)
    if not tag:
        return "body"
    attr = _ATTR.search(tag.group(2))
    if not attr:
        return "attr_unquoted" if tag.group(2).rstrip().endswith("=") else "body"
    name, value = attr.group(1).lower(), attr.group(2)
    if name.startswith("on") or name == "style":
        return "js"
    if not value or value[0] not in "\"'":
        return "attr_unquoted"
    if (name in _URL_ATTRS or (name == "src" and tag.group(1).lower() in _URL_SRC_TAGS)) and len(value) == 1:
        return "url_start"
    return "attr_quoted"


class Instance:
    """An object made from a class in the project. Attributes are shared by every reference to it."""
    __slots__ = ("cls", "attrs")

    def __init__(self, cls):
        self.cls, self.attrs = cls, {}


class Val:
    """Possible value of an expression. `strs` holds known text, with `*` for unknown parts.

    bag      the request source this value is a collection of ("query", "body", "json", ...)
    request  the framework's request object
    kind     "path" for filesystem paths, which are sinks when opened
    resp     what a response object holds: "html", "json" or "other"
    """
    __slots__ = ("taints", "strs", "fields", "bag", "request", "kind", "resp", "obj", "tables", "func", "cls")

    def __init__(self, taints=None, strs=frozenset(), fields=None, bag=None, request=False, kind=None, resp=None,
                 obj=None, tables=frozenset(), func=None, cls=None):
        self.taints = taints or {}
        self.strs, self.fields, self.bag, self.request = strs, fields, bag, request
        self.kind, self.resp, self.obj, self.tables, self.func, self.cls = kind, resp, obj, tables, func, cls

    @staticmethod
    def lit(text):
        return Val(strs=frozenset({text[:MAX_STR_LEN]}))

    @staticmethod
    def of(taint):
        return Val(taints={taint.key: taint})

    def all_taints(self) -> list:
        out = dict(self.taints)
        if self.fields:
            for field in self.fields.values():
                for taint in field.all_taints():
                    out.setdefault(taint.key, taint)
        return list(out.values())

    @property
    def tainted(self) -> bool:
        return bool(self.taints) or bool(self.fields and any(f.tainted for f in self.fields.values()))

    def map_taints(self, func) -> "Val":
        taints = {}
        for taint in self.taints.values():
            new = func(taint)
            if new is not None:
                taints[new.key] = new
        fields = {k: v.map_taints(func) for k, v in self.fields.items()} if self.fields else None
        return self.derive(taints=taints, fields=fields)

    def derive(self, **changes) -> "Val":
        out = Val(self.taints, self.strs, self.fields, self.bag, self.request, self.kind, self.resp, self.obj,
                  self.tables, self.func, self.cls)
        for name, value in changes.items():
            setattr(out, name, value)
        return out

    def flat(self) -> "Val":
        """The whole value as one, for when a collection is used as a single thing."""
        if not self.fields:
            return self
        return Val({t.key: t for t in self.all_taints()}, self.strs, kind=self.kind, resp=self.resp, tables=self.tables)

    def sig(self):
        field_sig = tuple(sorted((k, v.sig()) for k, v in self.fields.items())) if self.fields else ()
        obj = id(self.obj) if self.obj is not None else None
        return (tuple(sorted(_key_text(key) for key in self.taints)), field_sig, tuple(sorted(self.strs)[:6]), self.bag,
                self.request, obj, self.func.id if self.func is not None else None, tuple(sorted(self.tables)))


def _key_text(key) -> str:
    return repr(tuple(sorted(part) if isinstance(part, frozenset) else part for part in key))


EMPTY = Val()


def union(*vals) -> Val:
    vals = [v for v in vals if v is not None and v is not EMPTY]
    if not vals:
        return EMPTY
    if len(vals) == 1:
        return vals[0]
    taints, strs, fields, tables = {}, set(), None, set()
    first = vals[0]
    bag, request, kind, resp, obj, func, cls = None, False, None, None, None, None, None
    for val in vals:
        for key, taint in val.taints.items():
            if key in taints or len(taints) < MAX_TAINTS:
                taints.setdefault(key, taint)
        if len(strs) < MAX_STRS:
            # The cap has to keep the same values every run, whatever order sets iterate in.
            strs.update(sorted(val.strs)[:MAX_STRS - len(strs)])
        if val.fields:
            fields = dict(fields or {})
            for key, item in val.fields.items():
                fields[key] = union(fields[key], item) if key in fields else item
        tables |= val.tables
        bag, request = bag or val.bag, request or val.request
        kind, resp = kind or val.kind, resp or val.resp
        obj, func, cls = obj or val.obj, func or val.func, cls or val.cls
    return Val(taints, frozenset(strs), fields, bag, request, kind, resp, obj, frozenset(tables), func, cls)
