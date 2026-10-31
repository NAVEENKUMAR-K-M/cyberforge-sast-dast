"""Finds hard-coded secrets in configuration files, which the PHP analysis never reads."""
from __future__ import annotations

import os
import re

from sast.semgrep_runner import STRONG_NAME, is_secret_value

CONFIG_EXTS = {".ini", ".conf", ".cnf", ".config", ".yml", ".yaml", ".json", ".xml", ".toml", ".properties"}
SKIPPED_FILES = {"composer.lock", "package-lock.json", "yarn.lock", "composer.json", "package.json", "pipfile.lock",
                 "poetry.lock"}
MAX_BYTES = 256_000
MAX_LINE = 500

# name: value, name = value, "name": "value", <name>value</name>, name="value"
ASSIGNMENT = re.compile(r"""^\s*(?:export\s+)?([\w.-]+)\s*(?:=|:)\s*(?:"([^"]*)"|'([^']*)'|([^\s#;,]+))""")
INLINE_FORMS = [
    re.compile(r""""([\w.-]+)"\s*:\s*"([^"]*)\""""),
    re.compile(r"""<([\w.-]+)>([^<]+)</\1>"""),
    re.compile(r"""\b([\w.-]+)=["']([^"']+)["']"""),
]
KNOWN_FORMAT = re.compile(r"(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{16,}|ghp_[0-9a-zA-Z]{36}|xox[bp]-[0-9a-zA-Z-]{20,}|-----BEGIN (RSA |EC )?PRIVATE KEY-----)")
REFERENCE = re.compile(r"^(\$\{\{|\$\{?\w+|%\w*\(?\w+|\{\{.*|!vault|ENC\(|vault:|file:|env:)", re.I)


def is_config_file(name: str) -> bool:
    lowered = name.lower()
    if lowered in SKIPPED_FILES:
        return False
    return lowered == ".env" or lowered.startswith(".env.") or os.path.splitext(lowered)[1] in CONFIG_EXTS


def _candidates(line: str):
    """Yields each (name, value) a line of config could be setting."""
    match = ASSIGNMENT.match(line)
    if match:
        yield match.group(1), next(g for g in match.groups()[1:] if g is not None)
    for form in INLINE_FORMS:
        yield from form.findall(line)


def _secret_on_line(line: str) -> str | None:
    """Returns the secret's name when this line holds one. Known key formats need no name."""
    if KNOWN_FORMAT.search(line):
        return "credential"
    for name, value in _candidates(line):
        if not re.search(r"token", name, re.I) and not STRONG_NAME.search(name):
            continue
        value = value.strip()
        if not REFERENCE.match(value) and is_secret_value(name, value):
            return name
    return None


def scan_config_files(root: str, excludes) -> list:
    """Returns (relative path, line number, name) for each secret found."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excludes)
        for filename in sorted(filenames):
            if not is_config_file(filename):
                continue
            full = os.path.join(dirpath, filename)
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, errors="replace") as handle:
                    lines = handle.read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            for number, line in enumerate(lines, 1):
                if len(line) > MAX_LINE or line.lstrip().startswith(("#", ";", "//")):
                    continue
                name = _secret_on_line(line)
                if name:
                    found.append((rel, number, name))
    return found
