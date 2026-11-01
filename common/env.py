"""Reads API keys from a .env file, so they never appear in code, commands or the repo.

Lines are KEY=VALUE; blank lines and # comments are skipped; quotes around a value are removed. A variable that
is already set in the environment wins over the file.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

LINE = re.compile(r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$""")


def load_env(path: str | None = None) -> list:
    """Loads the first .env found (the given path, else the working folder, else the repo root).
    Returns the names it set, never the values."""
    candidates = [Path(path)] if path else [Path.cwd() / ".env", Path(__file__).resolve().parents[1] / ".env"]
    for candidate in candidates:
        if candidate.is_file():
            return _load(candidate)
    return []


def _load(path: Path) -> list:
    names = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        match = LINE.match(raw)
        if not match or raw.lstrip().startswith("#"):
            continue
        name, value = match.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if value and name not in os.environ:
            os.environ[name] = value
            names.append(name)
    return names
