"""The seam for adding languages: everything language-specific sits behind this."""
from __future__ import annotations

import importlib
import os
from dataclasses import dataclass, field
from typing import Protocol

from .model import ScanResult


@dataclass
class ScanOptions:
    web_root: str | None = None
    base_path: str = ""
    exclude: list = field(default_factory=list)
    use_semgrep: bool = True


class LanguageAdapter(Protocol):
    name: str

    def scan(self, source_root: str, options: ScanOptions) -> ScanResult: ...


# Adapters load on demand, so scanning a Python app never imports tree-sitter-php and the other way round.
ADAPTER_MODULES = {
    "php": ("sast.lang.php.adapter", "PhpAdapter"),
    "python": ("sast.lang.python.adapter", "PythonAdapter"),
}

# Folders that hold dependencies or tooling, not the app's own code.
_SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "vendor", "site-packages", "__pycache__", "build", "dist"}
_EXTENSIONS = {"php": {".php", ".phtml", ".inc"}, "python": {".py"}}
_MARKERS = {
    "php": {"composer.json", "artisan"},
    "python": {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "manage.py"},
}


def load_adapter(language: str) -> LanguageAdapter:
    module, cls = ADAPTER_MODULES[language]
    return getattr(importlib.import_module(module), cls)()


def detect_language(source_root: str) -> str:
    """The language most of the app's own files are written in. PHP when nothing decides it,
    which is what the engine did before it had a second language."""
    score = {language: 0 for language in ADAPTER_MODULES}
    for folder, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            for language, extensions in _EXTENSIONS.items():
                if ext in extensions:
                    score[language] += 1
                if name in _MARKERS[language]:
                    score[language] += 5
    best = max(score.values())
    if best == 0:
        return "php"
    # Ties keep PHP, the original behaviour, rather than guessing.
    return "php" if score["php"] == best else max(score, key=score.get)
