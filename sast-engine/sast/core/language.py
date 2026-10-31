"""The seam for adding languages: everything language-specific sits behind this."""
from __future__ import annotations

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
