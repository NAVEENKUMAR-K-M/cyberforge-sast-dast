import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sast.core.language import ScanOptions  # noqa: E402
from sast.lang.php.adapter import PhpAdapter  # noqa: E402


@pytest.fixture
def scan(tmp_path):
    """Writes PHP files to a folder and scans them. Keys are paths, values are source."""
    def run(files, semgrep=False, **options):
        for rel, source in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        result = PhpAdapter().scan(str(tmp_path), ScanOptions(use_semgrep=semgrep, **options))
        return json.loads(json.dumps({"routes": result.routes, "findings": result.findings, "stats": result.stats}))
    return run


@pytest.fixture
def py_scan(tmp_path):
    """Writes Python files to a folder and scans them. Keys are paths, values are source."""
    from sast.lang.python.adapter import PythonAdapter

    def run(files, semgrep=False, **options):
        for rel, source in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        result = PythonAdapter().scan(str(tmp_path), ScanOptions(use_semgrep=semgrep, **options))
        return json.loads(json.dumps({"routes": result.routes, "findings": result.findings, "stats": result.stats}))
    return run


def open_findings(result, cwe=None):
    return [f for f in result["findings"] if f["status"] == "open" and (cwe is None or f["cwe_family"] == f"CWE-{cwe}")]


def safe_findings(result, cwe=None):
    return [f for f in result["findings"] if f["status"] == "suppressed" and (cwe is None or f["cwe_family"] == f"CWE-{cwe}")]
