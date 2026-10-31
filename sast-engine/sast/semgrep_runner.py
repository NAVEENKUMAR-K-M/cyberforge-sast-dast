"""Runs Semgrep with our vendored rules. No network is needed at scan time."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
PLACEHOLDER = re.compile(
    r"^(|\*+|x+|changeme|change_me|your[_-].*|<.*>|\{.*\}|\$\{.*\}|%.*%|null|none|true|false|example|test|todo|placeholder|"
    r"password|secret|username|user|localhost|root|xsd:\w+|string|int|bool)$", re.I)
# Finds the secret's name and value on a line of code.
NAMED_VALUE = re.compile(
    r"""(?:->\s*|[$]|\bconst\s+|\bdefine\s*\(\s*['"]|\[\s*['"]|['"])([\w-]+)['"]?\s*\]?\s*(?:={1,3}>?|,)\s*(['"])(.*?)\2""", re.I)
# Names that talk about a secret without holding one.
NOT_A_SECRET_NAME = re.compile(
    r"(field|name|column|col|header|label|param|input|attr|attribute|type|url|uri|path|file|dir|id|policy|length|len|min|max|"
    r"hint|prompt|msg|message|error|regex|pattern|hash|algo|expiry|expires|ttl|lifetime|key_name|format)s?$", re.I)
STRONG_NAME = re.compile(r"pass|pwd|secret|api_?key|auth_?key|access_?key|private_?key|credential", re.I)


def _binary():
    beside_python = os.path.join(os.path.dirname(sys.executable), "semgrep")
    return beside_python if os.path.exists(beside_python) else shutil.which("semgrep")


def run_semgrep(source_root: str, rule_file: str, excludes, extra_files=(), timeout=180) -> tuple[list, str | None]:
    """Returns (raw results, error text). A failure here must be visible, not silent.

    Semgrep picks files by extension, so PHP in .inc and similar is scanned through
    temporary .php copies, and paths in the results are mapped back to the originals.
    """
    with tempfile.TemporaryDirectory(prefix="cyberforge-") as copies:
        mapping = {}
        for index, original in enumerate(extra_files):
            copy = os.path.join(copies, f"{index}.php")
            shutil.copyfile(original, copy)
            mapping[copy] = original
        results, error = _run(source_root, rule_file, excludes, list(mapping), timeout)
        for item in results:
            if item["path"] in mapping:
                item["path"] = mapping[item["path"]]
        return results, error


def _run(source_root, rule_file, excludes, extra_files, timeout):
    binary = _binary()
    if binary is None:
        return [], "semgrep isn't installed"
    command = [binary, "scan", "--config", os.path.join(RULES_DIR, rule_file), "--json", "--metrics=off",
               "--disable-version-check", "--no-git-ignore", "--quiet", "--timeout", "10"]
    for name in excludes:
        command += ["--exclude", name]
    env = dict(os.environ, SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    try:
        done = subprocess.run(command + [source_root, *extra_files], capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return [], f"semgrep timed out after {timeout}s"
    try:
        return json.loads(done.stdout).get("results", []), None
    except json.JSONDecodeError:
        return [], (done.stderr or "semgrep returned no JSON")[:400]


def looks_like_real_secret(line: str) -> bool:
    """Drops placeholders and names that only mention a secret. Known key formats skip this check."""
    match = None
    for match in NAMED_VALUE.finditer(line):
        if STRONG_NAME.search(match.group(1)) or re.search(r"token", match.group(1), re.I):
            break
    if match is None:
        return True
    name, value = match.group(1), match.group(3).strip()
    if NOT_A_SECRET_NAME.search(name) or PLACEHOLDER.match(value) or value.count(" ") >= 2:
        return False
    if STRONG_NAME.search(name):
        return True
    # "token" alone is a common word, so its value has to look machine-made.
    return len(value) >= 12 and bool(re.search(r"\d", value)) and bool(re.search(r"[A-Za-z]", value)) and " " not in value and ":" not in value
