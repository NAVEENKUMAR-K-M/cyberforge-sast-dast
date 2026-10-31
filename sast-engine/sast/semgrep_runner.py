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
# Values that stand for a secret without being one. Weak values like "password" or "root" aren't here:
# committing those as real credentials is exactly the bug.
PLACEHOLDER = re.compile(r"^(|\*+|\.+|x{3,}|<.*>|\[.*\]|\{.*\}|\$\{.*\}|%.*%|your[_-].*|null|none|nil|true|false|todo|tbd|placeholder)$", re.I)
# Values that describe a field's type or validation, as in schemas and form rules.
SCHEMA_VALUE = re.compile(r"^(xsd:\w+|string|int|integer|bool|boolean|text|varchar|number|float|array|required|nullable|hidden"
                          r"|hashed|encrypted(:\w+)?|datetime|date|timestamp|collection|object|json|real|double|decimal:\d+)$"
                          r"|^[a-z_]+(:[^|]*)?(\|[a-z_]+(:[^|]*)?)+$", re.I)
# Finds the secret's name and value on a line of code.
NAMED_VALUE = re.compile(
    r"""(?:->\s*|[$]|\bconst\s+|\bdefine\s*\(\s*['"]|\[\s*['"]|['"])([\w-]+)['"]?\s*\]?\s*(={1,3}>?|,)\s*(['"])(.*?)\3""", re.I)
# Names that talk about a secret without holding one.
NOT_A_SECRET_NAME = re.compile(
    r"(field|name|column|col|header|label|param|input|attr|attribute|type|url|uri|path|file|dir|id|policy|length|len|min|max|"
    r"hint|prompt|msg|message|error|regex|pattern|hash|algo|expiry|expires|ttl|lifetime|key_name|format|"
    r"broker|table|driver|provider|guard|connection|store|disk|channel|mailer|scheme|encoding|method|mode|level|cast)s?$", re.I)
STRONG_NAME = re.compile(r"pass|pwd|secret|api_?key|auth_?key|access_?key|private_?key|credential", re.I)


def _binary():
    executable_dir = os.path.dirname(sys.executable)
    names = ("semgrep.exe", "semgrep.cmd", "semgrep") if os.name == "nt" else ("semgrep",)
    for name in names:
        beside_python = os.path.join(executable_dir, name)
        if os.path.isfile(beside_python):
            return beside_python
    return shutil.which("semgrep")


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


# The same for Python, where a name is a bare identifier, a keyword argument, a dict key or a subscript.
PYTHON_NAMED_VALUE = re.compile(
    r"""(?:^|[\s(,{\[.])['"]?([\w-]+)['"]?\s*\]?\s*(=|:)\s*(['"])(.*?)\3""", re.I)


def looks_like_real_secret(line: str, pattern=NAMED_VALUE) -> bool:
    """Drops placeholders and names that only mention a secret. Known key formats skip this check."""
    match = None
    for match in pattern.finditer(line):
        if STRONG_NAME.search(match.group(1)) or re.search(r"token", match.group(1), re.I):
            break
    if match is None:
        return True
    return is_secret_value(match.group(1), match.group(4).strip(), mapping=match.group(2) in ("=>", ":"))


def is_secret_value(name: str, value: str, mapping: bool = False) -> bool:
    """Judges one name and value. `mapping` means an array entry, where `'password' => 'password'`
    usually maps a field to its own name."""
    if NOT_A_SECRET_NAME.search(name) or PLACEHOLDER.match(value) or SCHEMA_VALUE.match(value) or value.count(" ") >= 2:
        return False
    if mapping and value.lower() == name.lower():
        return False
    if re.search(r"public", name, re.I):
        return False  # public keys and tokens are meant to be seen
    if STRONG_NAME.search(name):
        return True
    # "token" alone is a common word, so its value has to look machine-made.
    return len(value) >= 12 and bool(re.search(r"\d", value)) and bool(re.search(r"[A-Za-z]", value)) and " " not in value and ":" not in value


ENV_FALLBACK = re.compile(r"""(?:getenv|env|environ\.get)\s*\(\s*['"]([\w.-]+)['"]""", re.I)


def fallback_is_secret(line: str) -> bool:
    """For `getenv('DB_PASSWORD') ?: 'value'` and `env('DB_PASSWORD', 'value')`: the secret is the last string."""
    name = ENV_FALLBACK.search(line)
    values = re.findall(r"""['"]([^'"]*)['"]""", line)
    return bool(name and values) and is_secret_value(name.group(1), values[-1])
