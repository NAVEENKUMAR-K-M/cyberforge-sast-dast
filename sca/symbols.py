"""Stage 4: which functions of the package an advisory affects, and how we know.

Three kinds of evidence, kept apart on every symbol:
- **listed by the advisory**: GHSA's `vulnerable_functions` or OSV's `ecosystem_specific`. Rarely filled in for PHP.
- **changed by the fix commit**: only a *candidate*. A patch also touches callers, validators and helpers, so changing a
  function doesn't make it the vulnerable one. A candidate counts as affected only when the advisory's own text names it.
- **unresolved**: nothing identifies a function.

Every symbol is checked against the exact version we analyse: a name that doesn't exist there is reported as such.
The patch is located in that version's own file (its pre-image text), not by the diff's line numbers or hunk header:
git's hunk header names the function *before* the change, which is often the wrong one.
"""
from __future__ import annotations

import os
import re

from sca.http import Unavailable

DECLARATION = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(")


def function_map(advisory: dict, package: str, index, fetcher) -> dict:
    result = {"affected": [], "candidates": [], "unresolved": [], "patches": []}
    text = f"{advisory.get('summary', '')}\n{advisory.get('details', '')}"
    seen = set()

    listed = [(raw, "listed by the advisory (GHSA vulnerable_functions)") for raw in (advisory.get("ghsa") or {}).get("vulnerable_functions") or []]
    listed += [(raw, "listed by the advisory (OSV ecosystem_specific)") for raw in advisory.get("osv_listed_functions") or []]
    for raw, provenance in listed:
        fn = find_symbol(index, package, raw)
        entry = {"symbol": fn.label if fn else raw.strip(), "provenance": provenance, "exists": fn is not None,
                 "key": fn.key if fn else None}
        if not fn:
            entry["note"] = "not found in this version's source"
        if (entry["key"] or entry["symbol"]) not in seen:
            seen.add(entry["key"] or entry["symbol"])
            result["affected"].append(entry)

    if not advisory.get("fix_commits"):
        result["unresolved"].append("the advisory references no fix commit")
    changed = {}
    merges = []
    for owner, repo, sha in advisory.get("fix_commits") or []:
        url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
        patch = {"commit": f"{owner}/{repo}@{sha[:12]}", "url": url, "mapped": [], "skipped": [], "unmapped": []}
        result["patches"].append(patch)
        try:
            status, diff, meta = fetcher.get_text(url)
        except Unavailable as exc:
            patch["error"] = f"unavailable: {exc}"
            result["unresolved"].append(f"fix commit {patch['commit']} couldn't be fetched")
            continue
        if status != 200:
            patch["error"] = f"HTTP {status}"
            result["unresolved"].append(f"fix commit {patch['commit']} couldn't be fetched (HTTP {status})")
            continue
        if not diff.strip():
            patch["error"] = "empty diff"
            result["unresolved"].append(f"fix commit {patch['commit']} has an empty diff (a merge commit?)")
            continue
        patch["fetched_at"] = meta["fetched_at"]
        count = commit_count(diff)
        if count > 1:
            # A merge (a forward-port to another branch) is served as the series of commits it brought in, and its
            # diff mixes them. Its changes can't be attributed to this advisory, whatever files they touch.
            patch["merge"] = f"a merge of {count} commits: its diff mixes in changes unrelated to this advisory"
            merges.append(patch["commit"])
            continue
        for change in parse_diff(diff):
            path = change["old"] or change["new"]
            if change["old"] is None:
                patch["skipped"].append(f"{change['new']}: a new file, so not in the affected version")
                continue
            reason = _skip_reason(path)
            if reason:
                patch["skipped"].append(f"{path}: {reason}")
                continue
            rel = map_file(index, package, path)
            if rel is None:
                patch["unmapped"].append(f"{path}: no matching file in this version's source")
                continue
            for hunk in change["hunks"]:
                for fn, how in map_hunk(index, rel, hunk):
                    if fn is None:
                        patch["unmapped"].append(f"{path} hunk at line {hunk['old_start']}: {how}")
                        continue
                    patch["mapped"].append({"symbol": fn.label, "how": how})
                    changed.setdefault(fn.key, (fn, patch["commit"]))
    for key, (fn, commit) in sorted(changed.items()):
        if key in seen:
            continue
        seen.add(key)
        if named_in(text, fn):
            result["affected"].append({"symbol": fn.label, "key": key, "exists": True,
                                       "provenance": f"changed by fix commit {commit} and named in the advisory text"})
        else:
            result["candidates"].append({"symbol": fn.label, "key": key, "exists": True,
                                         "provenance": f"changed by fix commit {commit}; the advisory doesn't name it"})
    if not result["affected"] and not result["candidates"]:
        if merges:
            result["unresolved"].append("fix commit(s) " + ", ".join(merges) + " are merges, whose changes can't be "
                                        "attributed to this advisory")
        if not result["unresolved"]:
            result["unresolved"].append(_no_function_reason(result["patches"]))
    return result


def _no_function_reason(patches: list) -> str:
    """Why a fix that was read fine still names no function: what it did change."""
    other = sorted({item.split(": ", 1)[1] for p in patches for item in p["skipped"]
                    if not item.endswith(": a test or documentation")})
    unmapped = [item for p in patches for item in p["unmapped"]]
    placed = f"; {len(unmapped)} change(s) couldn't be placed in this version's source" if unmapped else ""
    if other and not any(p["mapped"] for p in patches):
        return "the fix changes no PHP function: besides tests, it changed " + ", ".join(other) + placed
    if unmapped:
        return f"the fix's {len(unmapped)} change(s) couldn't be placed in this version's source"
    return "the fix commits changed no function in this version's source"


MBOX_FROM = re.compile(r"^From [0-9a-f]{40} ", re.M)


def commit_count(text: str) -> int:
    """How many commits a GitHub `.patch` holds: one for a plain commit, several for a merge."""
    return len(MBOX_FROM.findall(text)) or 1


def find_symbol(index, package: str, raw: str):
    """A function or method named in an advisory, in this package's source."""
    text = raw.strip().lstrip("\\").replace("->", "::").rstrip("()")
    if "::" in text:
        cls, _, method = text.partition("::")
        candidates = [info for key, infos in index.classes.items() for info in infos
                      if info.package == package and (key == cls.lower() or key.endswith("\\" + cls.lower()))]
        found = [info.methods[method.lower()] for info in candidates if method.lower() in info.methods]
        return found[0] if len(found) == 1 else None
    found = [fns[0] for key, fns in index.functions.items()
             if fns[0].package == package and (key == text.lower() or key.endswith("\\" + text.lower()))]
    return found[0] if len(found) == 1 else None


def named_in(text: str, fn) -> bool:
    """The advisory names this function: `Class::method`, or the class and `method(` both written as in the code."""
    called = re.search(rf"(?<![\w$]){re.escape(fn.name)}\s*\(", text) is not None
    if fn.kind == "method":
        short = fn.cls.split("\\")[-1]
        if re.search(rf"\b{re.escape(short)}\s*(?:::|->)\s*{re.escape(fn.name)}\b", text, re.I):
            return True
        return called and re.search(rf"\b{re.escape(short)}\b", text) is not None
    return called


def _skip_reason(path: str):
    """Why a changed file can't hold the affected function, or None when it is PHP code that can."""
    parts = path.split("/")
    name = parts[-1]
    lower = name.lower()
    if any(p.lower() in ("tests", "test", "docs", "doc", "fixtures") for p in parts[:-1]) or name.endswith("Test.php"):
        return "a test or documentation"
    if lower.endswith(".blade.php"):
        return "a Blade template"
    if name.upper().startswith(("CHANGELOG", "UPGRADE", "README")):
        return "documentation"
    if not lower.endswith((".php", ".inc")):
        return f"not PHP ({os.path.splitext(name)[1] or name})"
    return None


def parse_diff(text: str) -> list:
    files, current, hunk = [], None, None
    lines = text.splitlines()
    for number, line in enumerate(lines):
        if line.startswith("diff --git "):
            current = {"old": None, "new": None, "hunks": []}
            files.append(current)
            hunk = None
        elif current is None:
            continue
        elif line.startswith("--- ") and hunk is None:
            path = line[4:].strip()
            current["old"] = None if path == "/dev/null" else path[2:] if path.startswith("a/") else path
        elif line.startswith("+++ ") and hunk is None:
            path = line[4:].strip()
            current["new"] = None if path == "/dev/null" else path[2:] if path.startswith("b/") else path
        elif line == "-- " and re.fullmatch(r"\d+\.\d+[\w.]*", lines[number + 1].strip() if number + 1 < len(lines) else ""):
            hunk = None          # the trailer `git format-patch` ends a patch with: "-- " then a git version
        elif line.startswith("@@"):
            m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)", line)
            hunk = {"old_start": int(m.group(1)) if m else 0, "lines": []}
            current["hunks"].append(hunk)
        elif hunk is not None and line[:1] in (" ", "-", "+"):
            hunk["lines"].append((line[:1], line[1:]))
        elif hunk is not None and line == "":
            hunk["lines"].append((" ", ""))
    return files


def map_file(index, package: str, path: str):
    """This package's file the diff's path is: the longest matching tail of the path. None when that is ambiguous."""
    wanted = path.split("/")
    best, best_len, tie = None, 0, False
    for rel, info in index.files.items():
        if info["package"] != package:
            continue
        have = rel.split("/")
        n = 0
        while n < min(len(have), len(wanted)) and have[-1 - n] == wanted[-1 - n]:
            n += 1
        if n > best_len:
            best, best_len, tie = rel, n, False
        elif n == best_len and n:
            tie = True
    return best if best_len and not tie else None


def map_hunk(index, rel: str, hunk: dict) -> list:
    """[(function, how)] the hunk's changes fall in, or [(None, reason)]."""
    pre, positions, index_pre = [], [], 0
    for kind, line in hunk["lines"]:
        if kind == "-":
            positions.append(index_pre)
            pre.append(line)
            index_pre += 1
        elif kind == " ":
            pre.append(line)
            index_pre += 1
        else:
            positions.append(max(index_pre - 1, 0))
    positions = sorted(set(positions))
    sf = index.files[rel]["sf"]

    def norm(s):
        return " ".join(s.split())

    wanted = [norm(line) for line in pre]
    local = [norm(line) for line in sf.lines]
    offsets = [o for o in range(len(local) - len(wanted) + 1) if local[o:o + len(wanted)] == wanted] if wanted else []
    functions = [f for f in index.funcs.values() if f.sf.rel == rel and f.kind in ("method", "function")]
    found = []
    if len(offsets) == 1:
        for pos in positions:
            line = offsets[0] + pos + 1
            inside = [f for f in functions if f.line <= line <= f.end_line]
            if inside:
                fn = min(inside, key=lambda f: f.end_line - f.line)
                found.append((fn, f"patch located in this version's file at line {line}"))
            else:
                found.append((None, f"changes code outside any function (line {line})"))
    else:
        for pos in positions:
            name = next((m.group(1) for line in reversed(pre[:pos + 1]) for m in [DECLARATION.search(line)] if m), None)
            matches = [f for f in functions if name and f.name.lower() == name.lower()]
            if len(matches) == 1:
                found.append((matches[0], "the patch context declares this function just above the change"))
            else:
                reason = "the patch doesn't match this version's file" if not offsets else "the patch matches several places"
                found.append((None, reason))
    unique = {}
    for fn, how in found:
        unique.setdefault(fn.key if fn else how, (fn, how))
    return list(unique.values())
