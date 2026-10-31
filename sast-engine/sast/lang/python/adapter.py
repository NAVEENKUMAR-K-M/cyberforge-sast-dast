"""Runs the whole Python analysis and merges observations into findings."""
from __future__ import annotations

import ast
import os
import re
import time

from sast.config_secrets import scan_config_files
from sast.core import cwe as cwe_mod
from sast.core.language import ScanOptions
from sast.core.model import CONFIDENCE, Finding, Param, ScanResult, fingerprint
from sast.semgrep_runner import PYTHON_NAMED_VALUE, fallback_is_secret, looks_like_real_secret, run_semgrep

from .project import DEFAULT_EXCLUDES, Project
from .routes import extract
from .taint import Interpreter

MAX_PASSES = 3


class PythonAdapter:
    name = "python"

    def scan(self, source_root: str, options: ScanOptions) -> ScanResult:
        started = time.time()
        project = Project(source_root, options.exclude)
        route_map = extract(project, options.base_path)
        interp = Interpreter(project, route_map)

        # Stored flows need a pass to learn what's written before the reads can see it.
        passes, known_stores = 0, -1
        while passes < MAX_PASSES and interp.stored_count() != known_stores:
            known_stores = interp.stored_count()
            passes += 1
            interp.new_pass()
            for handler in route_map.handlers:
                interp.run_handler(handler)
            for generic in route_map.generics:
                interp.run_generic(generic)
        interp.run_unreached()
        route_map.merge_params()

        findings = self._merge(project, interp)
        self._add_config_findings(source_root, findings, options)
        semgrep_error = None
        if options.use_semgrep:
            semgrep_error = self._add_pattern_findings(source_root, project, interp, findings, options)
        ordered = sorted(findings.values(), key=_sort_key)
        stats = {
            "files": len(project.files),
            "files_skipped_too_large": project.skipped,
            "files_with_syntax_errors": len(project.syntax_errors),
            "entry_points": len(route_map.handlers) + len(route_map.generics),
            "routes": len(route_map.routes),
            "rewrite_rules_applied": 0,
            "passes": passes,
            "observations": len(interp.hits),
            "budget_exhausted_entries": interp.budget_hits,
            "semgrep_error": semgrep_error,
            "seconds": round(time.time() - started, 2),
        }
        return ScanResult("python", os.path.abspath(source_root), "", route_map.json_list(),
                          [f.to_json() for f in ordered], stats)

    # ---- observations -> findings --------------------------------------------------------------------------------

    def _merge(self, project, interp) -> dict:
        findings: dict[str, Finding] = {}
        for hit in interp.hits:
            fam = cwe_mod.family(hit.cwe)
            fp = fingerprint(fam, hit.file, hit.func, hit.expr)
            found = findings.get(fp)
            if found is None:
                sf = project.files.get(hit.file)
                found = Finding(fp, hit.cwe, fam, cwe_mod.TITLES.get(fam, f"CWE-{hit.cwe}"), cwe_mod.SEVERITY.get(fam, "medium"),
                                "low", hit.file, hit.line, sf.line_text(hit.line) if sf else "", hit.func, hit.sink,
                                status="suppressed", suppression_reason=hit.reason)
                found.trace = _trace(hit)
                found.engines.add("taint")
                findings[fp] = found
            is_open = hit.reason is None
            confidence = CONFIDENCE[min(hit.taint.penalty, 2)]
            if is_open and found.status == "suppressed":
                found.status, found.suppression_reason = "open", None
                found.source_params, found.conditions = {}, []  # only the inputs that can still do harm
                found.trace, found.sink, found.line = _trace(hit), hit.sink, hit.line
                found.confidence = confidence
                sf = project.files.get(hit.file)
                found.snippet = sf.line_text(hit.line) if sf else found.snippet
            elif is_open and CONFIDENCE.index(confidence) < CONFIDENCE.index(found.confidence):
                found.confidence = confidence
                found.trace = _trace(hit)
            elif not is_open and found.status == "suppressed" and CONFIDENCE.index(confidence) < CONFIDENCE.index(found.confidence):
                found.confidence = confidence
            if is_open or found.status == "suppressed":
                param = Param(hit.taint.name, hit.taint.location)
                found.source_params.setdefault(param.key(), param)
                for condition in hit.conditions:
                    if condition not in found.conditions:
                        found.conditions.append(condition)
            found.routes.update(hit.routes)
            if hit.taint.stored and is_open:
                meta = hit.taint.stored
                found.severity = "high" if found.cwe_family == 79 else found.severity
                found.stored_flow = {
                    "store": meta["store"],
                    "write_file": meta["write_file"],
                    "write_line": meta["write_line"],
                    "write_routes": [r.ref() for r in meta["routes"].values()],
                    "read_file": hit.sink_step[0],
                    "read_line": hit.sink_step[1],
                }
        for found in findings.values():
            if found.status == "open" and not found.routes:
                if _known_unreachable(found, project):
                    found.status = "suppressed"
                    found.suppression_reason = "no route can reach this code"
                else:
                    found.confidence = "low"
                    found.conditions.append("no route found; this code may run in a way the analysis can't see")
        return findings

    def _add_config_findings(self, source_root, findings, options):
        """Config files are outside the code analysis. Their values are left out of the snippet, because
        a real .env holds live secrets and this output gets shared."""
        excludes = set(DEFAULT_EXCLUDES) | set(options.exclude)
        for rel, line, name in scan_config_files(source_root, excludes):
            fp = fingerprint(798, rel, "<config>", name)
            if fp in findings:
                continue
            found = Finding(fp, 798, 798, cwe_mod.TITLES[798], cwe_mod.SEVERITY[798], "medium", rel, line,
                            f"{name} = ****", "<config>", "configuration file")
            found.engines.add("config")
            found.trace = [{"file": rel, "line": line, "note": f"{name} is set to a literal value"}]
            findings[fp] = found

    def _add_pattern_findings(self, source_root, project, interp, findings, options):
        excludes = sorted(set(DEFAULT_EXCLUDES) | set(options.exclude))
        results, error = run_semgrep(source_root, "python.yml", excludes)
        root = os.path.abspath(source_root)
        for item in results:
            rel = os.path.relpath(os.path.abspath(item["path"]), root).replace(os.sep, "/")
            line = item["start"]["line"]
            sf = project.files.get(rel)
            if sf is None:
                continue
            extra = item.get("extra", {})
            meta = extra.get("metadata", {})
            text = sf.line_text(line)
            if meta.get("env_fallback"):
                if not fallback_is_secret(text):
                    continue
            elif meta.get("secret") and not meta.get("known_format") and not looks_like_real_secret(text, PYTHON_NAMED_VALUE):
                continue
            if meta.get("machine_made") and not _machine_made_value(text):
                continue  # {"password": "Updated."} is a status message in a response, not a credential
            cwe = int(meta.get("cwe", 0))
            fam = cwe_mod.family(cwe)
            function = _enclosing_function(project, rel, line)
            fp = fingerprint(fam, rel, function, text)
            same_line = next((f for f in findings.values() if f.cwe_family == fam and f.file == rel and f.line == line), None)
            if same_line is not None:
                same_line.engines.add("semgrep")
                continue
            found = Finding(fp, cwe, fam, cwe_mod.TITLES.get(fam, f"CWE-{cwe}"), cwe_mod.SEVERITY.get(fam, "medium"), "high", rel,
                            line, text, function, extra.get("message", item.get("check_id", "")))
            found.engines.add("semgrep")
            found.trace = [{"file": rel, "line": line, "note": extra.get("message", "")}]
            for handler in interp.route_map.handlers:
                if handler.fd.file.rel == rel and handler.fd.start_line <= line <= handler.fd.end_line:
                    found.routes[(handler.view.id, tuple(sorted(handler.view.methods)))] = handler.view
            findings[fp] = found
        return error


def _machine_made_value(line: str) -> bool:
    """Whether the quoted value on the line could be a generated credential: long enough, no spaces, and mixing in
    digits or symbols the way a word or a sentence doesn't."""
    for match in PYTHON_NAMED_VALUE.finditer(line):
        value = match.group(4).strip().rstrip(".")
        if len(value) >= 8 and " " not in value and re.search(r"[0-9]|[^A-Za-z]", value):
            return True
    return False


def _enclosing_function(project, rel, line) -> str:
    best, size = "<module>", None
    for fd in project.defs_by_file.get(rel, []):
        if fd.node.lineno <= line <= fd.end_line:
            span = fd.end_line - fd.node.lineno
            if size is None or span < size:
                best, size = fd.label, span
    return best


def _known_unreachable(found, project) -> bool:
    """Whether code no route reached is known to be dead. Anything less than certain stays open:
    decorators, callbacks and frameworks can run code that nothing in the project names."""
    function = found.function
    if function in ("<module>", "<config>"):
        return False
    # Code a framework calls on its own: @app.errorhandler, @bp.before_request, @app.on_event, and the like.
    for fd in project.defs_by_file.get(found.file, []):
        if fd.label == function and any(isinstance(d.func if isinstance(d, ast.Call) else d, ast.Attribute) for d in fd.node.decorator_list):
            return False
    name = function.split(".")[-1]
    if name.startswith("__"):
        return False
    return len(re.findall(rf"\b{re.escape(name)}\b", project.all_text)) <= 1


def _trace(hit) -> list:
    steps = list(hit.taint.steps) + [hit.sink_step]
    return [{"file": f, "line": l, "note": n} for f, l, n in steps]


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sort_key(found: Finding):
    return (found.status != "open", _SEVERITY_ORDER.get(found.severity, 4), CONFIDENCE.index(found.confidence), found.file, found.line)
