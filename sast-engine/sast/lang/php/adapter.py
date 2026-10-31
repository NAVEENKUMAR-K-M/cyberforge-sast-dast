"""Runs the whole PHP analysis and merges observations into findings."""
from __future__ import annotations

import os
import time

from sast.core import cwe as cwe_mod
from sast.core.language import ScanOptions
from sast.config_secrets import scan_config_files
from sast.core.model import CONFIDENCE, Finding, Param, ScanResult, fingerprint
from sast.semgrep_runner import fallback_is_secret, looks_like_real_secret, run_semgrep

from .frameworks import router
from .interp import Interpreter
from .project import DEFAULT_EXCLUDES, Project
from .routes import RouteMap, apply_rewrites, find_entries
from .values import Taint, Val

MAX_PASSES = 3


class PhpAdapter:
    name = "php"

    def scan(self, source_root: str, options: ScanOptions) -> ScanResult:
        started = time.time()
        project = Project(source_root, options.web_root, options.exclude)
        routes = RouteMap(project, options.base_path)
        interp = Interpreter(project, routes)
        interp.collect_constants()
        for sf in project.files.values():
            interp.discover_file(sf)
        framework_routes = router.detect(project, routes, interp)
        entries = find_entries(project, interp.edges)
        # Files that read input may be front controllers, and the pages they dispatch to are analysed through them.
        reads_input = _reads_input(project)
        dynamic_first = sorted(entries, key=lambda rel: rel not in reads_input)

        # Stored flows need a pass to learn what's written before reads can see it.
        passes = 0
        known_stores = -1
        while passes < MAX_PASSES and len(interp.stored) != known_stores:
            known_stores = len(interp.stored)
            passes += 1
            for rel in dynamic_first:
                if rel in interp.selector_targets:
                    continue
                route = routes.for_file(rel)
                interp.run_entry(project.files[rel], [route])
            for handler in framework_routes:
                handler.run(interp)

        self._run_unreached(project, interp)
        rewrites = apply_rewrites(project, routes)
        findings = self._merge(project, interp)
        self._add_config_findings(source_root, project, findings, options)
        semgrep_error = None
        if options.use_semgrep:
            semgrep_error = self._add_pattern_findings(source_root, project, interp, findings, options)
        ordered = sorted(findings.values(), key=_sort_key)
        stats = {
            "files": len(project.files),
            "files_skipped_too_large": project.skipped,
            "entry_points": len(entries),
            "routes": len(routes.routes),
            "rewrite_rules_applied": rewrites,
            "passes": passes,
            "observations": len(interp.hits),
            "budget_exhausted_entries": interp.budget_hits,
            "semgrep_error": semgrep_error,
            "seconds": round(time.time() - started, 2),
        }
        return ScanResult("php", os.path.abspath(source_root), project.web_root, routes.json_list(),
                          [f.to_json() for f in ordered], stats)

    def _run_unreached(self, project, interp):
        """Analyses code no entry point runs, so its findings can be marked unreachable."""
        for rel, sf in project.files.items():
            if rel not in interp.executed_files and sf.has_top_level_code:
                interp.run_entry(sf, [])
        for defs in project.defs_by_file.values():
            for fd in defs:
                if fd.id in interp.executed_funcs:
                    continue
                if fd.cls is None and fd.name.lower() in project.callbacks:
                    self._run_callback(fd, project, interp)
                else:
                    interp.run_function(fd, [])

    def _run_callback(self, fd, project, interp):
        """A function handed over by name is called with values we can't see, so its parameters count as input."""
        seed = {}
        if fd.params is not None:
            for param in fd.params.kids:
                name = param.f("name") if param.type in ("simple_parameter", "variadic_parameter") else None
                if name is not None:
                    step = (fd.sf.rel, param.line, f"parameter {name.text} of handler {fd.label}()")
                    seed[name.text] = Val.of(Taint(name.text.lstrip("$"), "any", (step,), penalty=1))
        route = interp.routes.for_file(fd.sf.rel)
        interp.run_function(fd, [route] if route is not None else [], seed)

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
            confidence = CONFIDENCE[min(hit.penalty, 2)]
            if hit.downgraded:
                confidence = "medium" if confidence == "high" else confidence
            if is_open and found.status == "suppressed":
                found.status, found.suppression_reason = "open", None
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
                    "write_routes": [r.ref() for r in meta["meta"]["routes"].values()],
                    "read_file": hit.sink_step[0],
                    "read_line": hit.sink_step[1],
                }
        for found in findings.values():
            if found.status == "open" and not found.routes:
                if _known_unreachable(found, project, interp):
                    found.status = "suppressed"
                    found.suppression_reason = "no route can reach this code"
                else:
                    found.confidence = "low"
                    found.conditions.append("no route found; this code may run in a way the analysis can't see")
        return findings

    def _add_config_findings(self, source_root, project, findings, options):
        """Config files are outside the PHP analysis. Their values are left out of the snippet, because
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
        # Semgrep ignores .inc and similar by extension, but scans any file it's named explicitly.
        extra = [sf.path for sf in project.files.values() if not sf.rel.endswith(".php")]
        results, error = run_semgrep(source_root, "php.yml", excludes, extra)
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
            elif meta.get("secret") and not meta.get("known_format") and not looks_like_real_secret(text):
                continue
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
            found.routes.update(interp.file_routes.get(rel, {}))
            findings[fp] = found
        return error


def _reads_input(project) -> set:
    return {rel for rel, sf in project.files.items() if b"$_GET" in sf.data or b"$_REQUEST" in sf.data}


def _enclosing_function(project, rel, line) -> str:
    best, size = "<top-level>", None
    for fd in project.defs_by_file.get(rel, []):
        if fd.node.line <= line <= fd.node.end_line:
            span = fd.node.end_line - fd.node.line
            if size is None or span < size:
                best, size = fd.label, span
    return best


def _known_unreachable(found, project, interp) -> bool:
    """Whether code no route reached is known to be dead. Anything less than certain stays open:
    dynamic calls and frameworks can run code that nothing in the project names."""
    function = found.function
    if function in ("<top-level>", "<template>"):
        if interp.dynamic_include:
            return False
        return project.web_root_certain or project.web_path(found.file) is not None
    name = function.split("::")[-1]
    if name.startswith("__") or sum(blob.count(name) for blob in project.all_text_blobs) > 1:
        return False
    if "::" not in function:
        return "function" not in project.dynamic_calls
    return "method" not in project.dynamic_calls and not project.has_external_ancestor(function.split("::")[0])


def _trace(hit) -> list:
    steps = list(hit.taint.steps) + [hit.sink_step]
    return [{"file": f, "line": l, "note": n} for f, l, n in steps]


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sort_key(found: Finding):
    return (found.status != "open", _SEVERITY_ORDER.get(found.severity, 4), CONFIDENCE.index(found.confidence), found.file, found.line)
