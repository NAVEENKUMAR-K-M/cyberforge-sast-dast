# Analyst workspace

A local React/TypeScript interface for an existing correlated report. It reads files, shows source and runtime evidence, and exports JSON or the existing standalone HTML report. It does not launch scans or contact the target application.

## Run

From the repository root, install the Python dependencies in an isolated environment:

```sh
python3 -m venv web/.venv
web/.venv/bin/pip install -r web/requirements.txt
```

Build the frontend once (Node 20.19+ or Node 22.12+):

```sh
cd web
npm ci
npm run build
cd ..
```

Open your report:

```sh
web/.venv/bin/python -m web.server --report out/issues.json
```

Visit **http://127.0.0.1:8000**. The server binds to loopback. `--port` changes the port. Report paths are relative to the directory from which you start the server. Use the reload button after regenerating a report.

To inspect the interface before running a scan:

```sh
web/.venv/bin/python -m web.server --example
```

The example is explicitly labelled. `example.issues.json` contains selected actual SAST findings from the deliberately vulnerable benchmark shop, plus recorded DAST evidence from `common/examples/dast_sqli.common.json` and `dast_passive.common.json`, joined with the existing correlator. Its counts represent that selected sample, not a full scan; it contains no invented runtime confirmations or coverage metrics. The credentials in its source snippets are intentionally planted benchmark values.

## Use

- **Findings:** priority-ordered list, search by title/CWE/route/input/file, evidence-label filters, optional severity/CWE filters, and an explicit held-back finding toggle.
- **Evidence:** linked route/input explanation, runtime observation, payload/response, code location/snippet, expandable trace, CVSS rationale, and bookmarkable finding URLs. Arrow keys move between focused finding links. On narrow screens, selecting a finding opens its detail view with a back button.
- **Coverage:** only recorded scanner metadata, exclusions, deadline status, analysis errors, and suppression reasons. Unavailable metadata stays labelled as unavailable. The current scanner format does not record initial authentication success, per-probe completeness, or engine versions.
- **Need review:** conflicting source/runtime evidence, with the references retained by the correlator. Full conflicting evidence is in the original common reports.
- **Exports:** full issues JSON and the existing standalone HTML report. Attack strings render as text in the UI; no target links are automatically fetched.

The server loads scanner statistics from the original common-report paths recorded in `issues.json` (absolute paths, repository-relative paths, or report-directory-relative paths). If those files move, issue evidence still works but coverage may be unavailable.

## Development

Run the API on port 8000, then in a second terminal:

```sh
cd web
npm run dev
```

Vite proxies `/api` to FastAPI. Styling uses Tailwind CSS with small local shadcn/ui-style primitives (Radix Slot, class-variance-authority); there is no separate component framework or external font service.

## Checks

```sh
cd web
npm test
npm run build
cd ..
web/.venv/bin/pip install pytest httpx
web/.venv/bin/python -m pytest web/tests correlator/tests
```
