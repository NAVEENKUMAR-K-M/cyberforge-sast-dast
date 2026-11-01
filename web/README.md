# Analyst workspace

A local React/TypeScript interface and API for running the built-in SAST, DAST, and correlator CLIs against the repository's local test applications. It also opens reports created by the command-line workflow.

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

Open the workspace:

```sh
web/.venv/bin/python -m web.server --example
```

Visit **http://127.0.0.1:8000**. The server binds to loopback; `--port` changes the port. The example is clearly labelled until the first UI scan completes. To open a CLI-generated report instead, start with `--report out/issues.json`.

## Start a scan

Choose **Custom application** to scan any application on your machine (give its source folder and the URL where it runs; set `CYBERFORGE_WORKSPACE` to confine source folders to one directory, as the Docker image does, and `CYBERFORGE_ALLOWED_HOSTS` to add hosts such as `host.docker.internal`; the default allows only `localhost` and `127.0.0.1`), or choose **DVWA**, **OWASP Juice Shop**, or one of the bundled CyberForge shops: **PHP Benchmark**, **Python/Flask**, **FastAPI**, **Laravel**, or **Django**. Start the selected app separately using its instructions below or in `sast-engine/README.md`, then run SAST, DAST, or both from the scan panel. The target selector shows the configured local URL and language support. Configure the DAST backend, time budget, URL prefix, SARIF output, optional authentication, SAST prioritization hints, and whether to expand discovery with the full SAST route map under Advanced controls. Route-map expansion can require a larger DAST budget on apps with many routes. The UI shows scanner output, supports stopping an active scan, and switches to the combined report when correlation finishes.

Only `localhost` and `127.0.0.1` target URLs are accepted. Scan artifacts, total elapsed time, and completed scan history are written to `out/scans/<scan-id>/`. Credentials are sent to the selected local target and are not stored in scan history. The UI also supports focused runtime re-testing of code-only findings, route-map browsing, issue comparison, and JSON/HTML/SARIF exports.

The current SAST adapter analyzes PHP. DVWA and the benchmark shop can run SAST and DAST; Juice Shop is JavaScript and is available for DAST only, so its issues remain Runtime only until a JavaScript SAST adapter is added. The UI does not start or stop the target applications.

To inspect the interface before running a scan:

```sh
web/.venv/bin/python -m web.server --example
```

The example is explicitly labelled. `example.issues.json` contains selected actual SAST findings from the deliberately vulnerable benchmark shop, plus recorded DAST evidence from `common/examples/dast_sqli.common.json` and `dast_passive.common.json`, joined with the existing correlator. Its counts represent that selected sample, not a full scan; it contains no invented runtime confirmations or coverage metrics. The credentials in its source snippets are intentionally planted benchmark values.

## Report views

- **Findings:** priority-ordered list, search by title/CWE/route/input/file, evidence-label filters, optional severity/CWE filters, and an explicit held-back finding toggle.
- **Evidence:** linked route/input explanation, runtime observation, payload/response, code location/snippet, expandable trace, CVSS rationale, and bookmarkable finding URLs. Arrow keys move between focused finding links. On narrow screens, selecting a finding opens its detail view with a back button.
- **Coverage:** only recorded scanner metadata, exclusions, deadline status, analysis errors, and suppression reasons. Unavailable metadata stays labelled as unavailable. The current scanner format does not record initial authentication success, per-probe completeness, or engine versions.
- **Need review:** conflicting source/runtime evidence, with the references retained by the correlator. Full conflicting evidence is in the original common reports.
- **Routes:** source route map, handler file/function/line range, method, aliases, and discovered input parameters.
- **Exports:** full issues JSON, standalone HTML, SARIF, and SAST SARIF output when enabled. Attack strings render as text; report URLs are not automatically fetched.

The server loads scanner statistics from the original common-report paths recorded in `issues.json` (absolute paths, repository-relative paths, or report-directory-relative paths). If those files move, issue evidence still works but coverage may be unavailable. A CI gate can be enabled in the scan panel; it reports whether confirmed high or critical findings exceed the threshold.

## Development

Run the API on port 8000, then in a second terminal for hot-reload frontend development:

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
