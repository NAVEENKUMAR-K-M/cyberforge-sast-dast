# CyberForge: SAST + DAST correlation

One bug, one ticket. CyberForge reads an application's source code (SAST), attacks the running application (DAST), links the two views of each
bug, and gives **one ranked list**: *this URL and parameter is exploitable (here is the payload that proved it), and this is the line of code to change.*
Each issue is labelled **Confirmed** (found by both), **Code only** or **Runtime only**, and ranked by a CVSS v3.0 score. It supports PHP (plain and
Laravel) and Python (Flask, FastAPI, Django) applications and covers SQL injection, XSS, command injection, path traversal, open redirect and hard-coded secrets.
For the architecture, results and pitch material see [hackathon.md](hackathon.md).

## Quick start with Docker

You need Docker with Compose v2.24 or newer. Nothing else: the web interface is built inside the image.

```sh
cp .env.example .env                  # optional: add GROQ_API_KEY to enable the AI-assisted step (see below)
docker compose up -d --build          # the first build takes a few minutes (it installs the scanners and builds the UI)
```

Open **http://127.0.0.1:8000** (if that port is taken, set `CYBERFORGE_PORT` in `.env`). To check it is healthy: `docker compose ps`. To stop it: `docker compose down`.

### Scan an application (the organisers' app, or your own)

1. **Start the application** the way it came (usually its own `docker compose up -d`) and note the port it publishes, for example `8081`.
2. **Give the tool its source code.** Put the source folder's path in `.env` as `TARGET_SOURCE=/path/to/the/application/source`
   (or copy the source into the `workspace/` folder), then run `docker compose up -d` again. It is mounted read-only at `/workspace`.
3. **Scan it**, either in the browser or from the command line:
   - **Browser:** choose **Custom application**, keep the source folder `/workspace`, set the runtime URL to
     `http://host.docker.internal:8081` (the port from step 1), press **Start scan**. Progress and the log appear on the page and the ranked findings open when it finishes.
   - **Command line** (same engine, same results):
     ```sh
     docker compose run --rm scan scan --source . --target http://host.docker.internal:8081
     ```
     `--source .` is the mounted source folder (a subfolder name works too). It is written without a leading `/` on purpose: Git Bash on Windows rewrites
     arguments that start with `/` into Windows paths before Docker sees them. If you do need one, use PowerShell, or prefix the command with `MSYS_NO_PATHCONV=1`.

`host.docker.internal` is how a container reaches the machine Docker runs on, so the application on your own machine is reachable at that name.
Reports are written to `out/scans/<id>/` on your machine (`issues.html` is a self-contained report; `issues.json` is the data) and every run
also appears in the browser's scan history.

| If the application is... | Do this |
|---|---|
| Publishing a port on your machine (the usual case) | `http://host.docker.internal:<port>`, as above |
| Running in Docker but publishing **no** port | Share its network instead: `docker run --rm --env-file .env --network container:<app-container> -v <source>:/workspace:ro -v "$PWD/out:/app/out" cyberforge scan --source . --target http://localhost:<container port>` (command line only) |
| Running directly on your machine, and you don't want Docker for the tool | See "Quick start without Docker" |

`--source` and `--target` are each optional: only the source gives Code-only issues, only the URL gives Runtime-only issues, both give the full correlation.
`docker compose run --rm scan scan --help` lists the rest (login, headers, cookies, deadline, `--no-ai`, `--fail-on confirmed-high` for a CI gate, `--sarif`).

### Try it without an application of your own

```sh
TARGET_SOURCE=./sast-engine/benchmarks/pyshop docker compose --profile demo up -d --build   # starts two deliberately vulnerable demo apps: 8088 (PHP) and 8089 (Flask)
docker compose run --rm scan scan --source . --target http://host.docker.internal:8089
```
Expect about 20 Confirmed issues on this Flask shop in two to three minutes. The demo apps are deliberately vulnerable, so Compose publishes them on `127.0.0.1` only.

### The AI-assisted step

When a finding in the code can't be proven by the first automatic re-test, a language model (Groq, `openai/gpt-oss-120b`) may propose one more request. It can only
adjust the request: it can't change the route, parameter or weakness, and the **correlator alone** decides whether the result counts as proof. Findings proven this way carry an
**AI-assisted** tag. Without a key in `.env`, this step is skipped and **nothing leaves your machine**. With one, the handler's source (passwords removed) is sent to the provider.

### Safety

Scans only touch this machine: `localhost`, `127.0.0.1` and, inside Docker, `host.docker.internal`. Any other host is refused before a request is sent. Pages whose address
contains words such as `logout`, `reset` or `delete` are never requested, and `DELETE` endpoints are not tested. The application's source is mounted read-only.

## Quick start without Docker

Needs Python 3.10 or newer. Node is needed only if you want the browser interface.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt           # Windows: .venv\Scripts\pip install -r requirements.txt
.venv/bin/python -m cyberforge scan --source /path/to/app/source --target http://localhost:8081
```

For the browser interface, build it once (Node 20.19+ or 22.12+) and start the workspace:

```sh
(cd web && npm ci && npm run build)
.venv/bin/python -m web.server                      # http://127.0.0.1:8000
```
In this mode the same **Custom application** option scans any folder on your machine, and the bundled demo applications below are also listed.

## Structure

| Folder | What it is | Start here |
|---|---|---|
| [cyberforge/](cyberforge/) | The one-command scan (`python -m cyberforge scan`), which drives the workspace's scan runner | [cli.py](cyberforge/cli.py) |
| [sast-engine/](sast-engine/) | Static scanner: reads PHP or Python (Flask, FastAPI, spec-first) source, finds bugs and maps URLs to code | [README](sast-engine/README.md) |
| [dast-engine/](dast-engine/) | Dynamic scanner: tests the running app | [README](dast-engine/README.md) |
| [common/](common/) | The one finding format both scanners write, for the correlator to read | [FORMAT.md](common/FORMAT.md) |
| [correlator/](correlator/) | Joins both reports into one issue per bug: Confirmed, Code only or Runtime only | [README](correlator/README.md) |
| [web/](web/) | Local analyst workspace: findings, source/runtime evidence, and scan coverage | [README](web/README.md) |

## Open-source software used

Open-source scanners and libraries are used where noted. **The route map, the taint interpreter, the finding merge, the five DAST probes, the correlation logic, the ranking and
the re-test loop are our own work.**

| Software | Used for |
|---|---|
| [Semgrep](https://github.com/semgrep/semgrep) | Runs the SAST pattern rules. The rules ([PHP](sast-engine/sast/rules/php.yml), [Python](sast-engine/sast/rules/python.yml)) are ours |
| [tree-sitter](https://github.com/tree-sitter/py-tree-sitter), [tree-sitter-php](https://github.com/tree-sitter/tree-sitter-php) | Parses PHP. Python is parsed with the standard library `ast` module |
| [httpx](https://www.python-httpx.org/), [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/), [lxml](https://lxml.de/) | DAST requests, crawling and HTML parsing |
| [FastAPI](https://fastapi.tiangolo.com/), [Uvicorn](https://www.uvicorn.org/), [React](https://react.dev/), [Vite](https://vite.dev/) | The web workspace |
| [Groq API](https://console.groq.com/) (model `openai/gpt-oss-120b`), optionally OpenAI | The optional AI-assisted re-test step; off unless a key is configured |
| [OWASP ZAP](https://www.zaproxy.org/), [Nuclei](https://github.com/projectdiscovery/nuclei) | Optional alternate DAST backends; off by default |
| [DVWA](https://github.com/digininja/DVWA), [Mutillidae](https://github.com/webpwnized/mutillidae), [bWAPP](https://github.com/raesene/bWAPP), [XVWA](https://github.com/s4n7h0/xvwa), [Vulpy](https://github.com/fportantier/vulpy), [VAmPI](https://github.com/erev0s/VAmPI), [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Benchmark applications used only to measure accuracy |

The CVSS v3.0 scoring follows the [FIRST specification](https://www.first.org/cvss/v3.0/specification-document).

## Analyst interface

The [web workspace](web/README.md) runs local scans and opens the combined report. Choose **Custom application** (any source folder and the URL where it runs), DVWA, OWASP Juice Shop, or one of the bundled benchmark shops (PHP or Python); select SAST and/or DAST; follow progress and logs; inspect findings, source routes, coverage, conflicts, and compare completed scans. It exports JSON, standalone HTML, and SARIF. SAST hints are enabled by default; full route-map expansion is optional because it can consume DAST's budget on larger apps. After installing its dependencies and building the frontend:

```sh
web/.venv/bin/python -m web.server --example
```

Open **http://127.0.0.1:8000**. The selected app must already be running locally. The UI limits scan targets to `localhost` and `127.0.0.1`, and shows the full SAST + DAST + correlation elapsed time. SAST supports PHP and Python; Juice Shop runs DAST only.

## Running everything on the benchmark shop

Each engine has its own virtual environment; see its README. The shop is deliberately vulnerable and listens on `127.0.0.1` only.

```sh
# 1. SAST reads the source and writes routes.json
cd sast-engine
.venv/bin/python -m sast.cli scan benchmarks/shop --out out/shop

# 2. Start the shop
docker compose -f benchmarks/shop/docker-compose.yml up -d --build

# 3. DAST tests the running shop, using SAST's route map and hints
cd ../dast-engine
.venv/bin/python main.py scan --target http://127.0.0.1:8088 --config config.yaml \
    --route-map ../sast-engine/out/shop/routes.json --hints ../sast-engine/out/shop/hints.json --output output/shop.json

# 4. Check both outputs against the shared format
cd ..
sast-engine/.venv/bin/python common/validate.py sast-engine/out/shop/findings.common.json dast-engine/output/shop.common.json

# 5. Join them into issues
sast-engine/.venv/bin/python -m correlator.cli --sast sast-engine/out/shop/findings.common.json \
    --dast dast-engine/output/shop.common.json --out out/issues.json

# 6. Stop the shop
docker compose -f sast-engine/benchmarks/shop/docker-compose.yml down
```

The correlator only needs `jsonschema`, which the SAST environment already has.

## Running everything on the Python benchmark shop

Same steps, with the Flask shop on port 8089. SAST picks the language from the files (`--language python` forces it):

```sh
cd sast-engine
.venv/bin/python -m sast.cli scan benchmarks/pyshop --out out/pyshop
docker compose -f benchmarks/pyshop/docker-compose.yml up -d --build
cd ../dast-engine
.venv/bin/python main.py scan --target http://127.0.0.1:8089 --config pyshop.yaml \
    --route-map ../sast-engine/out/pyshop/routes.json --hints ../sast-engine/out/pyshop/hints.json --output output/pyshop.json
cd ..
sast-engine/.venv/bin/python -m correlator.cli --sast sast-engine/out/pyshop/findings.common.json \
    --dast dast-engine/output/pyshop.common.json --out out/pyshop_issues.json
sast-engine/.venv/bin/python correlator/eval/score_links.py out/pyshop_issues.json sast-engine/eval/keys/pyshop.json
docker compose -f sast-engine/benchmarks/pyshop/docker-compose.yml down
```

`pyshop.yaml` drops `logout` and `reset` from the denylist because pyshop's are harmless and carry a bug the key expects; DAST skips `DELETE` endpoints unless given `--allow-destructive`.

## Tests

Run these from the repo root:

```sh
(cd sast-engine && .venv/bin/python -m pytest)           # SAST
(cd dast-engine && .venv/bin/python -m pytest)           # DAST
sast-engine/.venv/bin/python -m pytest common/tests      # the shared format
sast-engine/.venv/bin/python -m pytest correlator/tests  # the correlator
web/.venv/bin/python -m pytest cyberforge/tests web/tests  # the one-command scan, and the analyst workspace's API (needs pytest, httpx)
(cd web && npm test -- --run)                             # the analyst workspace's UI
```

### Latest run (2026-11-01)

| Suite | Result |
|---|---|
| sast-engine | 349 passed |
| dast-engine | 160 passed, 1 failed |
| correlator | 159 passed |
| common | 16 passed |
| cyberforge (one-command scan, pytest) | 28 passed |
| web (API, pytest) | 21 passed, 1 skipped |
| web (UI, vitest) | 21 passed |
| **Total** | **754 passed, 1 failed, 1 skipped** |

Every Python suite was run in **one fresh virtual environment built only from the root `requirements.txt`** (`pip check` clean), which is what a judge's install is.
The skipped test creates a symlink, which needs OS permission on Windows; it runs on Linux and in Docker.

The one failure, `dast-engine/tests/test_main_cli.py::test_verify_tries_a_hinted_traversal_prefix_first`,
is a test-environment issue, not a product bug: it shells out to `main.py verify` with a route argument
that Git Bash's path conversion rewrites into a Windows path before Python ever sees it, on Windows only.
It fails the same way with no code changes at all.

Two real, non-pre-existing issues surfaced and were fixed while producing this run:
- `dast-engine/tests/fixtures/vuln_app.py`'s `/filtered_traversal` fixture used `os.path`/`os.path.join`
  for its traversal check, which on Windows treats `\` as a separator and honors a drive letter as an
  absolute-path override — letting two bypasses unrelated to the test's actual target ("backslash
  traversal", "`C:\`-prefixed path") win before the intended "`....//`" filter-bypass technique could.
  Rewritten with `posixpath` against a virtual root, so the fixture behaves like the Linux containers the
  real benchmark apps run in, regardless of which OS runs the test.
- `web/tests/test_server.py` read the real, developer-machine `out/scans/` history through a module-level
  constant with no test isolation, so a report a test asked for by path could be silently outranked by
  whatever scan happened to be newest on disk. Added an autouse fixture that points scan history at a
  temp directory for the whole file.
