# CyberForge: SAST + DAST correlation

One bug, one ticket. CyberForge reads an application's source code (SAST), attacks the running application (DAST), links the two views of each bug and gives **one ranked list**: *this URL and parameter is exploitable, here is the payload that proved it, and this is the line of code to change.*

Each issue is **Confirmed** (found in both), **Code only** or **Runtime only**, and is ranked by CVSS v3.0. It reads PHP (plain, Laravel) and Python (Flask, FastAPI, Django) and covers SQL injection, XSS, command injection, path traversal, open redirect and hard-coded secrets, plus a reachability check for vulnerable libraries in Composer apps.

## Run it

### With Docker

Needs Docker with Compose v2.24+. The interface is built inside the image.

```sh
cp .env.example .env                  # optional: a GROQ_API_KEY turns on the AI-assisted step (see below)
docker compose up -d --build          # first build takes a few minutes
```

Open **http://127.0.0.1:8000**. Stop it with `docker compose down`.

### Without Docker

Needs Python 3.10+. Node 20.19+ is only needed for the browser interface.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt            # Windows: .venv\Scripts\pip
.venv/bin/python -m cyberforge scan --source /path/to/app --target http://localhost:8081
(cd web && npm ci && npm run build) && .venv/bin/python -m web.server     # optional: the interface at http://127.0.0.1:8000
```

### Scan an application

1. **Start the application** the way it came (usually its own `docker compose up -d`) and note its port, for example `8081`.
2. **Give the tool its source.** With Docker, set `TARGET_SOURCE=/path/to/the/source` in `.env` (or copy it into `workspace/`) and run `docker compose up -d` again. It is mounted read-only at `/workspace`.
3. **Scan it.**
   - *Browser:* **New scan** → **Custom application**, source folder `/workspace`, URL `http://host.docker.internal:8081` → **Start scan**.
   - *Command line:* `docker compose run --rm scan scan --source . --target http://host.docker.internal:8081` (without Docker, use the `cyberforge scan` command above).

`--source` and `--target` are each optional: source only gives Code only issues, URL only gives Runtime only issues, both give the full correlation. If nothing answers at the URL, the scan stops at once and says so. `scan --help` lists login options, `--deadline`, `--no-ai`, `--no-sca`, `--sarif` and `--fail-on confirmed-high` (a CI gate).

Reports are written to `out/scans/<id>/`: `issues.html` is a self-contained report and `issues.json` is the data.

**Try it first:** `TARGET_SOURCE=./sast-engine/benchmarks/pyshop docker compose --profile demo up -d --build` starts two deliberately vulnerable demo apps on 8088 (PHP) and 8089 (Flask), then `docker compose run --rm scan scan --source . --target http://host.docker.internal:8089`.

**Safety.** Scans only touch `localhost`, `127.0.0.1` and, in Docker, `host.docker.internal`; any other host is refused before a request is sent. Pages named like `logout`, `reset` or `delete` are never requested and `DELETE` endpoints are not tested.

**What leaves the machine.** Nothing by default. The dependency analysis (Composer apps) sends package names and versions, never source code, to public advisory services (OSV, GitHub advisories, FIRST EPSS, CISA KEV); `--no-sca` turns it off. With a `GROQ_API_KEY`, a model may propose one extra test for a finding the first automatic re-test could not prove; it then receives the handler's source with passwords removed, and `--no-ai` turns it off. A model can only adjust a request; the correlator alone decides whether the result counts as proof.

## What it covers

| ID | Requirement | Where |
|---|---|---|
| FR-1 | SAST scan: file, line, type, severity, snippet | [sast-engine/](sast-engine/) |
| FR-2 | DAST scan: URL, method, parameter, payload, evidence | [dast-engine/](dast-engine/) |
| FR-3 | One common finding format with a CWE | [common/](common/FORMAT.md) |
| FR-4 | Route map: URL to function and lines | SAST's `routes.json`; the **Routes** tab |
| FR-5, FR-6 | Link runtime findings to code; merge duplicates (stable IDs, no copies on a rescan) | [correlator/](correlator/README.md) |
| FR-7 | Confirmed / Code only / Runtime only | Overview and Issues |
| FR-8 | Issue detail: URL, parameter, payload, file, line, snippet, CWE, severity | `issues.html`; **Issues** tab |
| FR-9 | Confirmed first, then CVSS v3.0 risk | Overview: *Fix first* |
| FR-10 | Command line, API and page, with this README | `python -m cyberforge scan`; `/api/report`; [web/](web/README.md) |
| B-1 | Auto-verify Code only issues at runtime | Every full scan re-tests them; AI step optional |
| B-2 | Cut SAST noise | Protected or unreachable code is `suppressed` with a reason |
| B-3 | Explain every link | Issue detail: *Why linked* |
| B-4 | Fix suggestion | Issue detail: *Fix guidance* |
| B-5 | Compare two scans | **New scan** → *Compare scans*; `/api/scans/compare` |
| B-6 | SARIF export and CI gate | **Export** menu; `--sarif`, `--fail-on confirmed-high` |
| B-7 | A second language or framework | PHP and Python: Laravel, Flask, FastAPI, Django |
| Note | Reachability-aware SCA | [sca/](sca/README.md); the **Dependencies** tab |

All six weakness types are covered (the PRD asks for four): CWE-89, 79, 78, 22, 601 and 798.

## Results

Every number below comes from one command, run on the deliberately vulnerable apps in this repository: `python -m cyberforge scan --source <app> --target <url> --no-ai`, in a fresh Python 3.11 environment installed from `requirements.txt`, with no AI and no per-app settings. The exception is DVWA, which needs a login and its difficulty level set to *low*, so it was run with its own config (`dast-engine/dvwa.yaml`) and the same correlation. Links are scored against hand-written answer keys in `sast-engine/eval/keys/` by `correlator/eval/score_links.py`. Every key bug was exploited over HTTP by a verify script, and every decoy was attacked to confirm it is safe.

| App | Correct links | Wrong links | Decoys reported | Confirmed | Time |
|---|---|---|---|---|---|
| PHP shop | 19 / 22 (86%) | 0 | 0 / 13 | 19 | 72 s |
| Flask shop | 21 / 23 (91%) | 0 | 0 / 16 | 21 | 93 s |
| FastAPI shop | 6 / 6 (100%) | 0 | 0 / 4 | 6 | 25 s |
| Django shop | 10 / 10 (100%) | 0 | 0 / 11 | 10 | 40 s |
| Laravel shop | 8 / 8 (100%) | 0 | 0 / 9 | 8 | 36 s |
| DVWA | not scored¹ | 0 seen | – | 14 | 8 min 15 s² |

¹ DVWA's key lists code locations only, so links can't be scored. Its runtime scan found **11 of 11** bugs in DVWA's runtime key with 0 false alarms in 62 findings. ² The runtime scan used its whole time budget (465 s) and stopped with 193 of 276 inputs tested, so a Code only issue there means *not proven*, not *safe*.

**Proof.** Each row is a real Confirmed issue from those runs. *Validated* means the recorded request and response show the weakness itself; *partial* means the input reached the target but exploitation is not shown (SQL injection is confirmed by a database error or a quote differential, not by extracting data).

<details open><summary><strong>PHP shop</strong></summary>

| Issue | Payload | Code | Proof |
|---|---|---|---|
| Command injection, `GET /api/convert.php?format` | `;expr 5586 + 720` | `app/public/api/convert.php:3` | **validated**: the target computed 6306, which is not in the payload |
| XSS, `GET /gallery.php?img` | `dz7p0oi040 onmouseover=dz7p0oi040` (a unique token) | `app/public/gallery.php:5` | **validated**: a script-running payload is reflected unchanged |
| SQL injection, `GET /shop.php?action=track&code` | `'` | `app/public/shop.php:13` | partial: a database error |
</details>

<details><summary><strong>Flask shop</strong></summary>

| Issue | Payload | Code | Proof |
|---|---|---|---|
| Path traversal, `GET /files/download?file` | `/etc/passwd` | `app/files.py:15` | **validated**: system file content in the response |
| Command injection, `POST /admin/backup` (`label`) | `$(sleep 4)` | `app/admin.py:30` | **validated**: two requests delayed 4.1 s against a 0.01 s baseline |
| SQL injection, `POST /auth/login` (`username`) | `'` against `''` | `app/auth.py:25` | partial: a database error |
</details>

<details><summary><strong>FastAPI shop</strong></summary>

| Issue | Payload | Code | Proof |
|---|---|---|---|
| Open redirect, `GET /api/v1/go?url` | `https://dast-canary.invalid/` | `main.py:116` | **validated**: the server redirected to the host the test chose |
| SQL injection, `GET /api/v1/items/search?q` | `'` against `''` | `main.py:67` | partial: a database error |
| Stored XSS, `POST /api/v1/items/{id}/notes` (`body`) | a unique marker | `main.py:96` | partial: reflected, but nothing that would run in a browser |
</details>

<details><summary><strong>Django shop</strong></summary>

| Issue | Payload | Code | Proof |
|---|---|---|---|
| Path traversal, `GET /download/?file` | `/etc/passwd` | `shop/views.py:73` | **validated**: system file content in the response |
| Open redirect, `GET /go/?url` | `https://dast-canary.invalid/` | `shop/views.py:82` | **validated**: redirected to the canary host |
| SQL injection, `GET /api/orders/?customer` | `'` against `''` | `shop/views.py:106` | partial: a database error |
</details>

<details><summary><strong>Laravel shop</strong></summary>

| Issue | Payload | Code | Proof |
|---|---|---|---|
| Command injection, `POST /tools/ping` (`host`) | `;expr 6383 + 839` | `app/Http/Controllers/ShopController.php:57` | **validated**: the target computed 7222 |
| Path traversal, `GET /download?file` | `../../../../etc/passwd` | `app/Http/Controllers/ShopController.php:38` | **validated**: system file content |
| Open redirect, `GET /go?url` | `https://dast-canary.invalid/` | `app/Http/Controllers/ShopController.php:43` | **validated**: redirected to the canary host |
</details>

<details><summary><strong>DVWA</strong></summary>

| Issue | Payload | Code | Proof |
|---|---|---|---|
| Path traversal, `GET /vulnerabilities/fi/?page` | `/etc/passwd` | `vulnerabilities/fi/index.php:36` | **validated** |
| Open redirect, `GET /vulnerabilities/open_redirect/source/low.php?redirect` | `https://dast-canary.invalid/` | `vulnerabilities/open_redirect/source/low.php:4` | **validated** |
| SQL injection, `GET /vulnerabilities/brute/?username` | `'` | `vulnerabilities/brute/source/low.php:13` | partial: a database error |
| SQL injection, `/vulnerabilities/sqli_blind/` | | | **left unlinked on purpose**: two separate code bugs fit it equally, so it stays Runtime only and *ambiguous* rather than guess |
</details>

### Applications we did not write (source analysis only)

Scored against keys we labelled by reading their source. The *first run* column is the honest estimate for an unseen app: it was recorded before we changed anything for that app. The misses were then fixed in general ways, so the later columns are no longer blind.

| App | First run: bugs found | Now: bugs found | Pairs with right route and parameter | Decoys reported |
|---|---|---|---|---|
| XVWA (PHP) | 9 / 10 | 10 / 10 | 9 / 9 | 0 / 2 |
| bWAPP (PHP) | 12 / 14 | 14 / 14 | 11 / 11 | 0 / 2 |
| Mutillidae (PHP) | – | 20 / 20 | 17 / 17 | – |
| Vulpy (two versions), VAmPI, Vulnerable-Flask-App (Python) | 20 / 26 | 24 / 26 | 7 / 7 | 0 / 13 |
| DVWA (PHP) | – | 18 / 18 | 18 / 18 | 0 / 10 |

### Dependency analysis (the bonus note)

| App | Result |
|---|---|
| [sca/benchmarks/composer-app](sca/benchmarks/composer-app) (real, affected package versions) | 3 / 3 statuses as expected. `symfony/http-foundation` is **Reachable**: `index.php` → `HttpFoundationFactory::createRequest` → … → `HeaderUtils::split`, through another dependency. `symfony/yaml` is **Unknown** because `$parser->$action()` picks the method at runtime. `league/flysystem` is **Present-only**. |
| A fresh Laravel 11 install (111 packages, 7,650 PHP files) | 4 / 4 **Unknown**, which is the correct answer: Laravel reaches app code through facades, the container and rules named by string, which a static call graph can't follow. About 4 s. |

### Against the brief's targets

| Measure | Good / Great | Ours |
|---|---|---|
| Code detection | > 60% / > 85% | 100% on our apps; 86–90% on a first, blind run of held-out PHP apps and 77% on Python |
| Runtime detection | > 50% / > 80% | 11 / 11 on DVWA |
| Correct links | > 50% / > 80% | 86–100% on five apps |
| Wrong links | < 20% / < 5% | 0 in every run |
| False alarms | < 30% / < 10% | 0 decoys reported |
| Unseen app | > 40% / > 65% | **Not measured end to end.** The held-out apps above are source-only. Our own apps are a best case |
| Run time | < 15 min / < 5 min | 25–93 s on the shops; 8 min 15 s on DVWA, which used its whole runtime budget |

## Open-source software used

**The route map, the taint interpreter, the finding merge, the five DAST probes, the correlation logic, the ranking, the re-test loop and the dependency call graph are our own work.**

| Software | Used for |
|---|---|
| [Semgrep](https://github.com/semgrep/semgrep) | Runs the SAST pattern rules; the rules ([PHP](sast-engine/sast/rules/php.yml), [Python](sast-engine/sast/rules/python.yml)) are ours |
| [tree-sitter](https://github.com/tree-sitter/py-tree-sitter), [tree-sitter-php](https://github.com/tree-sitter/tree-sitter-php) | Parsing PHP (Python uses the standard library `ast`) |
| [httpx](https://www.python-httpx.org/), [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/), [lxml](https://lxml.de/) | DAST requests, crawling and HTML parsing |
| [FastAPI](https://fastapi.tiangolo.com/), [Uvicorn](https://www.uvicorn.org/), [React](https://react.dev/), [Vite](https://vite.dev/) | The web workspace |
| [OSV](https://osv.dev/), [GitHub advisories](https://github.com/advisories), [FIRST EPSS](https://www.first.org/epss/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Public vulnerability data for the dependency analysis |
| [Groq API](https://console.groq.com/) (`openai/gpt-oss-120b`) | The optional AI-assisted step; off without a key |
| [OWASP ZAP](https://www.zaproxy.org/), [Nuclei](https://github.com/projectdiscovery/nuclei) | Optional alternate DAST backends; off by default |
| [DVWA](https://github.com/digininja/DVWA), [Mutillidae](https://github.com/webpwnized/mutillidae), [bWAPP](https://github.com/raesene/bWAPP), [XVWA](https://github.com/s4n7h0/xvwa), [Vulpy](https://github.com/fportantier/vulpy), [VAmPI](https://github.com/erev0s/VAmPI), [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Benchmark applications, used only to measure accuracy |

CVSS scoring follows the [FIRST v3.0 specification](https://www.first.org/cvss/v3.0/specification-document).

## Limits

- **Our apps are a best case.** We wrote the shops and their keys. The honest estimate for an unseen app is the held-out table above, and no unseen app has been run end to end.
- **SQL injection is usually *partial* proof**, not a validated one: a database error or a quote differential shows the input reaches the query, not that data can be read.
- **A runtime scan can run out of time** on a large app. The report says how many inputs were tested; a Code only issue then means *not proven*, not *safe*.
- **Not covered:** DOM XSS; aiohttp, Tornado and Sanic routes; and a black-box blind spot when code force-appends a suffix to a traversed path (SAST still reports it as Code only).
- **Dependency analysis** covers Composer only and needs the dependency source (`vendor/`); without it, every row is Unknown. Python lockfiles are not supported yet.

## Repository

| Folder | What it is |
|---|---|
| [cyberforge/](cyberforge/) | The one-command scan, `python -m cyberforge scan` |
| [sast-engine/](sast-engine/README.md) | Static scanner for PHP and Python; builds the route map |
| [dast-engine/](dast-engine/README.md) | Dynamic scanner with five attack probes |
| [common/](common/FORMAT.md) | The finding format both scanners write |
| [correlator/](correlator/README.md) | Links, merges, labels and ranks; re-tests Code only issues |
| [sca/](sca/README.md) | Reachability-aware dependency analysis |
| [web/](web/README.md) | The browser workspace and its API |

Tests, from the repository root:

```sh
(cd sast-engine && .venv/bin/python -m pytest)                                   # SAST
(cd dast-engine && .venv/bin/python -m pytest)                                   # DAST
.venv/bin/python -m pytest sca/tests correlator/tests common/tests cyberforge/tests web/tests
(cd web && npm test -- --run)                                                    # the interface
```

On the last full run: SAST 349, Python (dependency analysis, correlator, common format, scan command, web API) 372, interface 63, and DAST 160 passed with one failure. That failure, `test_verify_tries_a_hinted_traversal_prefix_first`, is out of date, not a product bug: the traversal probe now finds the bug without the hint the test expects to be needed.
