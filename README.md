# CyberForge: SAST + DAST correlation

**One bug, one ticket.** We scan the code, attack the running app and join both views of each bug into one ranked list:
*this URL and parameter is exploitable, here is the payload, and this is the line to fix.*

- **Labels:** Confirmed (found in both) · Code only · Runtime only
- **Ranking:** CVSS v3.0
- **Languages:** PHP (plain, Laravel) · Python (Flask, FastAPI, Django)
- **Finds:** SQL injection · XSS · command injection · path traversal · open redirect · hard-coded secrets
- **Bonus:** reachability check for vulnerable libraries (Composer apps)

## Run it

### With Docker

Needs Docker Compose v2.24+.

```sh
cp .env.example .env
docker compose up -d --build
```

Open **http://127.0.0.1:8000**. Stop with `docker compose down`.

### Without Docker

Needs Python 3.10+.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m cyberforge scan --source /path/to/app --target http://localhost:8081
```

Optional browser UI (Node 20.19+): `(cd web && npm ci && npm run build) && .venv/bin/python -m web.server`

## Scan an app

1. Start the app. Note its port, say `8081`.
2. Docker only: put `TARGET_SOURCE=/path/to/source` in `.env`, then `docker compose up -d`.
3. Scan it:
   - **Browser:** New scan → Custom application → source `/workspace`, URL `http://host.docker.internal:8081`
   - **Terminal:** `docker compose run --rm scan scan --source . --target http://host.docker.internal:8081`

Reports go to `out/scans/<id>/`: `issues.html` and `issues.json`.

| Flag | Effect |
|---|---|
| `--source`, `--target` | Give one or both |
| `--no-ai`, `--no-sca` | Turn those steps off |
| `--sarif` | Also write SARIF |
| `--fail-on confirmed-high` | CI gate |
| `--deadline N` | Runtime scan budget (seconds) |

**Demo:** `TARGET_SOURCE=./sast-engine/benchmarks/pyshop docker compose --profile demo up -d --build`, then scan `http://host.docker.internal:8089`.

## Safety and privacy

- Scans reach only `localhost`, `127.0.0.1` and, in Docker, `host.docker.internal`.
- Pages named `logout`, `reset`, `delete` are skipped. `DELETE` is never tested.
- If nothing answers at the URL, the scan stops at once.
- **Nothing leaves your machine by default.**
- Dependency check sends package names and versions, never source. Off with `--no-sca`.
- AI step (needs `GROQ_API_KEY`) sends one handler's source, passwords removed. Off with `--no-ai`.
- The AI only proposes a test. The correlator decides what counts as proof.

## What it covers

| ID | Requirement | Where |
|---|---|---|
| FR-1 | SAST scan | [sast-engine/](sast-engine/README.md) |
| FR-2 | DAST scan | [dast-engine/](dast-engine/README.md) |
| FR-3 | One finding format, CWE-numbered | [common/](common/FORMAT.md) |
| FR-4 | Route map | `routes.json`, Routes tab |
| FR-5, FR-6 | Link findings, merge duplicates | [correlator/](correlator/README.md) |
| FR-7 | Three labels | Overview, Issues |
| FR-8 | Issue detail | `issues.html`, Issues tab |
| FR-9 | Confirmed first, then CVSS | Overview: Fix first |
| FR-10 | CLI, API, page, README | `python -m cyberforge scan`, `/api/report`, [web/](web/README.md) |
| B-1 | Auto-verify Code only issues | Every full scan |
| B-2 | Cut SAST noise | Suppressed with a reason |
| B-3 | Explain every link | Issue detail: Why linked |
| B-4 | Fix suggestion | Issue detail: Fix guidance |
| B-5 | Compare scans | New scan → Compare |
| B-6 | SARIF + CI gate | Export menu, `--fail-on` |
| B-7 | Second language | PHP and Python, four frameworks |
| Note | Reachability SCA | [sca/](sca/README.md), Dependencies tab |

All six weakness types are covered (the brief asks for four).

## Results

How we measured:
- One command per app: `python -m cyberforge scan --source <app> --target <url> --no-ai`
- Fresh Python 3.11 environment, no AI, no per-app settings
- Links scored against answer keys in `sast-engine/eval/keys/`
- Every key bug was exploited over HTTP. Every decoy was attacked to prove it is safe.

| App | Correct links | Wrong links | Decoys reported | Confirmed | Time |
|---|---|---|---|---|---|
| PHP shop | 19 / 22 (86%) | 0 | 0 / 13 | 19 | 72 s |
| Flask shop | 21 / 23 (91%) | 0 | 0 / 16 | 21 | 93 s |
| FastAPI shop | 6 / 6 (100%) | 0 | 0 / 4 | 6 | 25 s |
| Django shop | 10 / 10 (100%) | 0 | 0 / 11 | 10 | 40 s |
| Laravel shop | 8 / 8 (100%) | 0 | 0 / 9 | 8 | 36 s |
| DVWA | not scored | 0 seen | – | 14 | 8 min 15 s |

**DVWA** needs a login and difficulty set to low, so it ran with its own config.
- Runtime detection: **11 / 11**, 0 false alarms in 62 findings
- Links not scored: its key has code locations only
- It used the whole time budget: 193 of 276 inputs tested

### Proof

Real Confirmed issues from those runs.
**Validated** = the response shows the weakness. **Partial** = the input reached the target, exploit not shown.

| App | Bug | Payload | Code | Proof |
|---|---|---|---|---|
| PHP shop | Command injection, `GET /api/convert.php?format` | `;expr 5586 + 720` | `app/public/api/convert.php:3` | validated: target computed 6306 |
| PHP shop | SQL injection, `GET /shop.php?code` | `'` | `app/public/shop.php:13` | partial: database error |
| Flask shop | Path traversal, `GET /files/download?file` | `/etc/passwd` | `app/files.py:15` | validated: file content returned |
| Flask shop | SQL injection, `POST /auth/login` | `'` vs `''` | `app/auth.py:25` | partial: database error |
| FastAPI shop | Open redirect, `GET /api/v1/go?url` | canary URL | `main.py:116` | validated: redirected to canary |
| FastAPI shop | SQL injection, `GET /api/v1/items/search?q` | `'` vs `''` | `main.py:67` | partial: database error |
| Django shop | Path traversal, `GET /download/?file` | `/etc/passwd` | `shop/views.py:73` | validated: file content returned |
| Django shop | Open redirect, `GET /go/?url` | canary URL | `shop/views.py:82` | validated: redirected to canary |
| Laravel shop | Command injection, `POST /tools/ping?host` | `;expr 6383 + 839` | `ShopController.php:57` | validated: target computed 7222 |
| Laravel shop | Path traversal, `GET /download?file` | `../../../../etc/passwd` | `ShopController.php:38` | validated: file content returned |
| DVWA | Path traversal, `GET /vulnerabilities/fi/?page` | `/etc/passwd` | `fi/index.php:36` | validated |
| DVWA | Open redirect, `.../open_redirect/source/low.php` | canary URL | `low.php:4` | validated |
| DVWA | SQL injection, `/vulnerabilities/sqli_blind/` | – | – | **left unlinked**: two code bugs fit equally |

### Apps we did not write (source scan only)

"First run" was recorded before we changed anything for that app.

| App | First run | Now | Pairs right | Decoys |
|---|---|---|---|---|
| XVWA (PHP) | 9 / 10 | 10 / 10 | 9 / 9 | 0 / 2 |
| bWAPP (PHP) | 12 / 14 | 14 / 14 | 11 / 11 | 0 / 2 |
| Mutillidae (PHP) | – | 20 / 20 | 17 / 17 | – |
| Vulpy, VAmPI, Vulnerable-Flask-App (Python) | 20 / 26 | 24 / 26 | 7 / 7 | 0 / 13 |
| DVWA (PHP) | – | 18 / 18 | 18 / 18 | 0 / 10 |

### Dependency analysis

| App | Result |
|---|---|
| [composer-app](sca/benchmarks/composer-app) | 3 / 3 as expected: one **Reachable** through another library, one **Unknown**, one **Present-only** |
| Fresh Laravel 11 install (7,650 files) | 4 / 4 **Unknown**, which is correct: facades and the container hide the calls |

### Against the brief's targets

| Measure | Good / Great | Ours |
|---|---|---|
| Code detection | > 60% / > 85% | 100% on our apps, 77–90% on a first run of held-out apps |
| Runtime detection | > 50% / > 80% | 11 / 11 on DVWA |
| Correct links | > 50% / > 80% | 86–100% |
| Wrong links | < 20% / < 5% | 0 |
| False alarms | < 30% / < 10% | 0 |
| Unseen app | > 40% / > 65% | **Not measured** end to end |
| Run time | < 15 / < 5 min | 25–93 s on shops, 8 min 15 s on DVWA |

## Open-source software used

Our own work: route map, taint interpreter, finding merge, five DAST probes, correlator, ranking, re-test loop, dependency call graph.

| Software | Use |
|---|---|
| [Semgrep](https://github.com/semgrep/semgrep) | Runs our SAST rules ([PHP](sast-engine/sast/rules/php.yml), [Python](sast-engine/sast/rules/python.yml)) |
| [tree-sitter](https://github.com/tree-sitter/py-tree-sitter) | Parses PHP |
| [httpx](https://www.python-httpx.org/), [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/), [lxml](https://lxml.de/) | DAST requests and crawling |
| [FastAPI](https://fastapi.tiangolo.com/), [React](https://react.dev/), [Vite](https://vite.dev/) | Web workspace |
| [OSV](https://osv.dev/), [GitHub advisories](https://github.com/advisories), [FIRST EPSS](https://www.first.org/epss/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Public data for the dependency check |
| [Groq API](https://console.groq.com/) | Optional AI step |
| [OWASP ZAP](https://www.zaproxy.org/), [Nuclei](https://github.com/projectdiscovery/nuclei) | Optional DAST backends, off by default |
| [DVWA](https://github.com/digininja/DVWA), [Mutillidae](https://github.com/webpwnized/mutillidae), [bWAPP](https://github.com/raesene/bWAPP), [XVWA](https://github.com/s4n7h0/xvwa), [Vulpy](https://github.com/fportantier/vulpy), [VAmPI](https://github.com/erev0s/VAmPI), [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Benchmarks, used only to measure |

## Limits

- Our shops are a best case. No unseen app has been run end to end.
- SQL injection is usually **partial** proof (database error, not data read).
- A large app can exhaust the runtime budget. Code only then means *not proven*, not *safe*.
- Not covered: DOM XSS, aiohttp / Tornado / Sanic routes.
- Dependency check: Composer only, and needs `vendor/` or every row is Unknown.

## Repository

| Folder | What |
|---|---|
| [cyberforge/](cyberforge/) | One-command scan |
| [sast-engine/](sast-engine/README.md) | Static scanner, route map |
| [dast-engine/](dast-engine/README.md) | Dynamic scanner, five probes |
| [common/](common/FORMAT.md) | Shared finding format |
| [correlator/](correlator/README.md) | Link, merge, label, rank, re-test |
| [sca/](sca/README.md) | Dependency reachability |
| [web/](web/README.md) | Browser workspace and API |

Tests, from the repository root:

```sh
(cd sast-engine && .venv/bin/python -m pytest)
(cd dast-engine && .venv/bin/python -m pytest)
.venv/bin/python -m pytest sca/tests correlator/tests common/tests cyberforge/tests web/tests
(cd web && npm test -- --run)
```

Last run: SAST 349 · Python 372 · UI 63 · DAST 160 passed, 1 failed.
The failing DAST test is out of date: the probe now finds that bug without the hint the test expects.
