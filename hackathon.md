# CyberForge — SAST + DAST Correlation

> **One bug, one ticket.** We scan the code, attack the running app, and join the two views of the same bug into a single, ranked, evidence-backed issue: *this URL and parameter is exploitable (here's the payload that proved it), and this is the line of code to change.*

---

## 1. The 30-second pitch

Security teams run two scanners that never talk to each other. The static scanner (SAST) says *"SQL injection in `orders.py`, line 88"*. The dynamic scanner (DAST) says *"SQL injection at `/api/orders`, parameter `id`"*. It is one bug, but it shows up as two tickets, buried in hundreds of findings, with no way to tell a proven bug from a guess.

CyberForge fixes that end to end:

1. **SAST** reads the source, builds a **route map** (URL → function → lines) and finds bugs with real taint tracking.
2. **DAST** attacks the running app, **using the route map and SAST's hints** to reach pages a crawler can't find.
3. The **correlator** links each runtime finding to the code that causes it, merges duplicates, labels every issue **Confirmed / Code only / Runtime only**, and ranks them by a real **CVSS v3.0** score.
4. A **re-test loop** takes every "Code only" bug that looks real and tries to prove it at runtime, deterministically first, then with an **AI-proposed** follow-up. The AI can suggest a test; **only the correlator decides** whether the evidence counts.

The result is one short list: **proven bugs first, with URL, parameter, payload, file, line, snippet, CWE, score and a fix.**

**What makes it different:** we optimise for the thing judges weigh most. *Correct* links, not *many* links. Across every benchmark run: **0 wrong links and 0 safe decoys reported.**

---

## 2. The problem, in the PRD's words

| Problem | What we do about it |
|---|---|
| **Same bug, two tickets** | Link by CWE family + route + parameter into one issue; merge every sighting. |
| **Too much noise** | SAST reads protections *in context* (a parameterised query, an allowlist, the right escape for the right place) and marks protected or unreachable code `suppressed` with a reason instead of reporting it. |
| **No place to fix** | Every Confirmed issue carries the exact file, line, snippet and the code trace from input to sink. |
| **No clear priority** | Confirmed first, then CVSS v3.0 *temporal* score, so a proven SQL injection outranks a Code-only weak hash. |

---

## 3. Architecture at a glance

```
                    ┌─────────────────── web workspace (FastAPI + React/TS) ───────────────────┐
                    │  launch scan · findings table · evidence · routes · coverage ·           │
                    │  need review · compare scans · JSON / HTML / SARIF export · AI status    │
                    └───────────────┬──────────────────────────────────────────────┬───────────┘
                                    │ POST /api/scans                              │ GET /api/report
                                    ▼                                              │
  source code ───► ┌────────────┐  routes.json                                      │
                   │    SAST    │  hints.json            ┌────────────┐             │
                   │ PHP+Python ├────────────────────────►    DAST    │             │
                   └─────┬──────┘  (URL → code, which    │ 5 probes   │             │
                         │          inputs are risky)    │ + crawler  │──► running app (localhost only)
                         │                               └─────┬──────┘
          findings.common.json                        dast.common.json
                         │                                     │
                         └──────────────┬──────────────────────┘
                                        ▼
                              ┌───────────────────┐   re-test a "Code only" bug
                              │    CORRELATOR     │◄──────────────────────────┐
                              │ link · merge ·    │                           │
                              │ label · rank      │──► issues.json / .html    │
                              └─────────┬─────────┘                    ┌──────┴───────┐
                                        │ proposes a follow-up test    │ DAST verify  │
                                        ▼                              └──────────────┘
                              ┌───────────────────┐
                              │  AI planner (Groq)│  can shape a request; can never
                              │  bounded, opt-in  │  change route, parameter or weakness
                              └───────────────────┘
```

### Components

| Folder | Role | Key modules |
|---|---|---|
| `sast-engine/` | Reads PHP and Python source; finds bugs; builds the route map | `sast/lang/php/` (tree-sitter + abstract interpreter), `sast/lang/python/` (stdlib `ast` taint engine), `sast/rules/*.yml` (own Semgrep rules), `sast/core/language.py` (adapter registry) |
| `dast-engine/` | Attacks the running app with five custom probes | `core/` (scope guard, auth, rate-limited client, scheduler), `discovery/` (crawler, OpenAPI, route-map loader), `scanners/probes/` (sqli, xss, cmdi, path_traversal, open_redirect) |
| `common/` | The one finding format both scanners write (FR-3) | `FORMAT.md`, `finding.schema.json`, `cwe_families.json`, `validate.py` |
| `correlator/` | The core of the product: link, merge, label, rank, re-test | `correlate.py`, `evidence.py`, `rank.py` + `cvss.py`, `loop.py`, `planner.py`, `report.py` |
| `web/` | Local analyst workspace and API | `server.py` (FastAPI), `scan_manager.py` (job orchestration), `src/` (React + TypeScript) |

**Design principle:** the scanners never import each other. They meet only through two JSON files in the common format, so either side can be swapped, run alone, or fed by a third-party tool (the DAST engine can also drive OWASP ZAP or Nuclei as alternate backends).

---

## 4. The common format (FR-3)

Both scanners write `*.common.json`. One finding, one shape, one CWE vocabulary:

```jsonc
{ "id": "sast:<fingerprint> | dast:<finding_id>",   // stable across rescans → no copies (FR-6)
  "cwe": "CWE-89", "cwe_family": "CWE-89",           // compare the *family*, scanners label things differently
  "severity": "high", "confidence": "high", "status": "open | suppressed",
  "params": [{ "name": "id", "location": "query" }],
  "routes": [{ "path": "/api/orders/{id}", "aliases": [], "selector": null, "methods": ["GET"] }],
  "code":    { "file", "line", "snippet", "function", "sink", "trace", "conditions", "stored_flow", ... },   // SAST only
  "runtime": { "method", "url", "payload", "technique", "verification", "evidence" } }                       // DAST only
```

Route templates are always written with `{name}` placeholders (`/orders/{order_id}`, never `<int:order_id>` or `:order_id`) and compared by *position*, so a crawl's `/orders/{id}` meets the code's `/orders/<int:order_id>`.

---

## 5. SAST engine — how it finds bugs

**Languages and frameworks:** PHP (plain and Laravel on real apps; Slim/Symfony-style routes on fixtures only) and Python (Flask, FastAPI, Django + DRF, spec-first/OpenAPI apps). `--language auto` picks the right adapter from the files.

**Pipeline**

1. **Parse** — tree-sitter for PHP; the standard `ast` module for Python (no extra parser).
2. **Route map (FR-4)** — which URL runs which function, which lines. Handles plain files, front controllers (`index.php?page=x`), `switch` dispatch, Laravel `Route::` groups, Flask blueprints (including prefixes registered from another file), FastAPI routers and `Depends`, Django `include()` chains, converters and class-based views. Typed parameters (`<int:id>`) are marked `validated` so DAST doesn't waste time on them.
3. **Abstract interpretation** — each entry point is "run" symbolically, inlining functions and methods and following includes, tracking both **taint** and **possible string values**. That is how it resolves `include "source/{$file}"` after a `switch`, or a bug where one file builds `$html` and another echoes it.
4. **Protections read in context** — `htmlspecialchars` is safe in HTML text but not in an unquoted attribute; `mysqli_real_escape_string` is safe inside quotes but not around an unquoted number; a `str_replace` filter does not count; `shlex.quote`, list-form `subprocess`, `secure_filename`, `realpath` + prefix checks, bound parameters and allowlists all do.
5. **Stored flows** — values written on one page and shown on another are linked through DB columns, ORM models and the session, so a stored XSS is tied to the route that *wrote* it.
6. **Pattern rules** (our own Semgrep rules) for what doesn't need taint: hard-coded secrets, weak hashes, predictable tokens, debug settings.
7. **Merge** — fingerprints contain no line numbers, so edits and rescans don't create copies. Protected or unreachable code is kept and marked `suppressed` with a reason (**B-2**).

**Covered weaknesses:** SQL injection (89), XSS incl. stored (79), command injection (78), path traversal / file inclusion (22), open redirect (601), hard-coded secrets (798, code-only), plus deserialization/code injection (502/94), weak hashes (327/328) and debug/predictable tokens.

---

## 6. DAST engine — how it proves bugs

**Rule one: never report on a status code alone.** Every probe owns its payloads, its confirmation logic and its confidence grade, and every tentative hit is re-checked against a **clean control request** so app content that merely *looks* like a hit is rejected.

| Probe | How it confirms |
|---|---|
| **SQL injection** | Database error signature (MySQL, Postgres, SQLite, MSSQL, Oracle, Python drivers) → boolean pair → time-based (hinted only). For apps that hide errors: a **quote differential** (`'` fails, `''` and a harmless value succeed, and the failure repeats), a **numeric differential** (`7-0` works, `7'` fails) and an **ORDER-BY identifier differential**. |
| **XSS** | Reflection with **context classification**: body text, attribute (quoted/unquoted), script. A surviving angle bracket is what matters in body text; quotes matter in attributes. Plus a **stored-marker** check that writes a unique marker through forms *and* JSON APIs and re-reads known pages. |
| **Command injection** | A **computed marker** (e.g. the sum the payload asked for, which isn't in the payload) found in the response; blind time-based variants with `$(sleep)`, backticks, pipe and newline forms. |
| **Path traversal** | Distinctive file *content* (`root:x:0:0`, `[fonts]`), never a common word; single-pass filter bypass (`....//`); a blind **differential** for apps that never show the file. |
| **Open redirect** | A redirect whose destination **host** is our canary domain (netloc match, not substring), in headers, meta refresh or JS. |

**Engineered for real apps**

- **Uses SAST's output:** `--route-map` reaches pages a crawler can't find; `--hints` run the expensive tests where the code says a bug is likely. Crawl-only on our Flask benchmark finds **24%** of the runtime-provable bugs; with SAST's route map and hints, **92%**.
- **CSRF-protected apps (Laravel, Django, Rails):** hidden token fields and `XSRF-TOKEN`/`csrftoken` cookies are carried the way a browser would, so writes aren't refused before they reach the code.
- **OpenAPI-aware:** reads `$ref`/`allOf`/`required` so JSON bodies are valid and aren't rejected with a 422 before reaching the sink.
- **Typed parameters skipped** (an integer or UUID can't carry a payload).
- **Time-aware scheduling:** hinted tests first, cheapest probe first, concurrent (4 at a time), slow endpoints in their own lane, adaptive per-endpoint rate limiter that doesn't mistake a debug-off 500 for load.
- **Deterministic IDs:** re-running a scan produces identical `finding_id` values.

**Safety (the PRD's "scan only the test app" rule), enforced in code, not by convention**

- A **scope guard** (allowlist of hosts, denylist of paths such as `logout`, `setup`, `reset`, `delete`) vets every request *and every redirect*.
- The web UI **rejects any target that isn't `localhost` / `127.0.0.1`.**
- `DELETE` endpoints are skipped unless `--allow-destructive` is passed; destructive pages (a GET-based password change in DVWA) are denylisted after we found a crawler genuinely changing the account password.
- Benchmark containers are published on loopback only.

---

## 7. The correlator — the heart of the product

This is the part we built hardest, because **correlation is what is judged most**.

### 7.1 When a runtime finding links to code (FR-5)

A link requires **all** of:

1. the same **CWE family**;
2. the DAST route equals the code's route, one of its **aliases** (`/shop/` for `/shop/index.php`), or a **`{name}` template**;
3. the page **selector** matches, if the code has one (`action=view`);
4. the same **parameter**, in a compatible place (`any` = query or body);
5. the code finding is **open**, not marked safe.

Stored bugs can also match on the route where the value was *written*.

| Situation | Result |
|---|---|
| Exactly one code bug fits | **Confirmed**, one issue holding all the evidence |
| Several *different* code bugs fit | **Not linked.** Runtime only, `ambiguous`, with `candidates` |
| Only code marked safe fits | A **conflict**. Neither side decides; both kept |
| Nothing fits | **Runtime only** |
| Code bug never seen at runtime | **Code only** (hard-coded secrets always are) |

**We refuse to guess.** The PRD's "wrong links" metric (Great: under 5%) is the one a tool is most tempted to cheat. Where the evidence can't separate two candidates, we say so.

### 7.2 Resolving ambiguity with *evidence*, not a guess

DVWA's SQL injection page picks `low.php` / `medium.php` / `high.php` from a difficulty cookie. One URL, one parameter, three real bugs. SAST records each branch's guard (`$vulnerabilityFile == 'low.php'`), and DAST records the setup it pinned once after login (`security=low`, then the setup page is denylisted so it can't change). The correlator uses that real, scan-wide fact to rule out `medium` and `high` (6 candidates → 2). The remaining two are genuinely separate bugs (a MySQL branch and a SQLite branch in the same file), so it **still refuses to pick**.

### 7.3 One bug = one issue (FR-6)

- *Code side:* open findings with the same CWE family, in the same function, sharing an input name **and fed by the same built value** are one bug (e.g. one query used twice). Separately built statements stay separate bugs: each needs its own fix.
- *Runtime side:* DAST findings with the same CWE family, route, selector, parameter **and place in the request** are one observation.
- IDs are content hashes and every list is sorted, so the same scans always produce the same file.

### 7.4 Don't trust the scanner's own confidence

`evidence.py` reads each finding's recorded payload and response and sets its own level:

| Level | Meaning |
|---|---|
| `validated` | The evidence shows the weakness itself (a computed result, system-file content, a redirect to our canary host, a script-running payload reflected unchanged) |
| `partial` | The input reached the target, but exploitation isn't shown (a DB error, an echo) |
| `unchecked` / `none` | No check for this weakness / not seen at runtime |

"Confirmed" still means *found in both*; `runtime_verification` says how strongly the runtime side was proven and feeds the score.

### 7.5 Ranking (FR-9) — real CVSS, not a toy score

Confirmed issues first, then **CVSS v3.0 Temporal** score, ties broken by Base score, then issue ID (so order is stable). Base vectors follow how NVD usually scores each weakness in a web app (SQL/command injection 9.8, path traversal 7.5, XSS and open redirect 6.1, weak hashes 5.9, missing headers 4.3). **Our evidence moves the temporal metrics:** validated runtime proof → `E:F`; code-only → `E:U`; found in both → `RC:C`. The equations are implemented from the FIRST specification and tested against published scores. Every metric choice is listed in `risk_factors`.

### 7.6 Labels (FR-7)

**Confirmed** (found by both) · **Code only** (SAST, not proven) · **Runtime only** (DAST, no code location found). Low-confidence code-only issues are kept but held back from the report; a hard-coded secret is always Code only.

---

## 8. The AI layer — bounded, auditable, never the judge

**Auto-verify (B-1)** is part of correlation, not a separate step. For every Code-only issue that looks real (open, not low-confidence, has a route and a named input, for a weakness DAST can re-test):

| Round | What happens | AI? |
|---|---|---|
| **1** | The DAST engine re-tests exactly what the code describes: same route, parameter, place in the request and method. | No. Deterministic. Nothing leaves the machine. |
| **2** | If round 1 is only partial, a **planner** (Groq, `openai/gpt-oss-120b`) sees the handler source and what round 1 actually sent and got back, and may propose extra fields or a payload hint. | Yes, when a key is configured. |

Every case ends with an outcome and a reason: `validated`, `unresolved` (**not safe**, just not proven), `blocked` (route denylisted, no request sent) or `no supported test`.

**Guardrails — this is the part to emphasise**

- **The planner never makes a link.** A re-test that reproduces comes back as a *new DAST finding*, matched by the same rules and judged by the same evidence checks as every other finding.
- It **cannot change the route, parameter or weakness**, repeat a request, or exceed `check_plan`'s limits; at most one model call per case, ≤ 20 cases, ≤ 180 s.
- **What leaves the machine** (only when a key is set): the handler file plus up to two trace files (numbered, ≤ 6,000 chars each, **password-like literals removed**), the snippet and trace, and a sample of round 1. Only files inside the scanned source root are read.
- **Failure is safe:** no key, no credit or no network → the case just stops after round 1, with the reason recorded.
- **Full audit trail:** each round keeps the model, a hash of the prompt, files sent, the raw reply and token counts.
- **The UI says so:** findings whose proof came from an AI-proposed round carry an **AI-assisted** tag, and the issue explains that *"the correlator alone decided it counted as proof."*

**Real example (recorded run):** on our PHP shop, `lang.php` only redirects when the `back` value contains the substring `forge-shop`. Round 1 (generic redirect payloads) got `200` every time. The planner read the handler and answered *"the redirect only occurs when the back parameter contains the string 'forge-shop'"*, proposing the hint `https://{canary}/forge-shop`. The engine sent it, got a `302` to our canary host, the evidence check rated it **validated** (*"the server redirected to dast-canary.invalid, the destination the test chose"*), and the issue became **Confirmed**, tagged AI-assisted.

---

## 9. The web workspace and interfaces (FR-10, B-3 to B-6)

- **Run a scan from the UI:** pick **Custom application** (any source folder + the URL where it runs; this is how the organisers' app is scanned) or one of our bundled targets (DVWA, Juice Shop, PHP / Flask / FastAPI / Laravel / Django shops), choose SAST and/or DAST, watch live logs and stages, stop a scan. SAST → DAST (with route map + hints) → correlate (with auto-verify) in one click. The same engine runs from the command line (`python -m cyberforge scan --source <dir> --target <url>`) and its runs show up in the UI history.
- **Findings table** ranked by risk, with label badge, AI-assisted tag, CWE, location; filters and search.
- **Issue detail:** URL, parameter, payload, file, line, snippet, trace, CVSS and why each metric was chosen, **why linked** (match basis: exact / alias / template / stored-write) (**B-3**), a plain-English **fix suggestion** per CWE (**B-4**).
- **Routes** tab (FR-4 route map), **Coverage** (what DAST actually tested; incomplete scans say so instead of implying safety), **Need review** (conflicts and ambiguous links).
- **Compare two scans** → new / fixed / still-open (**B-5**).
- **Exports:** JSON, standalone HTML, **SARIF**; optional **CI gate** that fails on Confirmed high/critical issues (**B-6**).
- **CLI** for every stage and a small REST API (`POST /api/scans`, `GET /api/report`, `GET /api/scans/{id}`, …).

---

## 10. PRD coverage

| ID | Requirement | Status |
|---|---|---|
| FR-1 | SAST scan with file, line, type, severity, snippet | ✅ |
| FR-2 | DAST scan with URL, method, parameter, payload, evidence | ✅ |
| FR-3 | One common format, CWE-numbered | ✅ `common/` + contract tests |
| FR-4 | Route map: URL → function → lines | ✅ PHP and Python |
| FR-5 | Correlate on CWE + route + parameter | ✅ |
| FR-6 | Merge duplicates; rescans make no copies | ✅ content-hash IDs |
| FR-7 | Confirmed / Code only / Runtime only | ✅ |
| FR-8 | Issue detail page | ✅ HTML report + UI |
| FR-9 | Confirmed first, then risk score | ✅ CVSS v3.0 temporal |
| FR-10 | CLI / API / page + README | ✅ all three |
| B-1 | Auto-verify Code-only → Confirmed | ✅ deterministic round 1 + AI round 2 |
| B-2 | Cut SAST noise | ✅ context-aware suppression with reasons |
| B-3 | Explain every link | ✅ |
| B-4 | Fix suggestion | ✅ |
| B-5 | Compare scans | ✅ |
| B-6 | SARIF + CI gate | ✅ |
| B-7 | Second language/framework | ✅ PHP + Python; Laravel, Flask, FastAPI, Django |
| Note | Reachability-aware SCA | ❌ not built (out of scope) |

**Weakness types:** all six (SQLi, XSS, command injection, path traversal, open redirect, hard-coded secrets). The PRD asks for four.

---

## 11. Results

We built our own benchmark apps with answer keys, because a scanner tuned only on its own key proves little. Every key bug is **exploited over HTTP** by a verify script, and every decoy is attacked to prove it is genuinely safe.

### Correlation (what is judged most) — latest runs

| App | Planted pairs correctly linked | Wrong links | Safe decoys reported |
|---|---|---|---|
| PHP shop | **21 / 22 (95%)** | **0** | **0 / 13** |
| Flask shop | **22 / 23 (96%)** | **0** | **0 / 16** |
| Laravel 11 shop | **8 / 8 (100%)** | **0** | **0 / 9** |
| Django 5 shop | **10 / 10 (100%)** | **0** | **0 / 11** |

### Against the PRD targets

| Measure | Good | Great | Ours |
|---|---|---|---|
| Code detection | > 60% | > 85% | **100%** on our apps; **86–90%** on first (blind) run of held-out apps |
| Runtime detection | > 50% | > 80% | **92%** (Flask shop), **100%** (DVWA regression) |
| Correct links | > 50% | > 80% | **95–100%** |
| Wrong links | < 20% | < 5% | **0%** |
| False alarms | < 30% | < 10% | **0%** |
| Unseen app | > 40% | > 65% | see below |
| Run time | < 15 min | < 5 min | **~1.5–2.5 min** per benchmark shop including auto-verify (DVWA with full route-map expansion uses the whole DAST budget, up to 8 min) |

### The honest "unseen app" evidence

Our own apps are a best case, so we also ran apps **we did not write**, labelled by reading their source *before* tuning, and recorded the **first-run** score:

| Held-out app | First run: bugs found | Notes |
|---|---|---|
| XVWA (PHP) | 9/10 (90%) | misses fixed in general ways afterwards |
| bWAPP (PHP) | 12/14 (86%) | " |
| Vulpy (bad + good), VAmPI, Vulnerable-Flask-App (Python) | 20/26 (77%) | misses were blueprint prefixes, Jinja `\|safe`, spec-first routes and framework-called functions, then fixed in general ways |

SAST precision, hand-checked on a random sample of 24 findings outside the keys: **high confidence 10/10 real, medium 4/7, low 0/7.** Confidence genuinely separates real from weak.

### Engineering quality

**716 automated tests pass** (SAST 349, DAST 160, correlator 159, common 16, web API 12, web UI 20). The one failure is a known Windows/Git-Bash path-conversion quirk in a CLI-subprocess test, unrelated to product code. Every false positive we hit on live DVWA became a regression test.

---

## 12. Limits we state up front (judges respect this)

- **Our apps are a best case.** The true test is the unseen app; the held-out numbers above are the honest estimate.
- **Framework gaps:** aiohttp / Tornado / Sanic routes aren't read (findings, no routes); DRF generic views and `ModelViewSet`, ModelForm `Meta.fields`, SQLAlchemy ORM stored flows and Jinja macros aren't followed; Laravel Livewire / Inertia / queued jobs untested.
- **A black-box blind spot we don't paper over:** when code force-appends a suffix to a traversed path (`$name . ".php"`), no runtime signal separates an escape from a block in a modern runtime. SAST still finds and reports it as Code only.
- **Not covered:** DOM XSS (lives in JavaScript), vulnerable-dependency reachability (SCA).
- **Keys are ours, and incomplete.** They cover well-known bugs; each app has other open findings no key lists.
- **DAST can be incomplete** on a large app inside its time ceiling; the report says "tested 98 of 276 inputs", and a Code-only issue then means *not proven*, not *tested safe*.

---

## 13. Likely judge questions

**Why not just let an LLM link the findings?**
Because a wrong link is the costliest mistake and an LLM will confidently make one. The correlator is deterministic and explainable: same CWE family, route, selector, parameter. AI only proposes a *test*, and the result must still pass the same evidence checks.

**How do you keep false positives down?**
Context-aware protections in SAST (an escape is checked against *where* the value lands), a control request against every DAST hit, evidence levels that don't trust the scanner's own confidence, and decoys we attack on the running app to prove they're safe. 0 decoys reported on every run.

**What stops the AI from doing something unsafe?**
It can't pick a route, parameter or weakness, can't send arbitrary traffic (the scanner builds every request), is bounded to a handful of calls, sees only redacted source from inside the scan folder, and its output is never trusted without runtime proof. No key means no network call at all.

**Why custom DAST probes instead of ZAP?**
We support ZAP and Nuclei as alternate backends, but a site-wide active scan blew the time budget on DVWA before reaching the relevant endpoints. Our probes run only against discovered injection points, with exact per-point attribution, which is what correlation needs.

**How does it handle apps that hide errors?**
Differential testing: a lone quote fails while a paired quote and a harmless value succeed, repeated to rule out flukes; arithmetic differentials for numeric inputs; identifier differentials for `ORDER BY`.

**Is it only tuned to your benchmark?**
We scored held-out apps on the *first* run before touching the engine and report those numbers, then fixed the misses in general ways. The Python engine's first run on four unseen apps found 77% of the planted bugs (20 of 26) and the PHP holdouts 86–90%; after the general fixes the rows improved, and we say plainly that they're no longer blind.

**Is it safe to run?**
Scope guard on every request and redirect, localhost-only targets enforced in the UI, destructive endpoints skipped by default, denylisted state-changing pages, loopback-bound benchmark containers.

**What did you build vs reuse?**
Own work: the route map, taint interpreter, finding merge, all five DAST probes, the correlator, ranking, the re-test loop and the UI. Open source used: tree-sitter, Semgrep (with our own rules), httpx, BeautifulSoup, FastAPI, React, pytest; optionally ZAP / Nuclei; Groq's API for the optional planner.

---

## 14. Suggested 5-minute demo

1. **Problem (30 s):** two tickets for one bug; show the two raw reports side by side.
2. **One click (60 s):** UI → *Python Shop* → run SAST + DAST. Narrate the three stages and the live log. Total time on screen.
3. **The list (45 s):** ranked findings; Confirmed first; point at CVSS ordering and the 0-noise list.
4. **One Confirmed issue (60 s):** open `/products/search`. Show URL + parameter + payload, file:line + snippet + trace, *why linked*, evidence level `validated`, fix suggestion.
5. **The AI moment (60 s):** switch to the PHP shop, open `/lang.php` (redirect). Show the **AI-assisted** tag, the round-1 miss (`200`), the planner's reason (*"the redirect only occurs when the back parameter contains the string 'forge-shop'"*), the hint `https://{canary}/forge-shop`, the `302` proof, and the line *"the correlator alone decided."* (Planner output varies run to run; keep a finished scan open as the fallback.)
6. **Honesty (30 s):** DVWA *Need review*: 6 candidates narrowed to 2, and *why we refuse to pick*.
7. **Close (15 s):** scoreboard: 95–100% correct links, **0 wrong, 0 decoys**; 716 tests; SARIF + CI gate; PHP and Python.

**Pre-flight checklist:** benchmark containers running and bound to `127.0.0.1`; `.env` has `GROQ_API_KEY`; frontend built (`cd web && npm run build`); start the UI with `web/.venv/bin/python -m web.server`; keep one finished scan open as a fallback.

---

## 15. Run it

**Docker (what judges will do), from the repo root:**

```sh
cp .env.example .env                           # optional: GROQ_API_KEY enables the AI-assisted step
docker compose up -d --build                   # workspace at http://127.0.0.1:8000, UI built inside the image

# the application to scan runs on the judge's machine (its own compose file); its source is mounted read-only at /workspace
echo "TARGET_SOURCE=/path/to/the/application/source" >> .env && docker compose up -d
#   browser: Custom application -> source /workspace, URL http://host.docker.internal:<its port> -> Start scan
docker compose run --rm scan scan --source . --target http://host.docker.internal:8081      # or the same from the command line
```

**Without Docker:** `python -m venv .venv && .venv/bin/pip install -r requirements.txt`, then
`.venv/bin/python -m cyberforge scan --source <dir> --target http://localhost:8081`, and `.venv/bin/python -m web.server` for the UI (built once with `cd web && npm ci && npm run build`).

The full instructions, the cases where the application publishes no port, and the safety rules are in the root `README.md`.
Per-component details: `sast-engine/README.md`, `dast-engine/README.md`, `correlator/README.md`, `common/FORMAT.md`, `web/README.md`.
