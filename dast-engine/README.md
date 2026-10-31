# DAST Engine (CyberForge)

Runtime vulnerability scanner for the SAST/DAST/correlation challenge.
Discovers routes, establishes behavioural baselines, runs passive
app-level checks, and runs custom Python probes for exact-attribution
active injection testing (SQLi, XSS, command injection, path traversal,
open redirect), producing a schema-stable `dast_results.json` for the
correlation engine.

## Active detection: custom Python probes

Each of the 5 target CWEs has its own probe (`scanners/probes/`) that owns
its payloads, its own confirmation logic, and its own confidence grading.
Detection techniques: error-based + boolean-based (+ time-based as a
hinted-only fallback) for SQLi, verbatim-reflection context classification
for XSS, a computed-marker (not a fixed string) for command injection,
known-file-signature matching for path traversal, and canary-host
netloc matching for open redirect. A shared `verification against a
clean control request` check (`scanners/probes/util.py::is_clean_request_noise`)
guards every probe against false positives from app content that merely
*looks* like a hit (confirmed necessary in testing — see below).

OWASP ZAP (`scanners/zap_runner.py`) and Nuclei (`scanners/nuclei_runner.py`)
remain available as alternate `active_backend` options for comparison, but
aren't the default: driving an external scanner's full site-wide active
scan was found, in testing against DVWA, to blow the 150s budget before
even finishing the relevant endpoints. The custom probes run directly
against only the discovered injection points, finishing comfortably
inside budget with exact per-point attribution.

### False positives found and fixed during testing (against live DVWA)

These were real, not hypothetical — each is covered by a regression test:

- A DB-exception **class name** bare in a signature list matched DVWA's
  own help text explaining a PHP version change, not an actual error.
  Fix: require the specific "Uncaught X" / "X: message" shape a real
  stack trace has — and still verify against a clean control request
  before trusting any error-signature match.
- A generic word ("localhost") used as a path-traversal confirmation
  signature matched ordinary page content unrelated to any file read.
- A computed CMDi marker coincidentally matched a number already present
  on a static, input-independent page.
- A quote-only XSS payload reflected into plain body *text* (not an
  attribute or script context) was treated as exploitable; quotes are
  inert there — only a surviving angle bracket actually opens a new tag.
- The XSS attribute-context regex expected the enclosing quote to sit
  *before* the match, but our payload templates include that quote as
  their own leading character, so it was never actually sitting there —
  attribute-context reflections were never being classified correctly.
- `build_request()`'s query-param branch pulled a GET form's *other*
  fields (e.g. a "Submit" button) from nowhere, since a crawled
  `<form method="GET">`'s `action` attribute never embeds them — DVWA's
  SQLi page gates its whole query behind `isset($_GET['Submit'])`, so the
  vulnerable code path never even ran until this was fixed.
- The spider/active-scan exclude list (ZAP backend) used
  `core.exclude_from_proxy`, which only affects *proxied* traffic, not the
  spider's or scanner's own requests — it hit `logout.php` (killing the
  session), then auto-submitted a discovered GET form on `setup.php`
  (**resetting the database**) and `security.php` (resetting the
  difficulty level), all mid-scan.
- `login()` checked `success_indicator` against the login POST's own
  redirect response, which is reliably empty-bodied — an absent failure
  string in an empty body "passed" even on a rejected login.
- DVWA's CSRF demo page (`vulnerabilities/csrf/`) is a GET-based
  password-change endpoint; a spider that auto-submits discovered GET
  forms with placeholder values genuinely changed the logged-in account's
  password as a side effect of crawling. Excluded via denylist.

## Architecture

```
config.yaml + optional route_map.json (from SAST)
  │
  ├─ core/scope_guard.py      allowlist + denylist + redirect vetting
  ├─ core/auth.py             generic form login (auto CSRF field detection)
  │                           + optional post_login actions (e.g. pinning
  │                             a target's difficulty/config level)
  ├─ core/request_manager.py  rate-limited, budget-aware httpx client
  ├─ discovery/crawler.py     links, forms, JS URLs, robots/sitemap, API specs
  ├─ discovery/injection_points.py   route_template derivation + dedupe
  ├─ discovery/baseline.py    per-endpoint baseline (status/length/hash)
  ├─ scanners/passive.py      headers, cookies, CORS, info disclosure, TRACE
  ├─ scanners/stored_marker.py  stored-content persistence probe (marker only)
  ├─ scanners/probes/          sqli.py, xss.py, cmdi.py, path_traversal.py,
  │                            open_redirect.py -- active backend (default)
  ├─ scanners/probe_runner.py  runs every probe against every injection point
  ├─ scanners/zap_runner.py    active backend (optional alt): drives OWASP ZAP
  ├─ scanners/nuclei_runner.py active backend (optional alt): drives nuclei
  ├─ results/normalizer.py    dedupe, confidence-tier filter, write JSON
  └─ api.py                   verify(cwe, method, route, param) for correlation (bonus B-1)
```

## Running

```bash
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install -r requirements.txt

# Dev target: DVWA (+ its MariaDB backend)
docker compose -f docker-compose.dev.yml up -d
# open http://localhost:8080/setup.php once by hand to create the DB

python main.py scan --target http://localhost:8080 --config dvwa.yaml
python eval/score.py output/dvwa_results.json eval/answer_keys/dvwa.json
```

`dvwa.yaml`'s `auth.post_login` pins the difficulty level to `low` right
after login (DVWA stores it per-session, so a fresh login always resets
it) — this is config-driven, not hardcoded into `auth.py`, so any target
needing an equivalent one-time setup step after login can use the same
mechanism.

To compare against the ZAP backend instead: `--active-backend zap` (needs
`docker compose -f docker-compose.dev.yml up -d zap` and `pip install
python-owasp-zap-v2.4`). Pass `--active-backend none` to exercise
discovery + passive checks alone.

## Verification

- `pytest` (57 tests) — scope guard, auth (including two real bugs found
  and fixed: an empty-redirect-body false positive and a non-idempotent
  ZAP exclude list), finding-id stability (including the app-scope CWE
  collision above), route-template derivation, passive checks, the
  stored-marker probe, and each of the 5 probes against a tiny Flask
  fixture with one vulnerable route and one safe decoy per CWE
  (`tests/fixtures/vuln_app.py`) — plus a dedicated regression test for
  every false positive listed above.
- Verified live against DVWA (security=low): **100% detection, 0% false
  alarms** against `eval/answer_keys/dvwa.json`'s 11-item expected set,
  in ~127s of a 150s budget (well under the PRD's 5-minute total).
- Re-running the same scan twice produces identical `finding_id` values
  (FR-6).

## Open-source tools used

- [DVWA](https://github.com/digininja/DVWA) — local dev target
- [httpx](https://www.python-httpx.org/), [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) — crawling and requests
- [OWASP ZAP](https://www.zaproxy.org/) / [Nuclei](https://github.com/projectdiscovery/nuclei) — optional alternate active backends
- [Playwright](https://playwright.dev/) — optional DOM-XSS confirmation (off by default)
