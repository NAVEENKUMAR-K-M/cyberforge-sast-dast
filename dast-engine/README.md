# DAST Engine (CyberForge)

Runtime vulnerability scanner for the SAST/DAST/correlation challenge.
Discovers routes, establishes behavioural baselines, runs passive
app-level checks, and delegates exact-attribution active injection
testing to OWASP ZAP (primary) or Nuclei (optional alt), producing a
schema-stable `dast_results.json` for the correlation engine.

## Why ZAP/Nuclei own the active payloads

Correlation scores on exact route + method + parameter + CWE attribution,
not just "found a bug". OWASP ZAP's Alerts API already reports url,
method, param, cweid, and the attack string it used for every finding —
exactly what the schema below needs — so this project drives ZAP (or,
optionally, Nuclei's community DAST templates) rather than re-implementing
SQLi/XSS/CMDi/path-traversal/open-redirect payloads from scratch. Both are
standard, non-destructive scanners appropriate for this authorized,
controlled test environment. Everything else — scope enforcement, auth,
discovery, baselining, the 6 passive/app-level checks, scheduling, dedupe,
the shared schema, and the correlation-facing `verify()` API — is custom
to this project.

## Architecture

```
config.yaml + optional route_map.json (from SAST)
  │
  ├─ core/scope_guard.py      allowlist + denylist + redirect vetting
  ├─ core/auth.py             generic form login (auto CSRF field detection)
  ├─ core/request_manager.py  rate-limited, budget-aware httpx client
  ├─ discovery/crawler.py     links, forms, JS URLs, robots/sitemap, API specs
  ├─ discovery/injection_points.py   route_template derivation + dedupe
  ├─ discovery/baseline.py    per-endpoint baseline (status/length/hash)
  ├─ scanners/passive.py      headers, cookies, CORS, info disclosure, TRACE
  ├─ scanners/stored_marker.py  stored-content persistence probe (marker only)
  ├─ scanners/zap_runner.py   active backend (primary): drives OWASP ZAP
  ├─ scanners/nuclei_runner.py  active backend (optional alt): drives nuclei
  ├─ results/normalizer.py    dedupe, confidence-tier filter, write JSON
  └─ api.py                   verify(cwe, method, route, param) for correlation (bonus B-1)
```

## Running

```bash
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install -r requirements.txt

# Dev target: DVWA + ZAP daemon
docker compose -f docker-compose.dev.yml up -d
# open http://localhost:8080/setup.php once by hand to create the DB

python main.py scan --target http://localhost:8080 --config dvwa.yaml
python eval/score.py output/dvwa_results.json eval/answer_keys/dvwa.json
```

Without a reachable ZAP daemon, pass `--active-backend none` (or `nuclei`
if the `nuclei` binary is on PATH) to still exercise discovery + passive
checks end to end.

## Verification

- `pytest` — scope guard (allowlist/denylist/redirect refusal), finding-id
  stability, route-template derivation, passive checks and the
  stored-marker probe against a tiny Flask fixture app (`tests/fixtures/app.py`).
- Re-running the same scan twice produces identical `finding_id` values
  (FR-6) — verified via `tests/test_models.py` and manually against the
  fixture app.
- Elapsed time, request count and p95 latency are reported in
  `dast_results.json` and surfaced by `eval/score.py` against the 150s
  scan budget (300s overall target including the SAST/correlation side).

## Open-source tools used

- [OWASP ZAP](https://www.zaproxy.org/) — active-scan backend (primary)
- [Nuclei](https://github.com/projectdiscovery/nuclei) — active-scan backend (optional)
- [httpx](https://www.python-httpx.org/), [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/), [Playwright](https://playwright.dev/) (optional DOM-XSS confirmation)
- [DVWA](https://github.com/digininja/DVWA) — local dev target
