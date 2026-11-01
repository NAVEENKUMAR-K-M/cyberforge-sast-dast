We are winning this gang!

## Structure

| Folder | What it is | Start here |
|---|---|---|
| [sast-engine/](sast-engine/) | Static scanner: reads PHP or Python (Flask, FastAPI, spec-first) source, finds bugs and maps URLs to code | [README](sast-engine/README.md) |
| [dast-engine/](dast-engine/) | Dynamic scanner: tests the running app | [README](dast-engine/README.md) |
| [common/](common/) | The one finding format both scanners write, for the correlator to read | [FORMAT.md](common/FORMAT.md) |
| [correlator/](correlator/) | Joins both reports into one issue per bug: Confirmed, Code only or Runtime only | [README](correlator/README.md) |
| [sca/](sca/) | Reachability-aware SCA (bonus): can the app reach a vulnerable library function? Composer apps | [README](sca/README.md) |
| [web/](web/) | Local analyst workspace: findings, source/runtime evidence, and scan coverage | [README](web/README.md) |

## Analyst interface

The [web workspace](web/README.md) runs local scans and opens the combined report. Choose DVWA, OWASP Juice Shop, or one of the bundled benchmark shops (PHP or Python); select SAST and/or DAST; follow progress and logs; inspect findings, source routes, coverage, conflicts, and compare completed scans. It exports JSON, standalone HTML, and SARIF. SAST hints are enabled by default; full route-map expansion is optional because it can consume DAST's budget on larger apps. After installing its dependencies and building the frontend:

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
sast-engine/.venv/bin/python -m pytest sca/tests         # reachability-aware SCA
web/.venv/bin/python -m pytest web/tests                 # the analyst workspace's API (needs pytest, httpx)
(cd web && npm test -- --run)                             # the analyst workspace's UI
```

### Latest run (2026-11-01)

| Suite | Result |
|---|---|
| sast-engine | 349 passed |
| dast-engine | 160 passed, 1 failed |
| correlator | 159 passed |
| common | 16 passed |
| web (API, pytest) | 12 passed |
| web (UI, vitest) | 20 passed |
| **Total** | **716 passed, 1 failed** |

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
