We are winning this gang!

## Structure

| Folder | What it is | Start here |
|---|---|---|
| [sast-engine/](sast-engine/) | Static scanner: reads PHP source, finds bugs and maps URLs to code | [README](sast-engine/README.md) |
| [dast-engine/](dast-engine/) | Dynamic scanner: tests the running app | [README](dast-engine/README.md) |
| [common/](common/) | The one finding format both scanners write, for the correlator to read | [FORMAT.md](common/FORMAT.md) |
| [correlator/](correlator/) | Joins both reports into one issue per bug: Confirmed, Code only or Runtime only | [README](correlator/README.md) |
| [web/](web/) | Local analyst workspace: findings, source/runtime evidence, and scan coverage | [README](web/README.md) |

## Analyst interface

The [web workspace](web/README.md) runs local scans and opens the combined report. Choose DVWA, OWASP Juice Shop, or the bundled benchmark shop; select SAST and/or DAST; follow progress and logs; inspect findings, source routes, coverage, conflicts, and compare completed scans. It exports JSON, standalone HTML, and SARIF. SAST hints are enabled by default; full route-map expansion is optional because it can consume DAST's budget on larger apps. After installing its dependencies and building the frontend:

```sh
web/.venv/bin/python -m web.server --example
```

Open **http://127.0.0.1:8000**. The selected app must already be running locally. The UI limits scan targets to `localhost` and `127.0.0.1`, and shows the full SAST + DAST + correlation elapsed time. SAST currently supports PHP; Juice Shop runs DAST only.

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

## Tests

Run these from the repo root:

```sh
(cd sast-engine && .venv/bin/python -m pytest)        # SAST
(cd dast-engine && .venv/bin/python -m pytest)        # DAST
sast-engine/.venv/bin/python -m pytest common/tests   # the shared format
sast-engine/.venv/bin/python -m pytest correlator/tests  # the correlator
```
