# Common finding format (FR-3)

SAST and DAST report findings in **one shape**, with a CWE number for the type. Both scanners keep their own detailed native output and additionally write a `*.common.json` in this format. A correlator needs to read only the common files.

| Scanner | Native output (unchanged) | Common output |
|---|---|---|
| SAST (`sast-engine`) | `findings.json`, `routes.json` | `findings.common.json` (same folder) |
| DAST (`dast-engine`) | `<output>.json` | `<output>.common.json` (same folder) |

The machine-readable definition is [finding.schema.json](finding.schema.json). Check any file with:

```sh
pip install jsonschema
python common/validate.py sast-engine/out/shop/findings.common.json dast-engine/output/dvwa_results.common.json
```

**SQL injection is `CWE-89` on both sides.** The same applies to XSS `CWE-79`, command injection `CWE-78`, path traversal `CWE-22` and open redirect `CWE-601`.

## File

```jsonc
{ "schema_version": "1.0", "source": "sast" | "dast", "tool": "...", "target": "...", "stats": {...}, "findings": [ ... ] }
```

## Finding

| Field | Meaning |
|---|---|
| `id` | `sast:<fingerprint>` or `dast:<finding_id>`. Stable across rescans, so a second scan makes no copies (FR-6). The prefix keeps the two sources from colliding. |
| `source`, `tool` | `sast` or `dast`; the producing tool (`cyberforge-sast`, `cyberforge-dast`, or `owasp-zap`/`nuclei` when DAST used them) |
| `cwe` | The exact CWE this scanner assigned, e.g. `CWE-209` |
| `cwe_family` | The normalised CWE. **Compare this one**, because scanners label one bug differently (see [cwe_families.json](cwe_families.json): `CWE-98` is the `CWE-22` family, `CWE-209` is `CWE-489`). A CWE not in the table is its own family. |
| `title`, `severity` | `severity` is `critical`, `high`, `medium`, `low` or `info` |
| `confidence` | `high`, `medium` or `low` |
| `status` | `open`, or `suppressed` when SAST found the code protected or unreachable. DAST findings are always `open`. |
| `scope` | `endpoint` (tied to a route), `app` (whole app, e.g. a missing header) or `code` (SAST, no route reaches it) |
| `params` | Inputs involved: `[{name, location, value?}]`. `location` is `query`, `body`, `json`, `path`, `header`, `cookie`, `session`, `file`, `any` (GET or POST) or `unknown`. SAST can list several; DAST lists one. |
| `routes` | `[{path, aliases, selector, methods}]`. `path` has no host or query string. `aliases` are other URLs for the same code (`/cart/` for `/cart/index.php`), so match a DAST path against `path` **or** `aliases`. `selector` is the query value that picks a page (`page=x.php`) or `null`. Empty for `app` and `code` scope. |
| `code` | SAST only, else `null`: `file`, `line`, `snippet`, `function`, `sink`, `trace`, `conditions`, `stored_flow`, `suppression_reason`, `engines` |
| `runtime` | DAST only, else `null`: `method`, `url`, `payload`, `technique`, `verification`, `evidence` |

## How each side fills it in

| Common field | From DAST | From SAST |
|---|---|---|
| `id` | `dast:` + `finding_id` | `sast:` + `fingerprint` |
| `confidence` | `confirmed`→`high`, `firm`→`medium`, `tentative`→`low`. The native tier is kept in `runtime.verification`. | unchanged |
| `cwe_family` | looked up in `cwe_families.json` | the engine's own family, same table |
| `params` | the single tested parameter | `source_params` |
| `routes` | the route template, `methods: [method]`, no aliases | the finding's routes, with `aliases` from the route map |
| `scope` | `endpoint` or `app` | `endpoint` if any route reaches it, else `code` |

## Matching a pair

Match on `cwe_family`, then route (`path` or an alias), then parameter `name`. The `common/examples/` folder holds one real SQL injection found by each side in the same app.
