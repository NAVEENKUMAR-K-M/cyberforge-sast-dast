# SAST output format

For the DAST team and whoever builds the correlator. The machine-readable version is [sast-output.schema.json](sast-output.schema.json), and a test checks real scan output against it.

A scan writes two files: `findings.json` and `routes.json`.

## Fields to agree on with DAST

These need to mean the same thing on both sides, or findings can't be compared.

| Field | Meaning | Example |
|---|---|---|
| `cwe` | The exact CWE this scanner assigned | `CWE-98` |
| `cwe_family` | The normalised CWE. **Compare this one**, because scanners label one bug differently | `CWE-22` |
| `severity` | `critical`, `high`, `medium` or `low` | `critical` |
| `confidence` | `high`, `medium` or `low` | `high` |
| route `path` | URL path, without host or query string | `/vulnerabilities/sqli/index.php` |
| route `selector` | The query value that picks this page, if any | `page=dns-lookup.php` |
| route `methods` | HTTP methods | `["GET", "POST"]` |
| parameter `location` | `query`, `body`, `json`, `any` (GET or POST), `cookie`, `header`, `path`, `file` or `session` | `body` |

CWE families are listed in [sast/core/cwe.py](../sast/core/cwe.py). Path parameters use the form the app declares, such as `/orders/{id}`, so DAST's concrete `/orders/7` has to be matched against that pattern.

## Finding: SAST-only fields

| Field | Meaning |
|---|---|
| `file`, `line`, `snippet`, `function` | Where to fix the bug. For XSS and for flows that cross files, this is where the input joined the output, not the shared `echo` or query helper |
| `sink` | The dangerous call the input reaches |
| `source_params` | Every input that reaches this sink. **There can be several**: one query can use two parameters and still be one bug |
| `trace` | Each step from source to sink, across files |
| `routes` | Every route that reaches this code. A shared helper lists them all |
| `status` | `open`, or `suppressed` when the code is protected or unreachable |
| `suppression_reason` | Why it's suppressed, in plain English |
| `conditions` | When this code runs, for pages that pick a file at runtime, such as `$vulnerabilityFile == 'low.php'` |
| `stored_flow` | For stored bugs: the table or session key, plus where it's written and read |
| `fingerprint` | Stable ID with no line numbers, so it survives edits and rescans |
| `engines` | Which analysis found it: `taint`, `semgrep` or `config` (secrets in configuration files, whose values are masked in `snippet`) |

## Route: extras DAST can use

A scan also writes `hints.json`: each exact route, parameter and CWE the code suggests is worth a closer look, for DAST's `--hints`. Low-confidence findings are left out.

`routes.json` lists every URL the code can serve, including pages no link points to. DAST can use it as a target list instead of crawling.

| Field | Meaning |
|---|---|
| `aliases` | Other URLs for the same code, such as `/shop/` for `/shop/index.php` |
| `params` | Every input the route's code reads |
| `required_params` | Inputs the code checks for before doing anything, such as `Submit`. Without these a request never reaches the bug. A `value` means the code compares against that exact value |
| `form_fields` | Forms found in the page, with method, action and field names |
| `handler` | The file, function and lines that handle the route |

## Advice for the correlator

- **Suppressed findings are kept on purpose,** so a disagreement between the engines is visible. If DAST reports something SAST marked safe, don't let either side win automatically: flag it for review with both sides' evidence. Either engine can be the wrong one. On the benchmark shop, DAST once reported XSS on a page served as `text/plain`, which SAST had correctly marked safe. Leave suppressed findings out of the reported list otherwise, so decoys don't count as false alarms.
- **Show low-confidence findings only if DAST confirms them.** In a sample checked by hand, high confidence was right 10 times out of 10, medium 4 of 7, and low 0 of 7. The sample is small, but the gap is wide.
- **Match on `cwe_family`, then route, then parameter.** Two bugs on one page with the same CWE are told apart by parameter.
- **`selector` matters.** On `/index.php?page=a.php` and `/index.php?page=b.php`, the path alone says nothing.
- **Stored bugs have two routes.** DAST injects at `stored_flow.write_routes` and sees the result at `routes`, so a stored finding can match on either.
- **`any` matches both.** A `location` of `any` means `$_REQUEST`, so it matches a DAST finding in the query or the body.
