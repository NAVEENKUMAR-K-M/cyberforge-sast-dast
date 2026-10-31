# Correlator

Joins the SAST and DAST reports into **one issue per real bug**, labelled by what proved it. This covers the PRD's FR-5 (link), FR-6 (merge) and FR-7 (label). It reads only the two `*.common.json` files ([common/FORMAT.md](../common/FORMAT.md)) and needs no network.

```sh
pip install -r correlator/requirements.txt
python -m correlator.cli --sast sast-engine/out/shop/findings.common.json \
    --dast dast-engine/output/shop.common.json --out out/issues.json
```

Use `--base-path /app` if the app is served under a prefix. By default it's taken from the DAST target URL. A bad input exits with code 2 and says what's wrong.

## How it decides
**One bug, seen several ways, is one issue.**
- **Code side:** open SAST findings with the same CWE family, in the same function, sharing an input name, are one bug. For example, the same query run in two branches.
- **Runtime side:** DAST findings with the same CWE family, route, page selector and parameter are one bug. For example, GET in the query and POST in the body.

**A runtime bug links to a code bug only when all of these hold:**
- the same CWE family;
- the DAST route equals the code's route, one of its aliases (`/shop/` for `/shop/index.php`) or a `{name}` template;
- the page selector, if the code has one (`action=view`), is the one tested;
- the same parameter, in a compatible place (`any` means query or body);
- the code finding is open, not marked safe.

Stored bugs can also match on the route where the value is written.

| Situation | Result |
|---|---|
| Exactly one code bug fits | Linked. One **Confirmed** issue, holding all the evidence |
| Several different code bugs fit | Not linked. The runtime bug is **Runtime only**, `ambiguous`, with `candidates` |
| Only code marked safe fits | Not an issue. Listed under `conflicts` for a person to decide |
| Nothing fits | **Runtime only** |
| Code bug never seen at runtime | **Code only** (hard-coded secrets always are) |

Code-only issues made up only of low-confidence findings are kept with `reportable: false`. Findings SAST marked safe are listed under `suppressed`, never as issues. Every list is sorted and IDs are content hashes, so the same scans always give the same file.

## Output
[issues.schema.json](issues.schema.json) defines the file:
- **`issues`:** label, CWE, highest severity, merged routes and parameters, and full copies of every member finding under `evidence`.
- **`links`:** what matched and how (exact route, alias, template, or stored-write).
- **`conflicts`, `suppressed`, `diagnostics`, `stats`.**

## Results
```sh
python correlator/eval/score_links.py out/issues.json sast-engine/eval/keys/shop.json
```

| App | Confirmed | Correct links | Wrong links | Decoys reported |
|---|---|---|---|---|
| Benchmark shop (our own app) | 14 | 14 of 22 (64%) | 0 | 0 of 13 |
| DVWA (tuned DAST run) | 5 | – | 0 seen | – |

- **The shop's 8 unlinked pairs** are bugs DAST didn't prove, so the link rate can't beat DAST's own recall.
- **DVWA's 3 ambiguous bugs** are its difficulty-level variants: the same parameter in low, medium and high files. Nothing in either report says which level ran, so linking one would be a guess.

## Tests
```sh
python -m pytest correlator/tests
```
