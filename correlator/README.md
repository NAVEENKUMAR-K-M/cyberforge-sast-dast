# Correlator

Joins the SAST and DAST reports into **one issue per real bug**, labelled by what proved it, ranked, and written out as a page a developer can work from. This covers the PRD's FR-5 (link), FR-6 (merge), FR-7 (label), FR-8 (issue detail) and FR-9 (prioritised list). It reads only the two `*.common.json` files ([common/FORMAT.md](../common/FORMAT.md)) and needs no network.

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

## Order (FR-9)
Confirmed issues come first, then the rest by **CVSS v3.0 Temporal score**, with ties broken by Base score. Low-confidence issues held back from the report come last. [cvss.py](cvss.py) implements the equations in the [FIRST v3.0 specification](https://www.first.org/cvss/v3.0/specification-document), and the tests check them against published scores.

Each issue gets a full vector, such as `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RC:C`. Every choice is listed in `risk_factors`.

**Base metrics.** These start from a baseline for the weakness ([rank.py](rank.py)), similar to how NVD usually scores it in a web app:
- SQL, command and code injection, deserialization and hard-coded secrets: **9.8**.
- Path traversal: **7.5**.
- XSS and open redirect: **6.1**.
- Weak hashes and predictable randomness: **5.9**.
- Information disclosure: **5.3**.
- Missing headers: **4.3**.
- Cookie flags: **3.1**.

A weakness without a baseline falls back to the scanner's severity. Our evidence changes the baseline in two places:
- **No known URL** reaches a request-driven bug: `AV:L`.
- **XSS or a redirect through a header or cookie**, which another site can't set for its victim: `AC:H`.

**Temporal metrics.** These record what the scans proved:

| Evidence | Metrics |
|---|---|
| A runtime test exploited it | `E:F` |
| A runtime test showed it but didn't fully exploit it (such as reflected XSS) | `E:P` |
| Found by code analysis only | `E:U` |
| Found in both code and runtime, or confirmed by a runtime test | `RC:C` |
| One scanner, reasonable evidence | `RC:R` |
| Low-confidence code analysis | `RC:U` |

On the shop, a Confirmed SQL injection scores 9.6 (base 9.8). The same bug seen only in code scores 8.6, and a Code only weak hash 5.2. The issue ID breaks remaining ties, so the order is the same on every run.

**Not scored:** Privileges Required is always `N`, since neither report says whether a login was needed. Remediation Level is left undefined.

## The page (FR-8)
Next to `issues.json`, the CLI writes `issues.html`: one self-contained page, with no scripts. It has the ranked list, then a section per issue showing:
- **Where to look:** the URL and parameter, each runtime test's method, URL, payload and technique, and the file, line and code snippet;
- **What it is:** the CWE, the CVSS v3.0 scores and vector, and why each metric was chosen;
- **Why:** why the runtime and code findings were linked, and how the input reaches the code.

Every value is HTML-escaped, since payloads and snippets are attack strings.

## Output
[issues.schema.json](issues.schema.json) defines the file:
- **`issues`:** in ranked order, with `rank`, label, CWE, highest scanner severity, `cvss` (vector, base and temporal scores, rating), `risk_score` (the temporal score) and `risk_factors`, merged routes and parameters, and full copies of every member finding under `evidence`.
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
