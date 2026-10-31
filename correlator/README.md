# Correlator

Joins the SAST and DAST reports into **one issue per real bug**, labelled by what proved it, ranked, and written out as a page a developer can work from. This covers the PRD's FR-5 (link), FR-6 (merge), FR-7 (label), FR-8 (issue detail) and FR-9 (prioritised list). It reads only the two `*.common.json` files ([common/FORMAT.md](../common/FORMAT.md)) and needs no network.

```sh
pip install -r correlator/requirements.txt
python -m correlator.cli --sast sast-engine/out/shop/findings.common.json \
    --dast dast-engine/output/shop.common.json --out out/issues.json
```

Use `--base-path /app` if the app is served under a prefix. By default it's taken from the DAST target URL. The prefix is removed from runtime routes, and from code routes if SAST added it (`--base-path` in the SAST scan), so either tool, or both, may have used it. A bad input exits with code 2 and says what's wrong.

## How it decides
**One bug, seen several ways, is one issue.**
- **Code side:** open SAST findings with the same CWE family, in the same function, sharing an input name and **fed by the same built value** are one bug. For example, one query used twice. Separately built statements stay separate bugs even with the same input (such as DVWA's MySQL and SQLite branches): each needs its own fix, and a runtime test can't tell which it hit. The value is identified by the last step of the trace before the sink, so sinks with no trace merge as before.
- **Runtime side:** DAST findings with the same CWE family, route, page selector, parameter **and place in the request** are one observation. A query sighting and a body sighting are different requests. They join one issue only by linking to the same code bug.

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
| Only code marked safe fits | A **conflict**. Neither side decides; see below |
| Nothing fits | **Runtime only** |
| Code bug never seen at runtime | **Code only** (hard-coded secrets always are) |

**Conflicts** keep the full evidence of both sides (`evidence.runtime`, `evidence.code`), the suppression reason and the runtime proof level. If the runtime evidence is **validated** (below), the finding is also ranked as a Runtime only issue with `conflict: true` and `conflict_with`, at lower report confidence (`RC:R`), and the record points to it with `issue_id`. Weaker runtime evidence stays only in `conflicts`. Nothing is dropped.

Code-only issues made up only of low-confidence findings are kept with `reportable: false`. Findings SAST marked safe are listed under `suppressed`, never as issues. Every list is sorted and IDs are content hashes, so the same scans always give the same file.

## What the runtime evidence shows
The scanner's technique name and its own confidence tier are not trusted. [evidence.py](evidence.py) reads each finding's recorded payload and response and sets a level. Each issue carries `runtime_verification` with the level and one reason per finding.

| Level | Meaning |
|---|---|
| `validated` | The recorded evidence shows the weakness itself |
| `partial` | The input reached the target, but exploitation isn't shown |
| `unchecked` | There is runtime evidence, but no check for this weakness |
| `none` | Not seen at runtime |

| Weakness | `validated` needs | Otherwise `partial` |
|---|---|---|
| Command injection, SQL injection | A computed result (the sum the payload asked for) found in the response and not in the payload, or two delayed repeats clear of the baseline | A changed response or a database error |
| Path traversal | System file content in the response that the payload doesn't contain | An echo, or no recognisable content in the recorded excerpt |
| Open redirect | A server redirect (3xx) to a destination outside the app that the test chose | A redirect only in the page, or a destination inside the app |
| XSS | A script-running payload reflected unchanged | A marker reflected where it wouldn't run, or not in the recorded excerpt |

**Confirmed still means found in both.** Its `runtime_verification` says how strongly the runtime side was shown, and `partial` lowers the exploit metric (`E:P`). The recorded response excerpt is short, so evidence that was cut off counts as `partial`.

## Re-testing what has no runtime proof
`--investigate` closes the loop for Code only issues that look real (open, not low-confidence, with a route and a named input, for a weakness the DAST engine can re-test) and for runtime bugs several code bugs fit:

```sh
python -m correlator.cli --sast ... --dast ... --out out/issues.json --investigate \
    --dast-python dast-engine/.venv/bin/python --dast-config dast-engine/config.yaml
```

**Correlate → investigate one case → run a supported test → take the result back into correlation → stop.** Each case gets at most two tests ([loop.py](loop.py)):

1. **Round 1** is the re-test the code itself describes: the route, parameter, place in the request and method SAST reported, run with the DAST engine's `main.py verify`.
2. **Round 2** is a test a *planner* proposes after seeing round 1's actual requests and responses. A planner may add other fields the request needs and a payload hint. It cannot change the route, parameter or weakness, repeat a request, or go past the limits in `check_plan`. Without a planner a case stops after round 1. Planner = `planner(case, history)` passed to `run_loop`; no model client is built in yet.

The planner never makes a link. A re-test that reproduces comes back as a new DAST finding, which is matched by the same rules and judged by the same evidence checks as every other finding. If it doesn't link, the case says so. If the evidence is only `partial`, the case stays open for round 2.

**Every case ends with an outcome and a reason**, kept under `investigations` with each round's plan, the requests actually sent, the result, the evidence level and what it did to the issue (`Code only → Confirmed`):

| Outcome | Meaning |
|---|---|
| `validated` | A test showed the weakness itself |
| `unresolved` | Not reproduced, or only partial evidence, when the rounds ran out. **Not safe**, just not proven |
| `blocked` | No request was sent: the route is out of scope or denylisted |
| `no supported test` | The re-test can't be built, such as a stored bug (needs a write, then a read), or runtime bugs that several code bugs fit equally |

It writes `<out>.dast.common.json` next to the result, with the new findings added.

**The planner** ([planner.py](planner.py)) is opt-in: `--planner groq --source-root <folder SAST scanned>`, with `GROQ_API_KEY` in `.env`. Only the standard library is used.
- **What leaves the machine:** the handler file the finding names, plus up to two files from its trace (numbered, 6,000 characters each, with password-like literals removed), the finding's snippet and trace, and a sample of what round 1 sent and got back. Nothing is sent unless you pass `--planner`, and only files inside `--source-root` are read.
- **What it can answer:** extra fields the request needs, and for open redirect, path traversal and XSS a payload hint. It may also say there is nothing useful to try. `check_plan` limits everything else.
- **Failure is safe:** with no key, no credit or no network the case just stops after round 1, with the reason recorded (for example `HTTP 429 credit_balance_exhausted`).
- **Audit:** each round's plan keeps the model, a hash of the prompt, the files sent, the raw reply and the token counts.
- **Provider and model:** `--planner groq` (or `openai`), `--planner-model` (default `openai/gpt-oss-120b`). It beat `openai/gpt-oss-20b` in two live runs on the shop, which is thin evidence. Keys go in `.env` (see `.env.example`); extra keys `GROQ_API_KEY_2`, `_3`, ... are used in turn and ride out rate limits.
- **Limits:** at most one model call per unresolved case in round 2, so no more than `--max-cases` (default 10) per run. A case is skipped without a call when there is no source to read or nothing the planner could change.

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
| Runtime evidence `validated` | `E:F` |
| Runtime evidence `partial` or `unchecked` | `E:P` |
| Found by code analysis only | `E:U` |
| Found in both code and runtime, or `validated` at runtime | `RC:C` |
| Runtime evidence for code that was marked safe (a conflict) | `RC:R` |
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
- **`conflicts`, `suppressed`, `diagnostics`, `stats`.** `stats.runtime_coverage` copies DAST's coverage numbers. When the runtime scan didn't test everything, a diagnostic says a Code only issue means no proof was found, not that it was tested and found safe.

## Results
```sh
python correlator/eval/score_links.py out/issues.json sast-engine/eval/keys/shop.json
```

| App | Confirmed | Correct links | Wrong links | Decoys reported |
|---|---|---|---|---|
| Benchmark shop (our own app) | 14 (7 validated, 7 partial) | 14 of 22 (64%) | 0 | 0 of 13 |
| DVWA (tuned DAST run) | 4 (2 validated, 2 partial) | – | 0 seen | – |

- **The shop's 8 unlinked pairs** are bugs DAST didn't prove, so the link rate can't beat DAST's own recall.
- **DVWA's 4 ambiguous bugs** are its difficulty-level variants (the same parameter in low, medium and high files) and, for SQL injection, two separately built queries in one file. Nothing in either report says which one ran, so linking one would be a guess.
- **The partial Confirmed issues** are 5 SQL injections proven only by a database error, and 2 reflections of a marker that wouldn't run. They stay Confirmed, flagged `partial`, until a stronger test is recorded.

## Tests
```sh
python -m pytest correlator/tests
```
