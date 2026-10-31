# CyberForge SAST engine

Static analysis for PHP web apps, built for the CyberForge SAST and DAST correlation challenge. It reads source code and reports where user input reaches something dangerous, along with the URL that triggers it, so each finding can later be linked to a runtime proof.

This folder holds the SAST side. The DAST engine lives in `../dast-engine`, and it and the correlator connect to this engine through the [output format](docs/finding-format.md).

## Quick start

Needs Python 3.10 or newer. Run every command in this README from this folder.

```sh
cd sast-engine
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

.venv/bin/python -m sast.cli scan benchmarks/shop --out out/shop
```

This writes `out/shop/findings.json` and `out/shop/routes.json`, and prints a summary. Scanning never contacts a running app and needs no network.

| Option | Use |
|---|---|
| `--web-root public` | Set the web root, if detection gets it wrong |
| `--base-path /dvwa` | Add a prefix if the app is served under one |
| `--exclude name` | Skip a folder; can be repeated |
| `--sarif` | Also write `findings.sarif` |
| `--no-semgrep` | Skip the pattern rules |

## What it finds

| Type | CWE | How |
|---|---|---|
| SQL injection | 89 | Taint tracking |
| Cross-site scripting, including stored | 79 | Taint tracking |
| Command injection | 78 | Taint tracking |
| Path traversal and file inclusion | 22 | Taint tracking |
| Open redirect | 601 | Taint tracking |
| Unsafe deserialization, code injection | 502, 94 | Taint tracking |
| Hard-coded secrets | 798 | Pattern rules |
| Weak password hashes | 328 | Both |
| Predictable tokens, debug settings | 338, 209, 200 | Pattern rules |

## How it works

1. **Parse** every PHP file with tree-sitter.
2. **Build the route map:** which URLs exist and what code runs for each. It handles plain files, front controllers such as `index.php?page=x.php`, `switch` and path-based dispatch, and routes declared in code, such as Laravel and Slim.
3. **Run each entry point abstractly**, following includes with their shared variables, inlining function and method calls, and tracking both taint and possible string values. That's how it resolves `include "source/{$file}"` after a `switch`, and how it finds a bug where one file builds `$html` and another echoes it.
4. **Check protections against context.** `htmlspecialchars` is safe in HTML text but not in an unquoted attribute. `mysqli_real_escape_string` is safe inside quotes but not around an unquoted number. Filters built on `str_replace` don't count.
5. **Track stored flows** through database columns and the session, so a value written on one page and shown on another is linked, with the right parameter.
6. **Run the pattern rules** for bugs that don't need taint tracking.
7. **Merge into findings**, each with a fingerprint that has no line numbers, so edits and rescans don't create copies.

Protected or unreachable code is kept and marked `suppressed` with a reason, rather than dropped.

## Accuracy

Mitigata provides no test app or answer key, so we made our own keys.

```sh
benchmarks/fetch.sh            # downloads the benchmark apps at pinned commits
.venv/bin/python eval/run_all.py
```

| App | Role | Bugs found | Pairs with right route and parameter | Decoys reported | Time |
|---|---|---|---|---|---|
| `benchmarks/shop` | Our own, verified at runtime | 32/32 | 22/22 | 0/13 | 1.1s |
| DVWA | Development | 18/18 | 18/18 | 0/10 | 1.7s |
| Mutillidae | Development | 20/20 | 17/17 | none labelled | about 15s |
| XVWA | Holdout | 10/10 | 9/9 | 0/2 | 1.1s |
| bWAPP | Holdout | 14/14 | 11/11 | 0/2 | 4.4s |

**Read these with care.** The best estimate for an unseen app is the first run on the holdout apps, before any fixes:

| Holdout, first run | Bugs found | Pairs with right route and parameter | Decoys reported |
|---|---|---|---|
| XVWA | 9/10 (90%) | 8/9 | 0/2 |
| bWAPP | 12/14 (86%) | 11/11 | 0/2 |

The misses from that run were fixed in general ways, so the 100% rows above are no longer blind tests. Other limits:

- We wrote the keys and they aren't complete. They cover well-known bugs, and each app has many other open findings that no key lists.
- We wrote the shop too, so its scores are a best case. `eval/verify_shop.py` does prove its key is true: it exploits every bug and attacks 8 of the 13 decoys on the running app.
- The external apps have few labelled decoys, so the false alarm rate rests mostly on the shop and DVWA.

**Precision**, from a random sample of 24 findings outside the keys on the holdout apps, each checked by hand against the code:

| Confidence | Real bugs |
|---|---|
| High | 10 of 10 |
| Medium | 4 of 7 |
| Low | 0 of 7 |

The sample is small, but confidence clearly separates real findings from weak ones. See the [advice for the correlator](docs/finding-format.md#advice-for-the-correlator).

## Known limits

- **PHP only.** Language-specific code sits behind `LanguageAdapter` in [sast/core/language.py](sast/core/language.py), so others can be added.
- **Framework support is only tested on small examples.** Laravel and Slim-style routes pass tests on hand-written fixtures, but haven't been run on a real Laravel app. Plain PHP is what the benchmarks cover.
- **DOM XSS isn't covered**, since it lives in JavaScript.
- **Dynamic features can hide flows:** `$$var`, and callbacks passed as variables.
- **Third-party code inside the app folder is scanned as app code.** `vendor`, `node_modules`, `tests` and `docs` are skipped by default; use `--exclude` for others.
- **Hard-coded secrets rely on names and known formats**, so a secret in an oddly named variable can be missed.

## Benchmark shop

`benchmarks/shop` is a deliberately vulnerable PHP shop of 34 pages. Its answer key is `eval/keys/shop.json`. The DAST team can scan it too.

```sh
docker compose -f benchmarks/shop/docker-compose.yml up -d --build
.venv/bin/python eval/verify_shop.py
docker compose -f benchmarks/shop/docker-compose.yml down
```

It listens on `127.0.0.1:8088` only. Never expose it to a network.

## Tests

```sh
.venv/bin/python -m pytest
```

## Open-source components

| Component | Used for |
|---|---|
| [tree-sitter](https://github.com/tree-sitter/py-tree-sitter) and [tree-sitter-php](https://github.com/tree-sitter/tree-sitter-php) | Parsing PHP |
| [Semgrep](https://github.com/semgrep/semgrep) | Running the pattern rules. The rules in [sast/rules/php.yml](sast/rules/php.yml) are our own |
| [pytest](https://github.com/pytest-dev/pytest) and [jsonschema](https://github.com/python-jsonschema/jsonschema) | Tests |

Benchmark apps, downloaded at evaluation time and not part of this repo: [DVWA](https://github.com/digininja/DVWA), [Mutillidae](https://github.com/webpwnized/mutillidae), [bWAPP](https://github.com/raesene/bWAPP), [XVWA](https://github.com/s4n7h0/xvwa).

The route map, taint interpreter and finding merge are our own work.
