# Reachability-aware SCA

Reports whether the app can actually **reach a vulnerable library function**, not just that an affected version is installed. This is the PRD's bonus note. It covers Composer (PHP) apps. Its results are kept apart from the SAST–DAST issues: they never enter linking, labels or the issue ranking.

```sh
sast-engine/.venv/bin/python -m sca.cli scan path/to/app --routes sast-engine/out/app/routes.json --out out/sca
```

| Option | Use |
|---|---|
| `--routes` | SAST's `routes.json`. Its handlers are the entry points. Without it, every app file with top-level code is one |
| `--deps-source` | The dependency source to analyse. Default: `<app>/vendor` |
| `--lock` | `composer.lock`, if it isn't in the app folder |
| `--cache-dir`, `--offline` | Lookups are cached (default `~/.cache/cyberforge-sca`). `--offline` reads only the cache |

It writes `sca.json` and `sbom.cdx.json` (CycloneDX 1.5). Pass `sca.json` to the correlator with `--sca` to add a **Dependencies** section to `issues.json` and the issue page.

Nothing from the app's source leaves the machine. The lookups send package names, versions and advisory IDs. `GITHUB_TOKEN` in `.env` is optional; it only raises GitHub's rate limit.

## How it decides

1. **Inventory.** Reads `composer.lock`: packages, exact versions, `require` edges (through `replace` and `provide`), and autoload rules. It stores the dependency graph and one shortest path from the root per package.
2. **Dependency source.** It uses a supplied `vendor/` tree or folder, never downloads one and never runs its code.
   - **Identity:** what the lock and Composer's `installed.json` say. A matching install record doesn't prove the files are unmodified.
   - **Integrity:** whether the files were checked against a checksum. They aren't, and the report says so.
3. **Advisories.**
   - OSV's batch query, then each returned ID's full record, then records merged by alias.
   - Each advisory is enriched with the GHSA record (`vulnerable_functions` and the published CVSS score), EPSS (FIRST) and KEV (CISA).
   - Each enrichment has its own availability. An unavailable one says `unavailable` and changes nothing else.
   - A query with no matches reads "no known advisories returned by OSV at \<time\>", which is not a clean bill.
4. **Function map.** Every symbol keeps its provenance:

| Provenance | Can support Reachable? |
|---|---|
| Listed by the advisory (GHSA `vulnerable_functions`, OSV `ecosystem_specific`) and present in this version's source | Yes |
| Changed by a fix commit **and** named in the advisory's text | Yes |
| Changed by a fix commit only | **No.** A patch also touches callers, validators and helpers. A path to it gives Unknown |
| Nothing identifies a function | No |

   A fix commit that is a **merge** (a forward-port to another branch) is served by GitHub as the series of commits it brought in, whose diff mixes unrelated changes. It contributes nothing; the row records it as skipped.

   The fix diff is located in **this version's own file**, by its pre-image text. Neither its line numbers nor git's hunk header are used, since the header names the function *before* the change. If that fails, the change is placed by a function declaration in the patch's own context. Otherwise the hunk stays unmapped. Checked on 2026-11-01, no advisory listed a function: none of the 2,000 newest reviewed GHSA Composer advisories (published 2025-02 to 2026-10, read page by page with GitHub's cursor) has `vulnerable_functions`, and none of the 7,397 Packagist records in OSV's full export has any `ecosystem_specific` field. So fix commits are the main source.

5. **Call graph.** It is built from the app and the source of every package that can reach an affected package, on SAST's tree-sitter parser with PHP's name rules (namespaces, `use`, `self`, `parent`, `static`).
   - **Exact calls.** A call is exact when it has one target:
     - `new X` running X's constructor;
     - `$this` on an object whose class is known because it was created with `new`;
     - static calls and namespaced functions;
     - a literal include.
   - **Candidates.** Several targets, or an override that might run instead, make a call a candidate. Examples: a receiver typed by a parameter, a method found by name only, a dynamic method name on a known class, a closure that may never run, a function declared under a condition.
   - **Unresolved.** Anything else is recorded as unresolved: a variable callable, `new $class`, a dynamic include, or a class missing from its package's source.
6. **Supply chain.** Each finding is worded no stronger than its evidence:
   - **malicious package:** an applicable OSV MAL-\* record;
   - **unlocked or out-of-date lock:** Composer's own `content-hash`, which includes `config.policy` since Composer 2.11; both forms are accepted;
   - **branch versions;**
   - **dependency-confusion risk:** only for a `canonical: false` repository whose package name is also on Packagist;
   - **name similarity:** a name close to a popular package under a *different* vendor. A warning, never a typosquat claim.

## Statuses

Each row (package × advisory) starts **Unknown** and moves only on complete evidence. It carries a reason, its scope (roots, packages analysed, call kinds) and its limits.

| Status | What it claims | Requires |
|---|---|---|
| **Reachable** | *Static potential reachability*: not a demonstrated exploit, not feasibility under every configuration | A path from an entry point to an affected function where every call is exact. The path and its assumptions are in the row |
| **Imported-only** | The package is used, but nothing reaches its affected functions, within the stated scope | Affected functions known, the package used, no relevant unresolved call |
| **Present-only** | Nothing the app uses mentions the package, within the stated scope | Not used from the app or from any package the app uses. A `bin` entry is noted as an uncertainty, not taken as launched |
| **Unknown** | Not enough evidence | Missing source, a path only through a candidate call, a patch candidate only, an unidentified affected function on a used package, a relevant unresolved call, or a cap |

An unresolved call is **relevant** to a package when the roots reach it and it sits in code that can see that package (the app, the package, or one with a dependency path to it).

"Never downgrade Unknown" means never trading uncertainty for a reassuring status without that evidence. A later, better-supported assessment may move a row either way.

**Order:**
1. Known exploitation (KEV), Reachable first, then Unknown.
2. Then Reachable.
3. Then Unknown.
4. Then Imported-only.
5. Then Present-only.

Within each tier, rows are ordered by EPSS, then the published CVSS score. A KEV-listed Unknown is never ranked below an unlisted Reachable.

## Results

```sh
sast-engine/.venv/bin/python -m sca.cli scan sca/benchmarks/composer-app --out out/sca \
    --cache-dir sca/benchmarks/composer-app/snapshot --offline
sast-engine/.venv/bin/python sca/eval/score.py out/sca/sca.json sca/benchmarks/composer-app/key.json
```

`sca/benchmarks/composer-app` is a two-page app on real, affected package versions, with its `vendor/` tree. Its key was written before the analysis ran on it. `snapshot/` holds the advisory replies, so it runs offline.

| Row | Expected | Got | How |
|---|---|---|---|
| symfony/http-foundation v7.4.18, GHSA-r925-mgvr-h9cc | Reachable | Reachable | `index.php` → `HttpFoundationFactory::createRequest` (psr-http-message-bridge) → `new Request` → `initialize` → `new HeaderBag` → `set` → `parseCacheControl` → `HeaderUtils::split`. The app never names http-foundation |
| symfony/yaml v7.4.17, GHSA-2v3c-qxhr-7vpv | Unknown | Unknown | `$parser->$action()` picks the method at runtime. Three of its four fix commits are forward-port merges, which are skipped; the plain one maps to `Parser::lexInlineStructure`, which the advisory names |
| league/flysystem 3.35.2, GHSA-cxf4-7mrp-vvpr | Present-only | Present-only | Required but unused. flysystem-local requires it back, but nothing the app uses mentions either |

- **Benchmark:** 3/3, no false Reachable, no unsafe reassurance. Reruns are byte-identical.
- **Holdout:** DVWA's real `vulnerabilities/api/composer.lock` ([key](benchmarks/holdouts/dvwa-api.key.json), labelled before the first run). It pins symfony/yaml v8.1.2, inside GHSA-2v3c's range, with no `vendor/` tree. Result: Unknown, "source not supplied for symfony/yaml, zircote/swagger-php". 1/1.
- **Framework-heavy holdout:** the shop's Laravel app on a fresh `laravel/laravel:^11.0` install (111 locked packages, 65 MB of `vendor/`, 7,650 PHP files; rebuild with [build-lashop.sh](benchmarks/holdouts/build-lashop.sh)). [Key](benchmarks/holdouts/lashop.key.json), written after reading the app's code and before the first run. `laravel/framework` v11.57.1 has four advisories. **All four are Unknown, which is the expected answer: 4/4, no false Reachable, no unsafe reassurance.** The run takes about 4 seconds and 450 MB.
  - Laravel reaches the app's code through the framework: routing, the container, facades, and rules named by string. None of that is a call a static graph can follow. Exact calls reach 116 functions; calls we can only guess reach 9,807 (a method found by name alone, a closure that may never run), which is why 651 unresolved calls in code that can see `laravel/framework` block any "nothing reaches it".
  - A person reading the code can say three of the four are not used (no token guard, no signed URLs, no `email` rule) and the fourth depends on `APP_DEBUG`, which the source and the container set differently. The tool says Unknown for all four. That is safe but imprecise, and it is what a framework-heavy app gets.
  - Forced to stop early (`--max-functions 50` or `3000`, `--timeout 0.2`), every row stays Unknown with the stop reason recorded.
- **These are small.** We wrote the benchmark, and the holdouts are two real apps, one with no `vendor/` tree and one where the honest answer is Unknown throughout. They show the rules hold, not an accuracy rate: no real app yet gives a mix of statuses.

## Version ranges

OSV decides which advisories match a locked version. Our own range check only picks which fix version to show, and it follows **Composer's version order**, not OSV's version lists (which disagree with themselves: for pre-releases of an `introduced` bound they list 83 pairs and omit 962). A version Composer can't read is Unknown, never guessed.

Checked against Composer's own comparator (`composer/semver`, in the `composer:2` image) on 578,172 real version pairs from Packagist and advisory bounds, plus 2,401 pairs among unusual spellings (`-dev`, `-PL1`, `RC-8`, dates, build metadata): all agree, and so does which strings are readable. [tests/test_versions.py](tests/test_versions.py) re-runs a sample of that, stratified by version shape. Checking found three defects in the first version: `RC-8` equal to `RC-1`, an unreadable `introduced` bound silently skipping its range, and `1.5.7c` accepted as `1.5.7`. It also showed that Composer doesn't pad a date version to four parts.

## Limits

- **Composer only.** Python lockfiles are next.
- **The source is supplied, not downloaded.**
- **Process configuration** (Dockerfile, Procfile) isn't read, so a `bin` entry stays an uncertainty.
- **Framework magic stays unresolved:** container lookups, `__call` dispatch and string-built class names. A framework-heavy app gets more Unknown rows.
- **Library code isn't analysed for every package:** only for those with a dependency path to an affected package. This assumes a package only calls packages it declares.
- **Tools:** the note suggests CodeQL, Joern or Semgrep for the call graph. CodeQL has no PHP support and Joern needs a JVM, so we built the graph on SAST's tree-sitter parser.

## For the web workspace

`issues.json` has an optional top-level `dependencies` object (see [issues.schema.json](../correlator/issues.schema.json)) with these parts:
- `rows`: each with `status`, `package`, `version`, `advisory` (`id`, `url`, `cvss`, `epss`, `kev`), `reason`, and `path` (steps with `function`, `package`, `called_from`), plus `assumptions` and `limits`.
- `supply_chain`, `advisory_lookup`, `stats`.

Wiring it into the UI takes three steps:
1. Run `sca.cli scan` after SAST, with its `routes.json`.
2. Pass `--sca <out>/sca.json` to the correlator.
3. Show the section in its own tab, not mixed into the issue list.

## Tests

```sh
sast-engine/.venv/bin/python -m pytest sca/tests
```

The tests use no network: they run on small Composer projects built in temp folders, recorded replies, and the benchmark's snapshot.

Regenerate `data/popular-packagist.txt` from `https://packagist.org/explore/popular.json?per_page=100`, following `next` for 10 pages.
