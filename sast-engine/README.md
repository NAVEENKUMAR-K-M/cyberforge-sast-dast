# CyberForge SAST engine

Static analysis for PHP and Python web apps, built for the CyberForge SAST and DAST correlation challenge. It reads source code and reports where user input reaches something dangerous, along with the URL that triggers it, so each finding can later be linked to a runtime proof.

This folder holds the SAST side. The DAST engine lives in `../dast-engine`, and it and the correlator connect to this engine through the [output format](docs/finding-format.md). Every scan also writes `findings.common.json`, the one finding format both scanners share, described in [common/FORMAT.md](../common/FORMAT.md).

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
| `--language python` | `php`, `python` or `auto` (the default), which picks the language with most files, with `composer.json` or `requirements.txt` counting extra |
| `--web-root public` | Set the web root, if detection gets it wrong (PHP) |
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
| Weak password hashes | 327, 328 | Both |
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

### Python

The Python engine (`sast/lang/python/`) works the same way on the standard `ast` module, with no extra parser:

- **Routes** come from Django (`urls.py` with `path()`, `re_path()` and `include()` chains, found from `ROOT_URLCONF`; `<int:pk>`, `<slug:s>` and `(?P<year>[0-9]{4})` patterns; function views with `require_POST` and friends, class-based views by the methods they define, DRF routers and `@api_view`), Flask (`@app.route`, `@bp.get`, `add_url_rule`, `MethodView`, blueprint prefixes from both `Blueprint(url_prefix=)` and `register_blueprint(url_prefix=)`, `<int:id>` converters), FastAPI (`APIRouter(prefix=)`, `include_router`, parameters bound from the signature: path, query, header, cookie, pydantic bodies, `Depends`) and OpenAPI-first apps such as connexion (the document's `operationId` names the handler). Every URL is written with `{name}` placeholders whatever the framework spells them as, so a runtime finding on `/orders/5` meets the code behind `/orders/<int:order_id>`.
- **Django specifics:** `request.GET`, `request.POST`, `request.META`, `request.body` (as JSON when passed to `json.loads`) and DRF's `request.data`; `Form` classes, where `cleaned_data` holds one input per declared field and an `IntegerField` or `ChoiceField` can't carry text; the ORM, where `Model.objects.create(...)` and `Model(...).save()` store values by model and `.all()` / `.filter()` give them back, so a stored XSS through `{{ review.body|safe }}` is linked to the view that wrote it; `Model.objects.raw()`, `cursor.execute()`, `mark_safe()` and `{% autoescape off %}`.
- **Typed parameters** (`<int:id>`, `id: int`, `type=int`) are parsed by the framework before the code runs. They stay in the route map marked `type: validated`, and DAST skips them.
- **Flows** follow Flask `request.*`, FastAPI parameters, string building (f-strings, `%`, `.format`, `+`), project functions and methods (including through a class), SQL results (stored XSS through `INSERT` then `SELECT`), and the `| safe` and `autoescape false` spots of Jinja templates. A `str` returned from a normal FastAPI route is JSON, so it isn't XSS; from Flask it is HTML.
- **Protections** are read in context, as for PHP: bound parameters, `int()` and `type=int`, allowlists and `isdigit()` guards, `html.escape` (and where it is not enough), `shlex.quote`, list-form `subprocess` with no shell, `secure_filename`, `realpath` plus a prefix check, and fixed redirect prefixes.
- **Pattern rules** are in [sast/rules/python.yml](sast/rules/python.yml).

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
| `benchmarks/lashop` (Laravel 11) | Our own, verified by DAST | 10/10 | 8/8 | 0/9 | 4s |
| `benchmarks/djshop` (Django 5) | Our own, verified by DAST | 12/12 | 10/10 | 0/11 | 4s |
| `benchmarks/pyshop` (Flask) | Our own, verified at runtime | 33/33 | 23/23 | 0/16 | 4s |
| `benchmarks/fastshop` (FastAPI) | Our own, verified at runtime | 7/7 | 6/6 | 0/4 | 4s |
| Vulpy `bad` (Flask) | Holdout, Python | 8/9 | 4/4 | 0/3 | 3s |
| Vulpy `good` | Holdout, Python | 6/6 | 1/1 | 0/3 | 3s |
| VAmPI (Flask + connexion) | Holdout, Python | 3/3 | 1/1 | 0/3 | 3s |
| Vulnerable-Flask-App | Holdout, Python | 7/8 | 1/1 | 0/4 | 3s |

**Read these with care.** The best estimate for an unseen app is the first run on the holdout apps, before any fixes:

| Holdout, first run | Bugs found | Pairs with right route and parameter | Decoys reported |
|---|---|---|---|
| XVWA | 9/10 (90%) | 8/9 | 0/2 |
| bWAPP | 12/14 (86%) | 11/11 | 0/2 |

The misses from that run were fixed in general ways, so the 100% rows above are no longer blind tests.

The Python holdouts were fetched at pinned commits and labelled by reading their source before the engine was changed for them. The first run was:

| Python holdout, first run | Bugs found | Pairs with right route and parameter | Decoys reported |
|---|---|---|---|
| Vulpy `bad` | 7/9 | 0/4 | 0/3 |
| Vulpy `good` | 5/6 | 0/1 | 0/3 |
| VAmPI | 2/3 | 0/1 | 1/3 |
| Vulnerable-Flask-App | 6/8 | 1/1 | 1/4 |

What that run showed, all fixed in general ways (so the Python holdout rows in the first table are not blind tests either): module resolution lost the `url_prefix` of blueprints registered from another file (every Vulpy route was wrong), Jinja `| safe` output wasn't modelled (Vulpy's stored XSS), a spec-first app had no routes at all (VAmPI, whose only injection was therefore never reached), a function the framework calls (`@app.errorhandler`) was treated as dead code, a JSON `Response` whose `mimetype` is set afterwards was taken for an HTML page, and a status message under a key called `Password` was taken for a credential. Still missed, and left visible in the keys: an API key built from `random.getrandbits` (the variable name is too ordinary for the pattern rule) and an unsafe `yaml.load` of a file the visitor uploaded (it needs file content to count as input).

Other limits:

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

- **PHP and Python only.** Language-specific code sits behind `LanguageAdapter` in [sast/core/language.py](sast/core/language.py), so others can be added. Python covers Flask, FastAPI, Django (with DRF) and spec-first apps; **aiohttp, Tornado and Sanic routes are not read**, so those apps get findings without routes. Django's generic class-based views are read from their class attributes (`model`, `fields`, `form_class`, `template_name`, `paginate_by`): a `CreateView` stores its fields, a `ListView` or `DetailView` shows the model through its template, and overridden hooks such as `form_valid(self, form)` and `get_queryset(self)` are analysed. DRF's generic views (`ModelViewSet`, `ListCreateAPIView`) and a ModelForm's `Meta.fields` are not read.
- **Only the Django ORM is followed for stored flows.** Raw SQL (`execute("INSERT ...")` then `execute("SELECT ...")`) and Django's `Model.objects` are tracked; SQLAlchemy's `session.add(Model(...))` and `Model.query.all()` are not.
- **Jinja is read as text.** `| safe` and `autoescape false` are found, including through loops and `{% include %}`, but filters, macros and `flash()` messages printed by an included template are not followed.
- **Laravel is tested on one real app we wrote** (`benchmarks/lashop`, Laravel 11 installed by composer, with CSRF-protected forms, Blade, `DB::` queries, Eloquent and `routes/api.php`): 10/10 bugs, 8/8 pairs, 0/9 decoys, and 8 of 8 pairs Confirmed end to end. It reads `Route::get/match/any/resource`, groups and prefixes, `routes/api.php` under `/api`, `->whereNumber()`, `->whereUuid()` and `->where()` patterns, Blade `{!! !!}` including through `@foreach`, `DB::insert` bindings as stored writes, and `response()->download()`. Not tested: Livewire, Inertia, queued jobs, middleware that rewrites input, and other versions of Laravel. Slim and Symfony-style routes pass on hand-written fixtures only. Plain PHP is what the older benchmarks cover.
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

## Benchmark Laravel app

`benchmarks/lashop/overlay` holds the files we wrote for a Laravel 11 app: routes, controllers, Blade views, a migration. The Dockerfile installs the Laravel skeleton with composer (its security-advisory blocking is switched off, since this app is deliberately vulnerable), copies the overlay over it and serves it in production mode.

```sh
docker compose -f benchmarks/lashop/docker-compose.yml up -d --build   # first build takes a few minutes
docker compose -f benchmarks/lashop/docker-compose.yml down
```

It listens on `127.0.0.1:8092` only. Scanning the whole installed tree works too (`docker cp` it out and delete `vendor/`), which is how we checked that Laravel's own files produce no findings.

## Benchmark Python apps

`benchmarks/pyshop` is a deliberately vulnerable Flask shop (37 URLs: blueprints, a JSON API, HTML pages, SQLite, debug off). Its key is `eval/keys/pyshop.json` and `eval/verify_pyshop.py` proves it over HTTP: every bug is exploitable and every decoy holds.

```sh
docker compose -f benchmarks/pyshop/docker-compose.yml up -d --build
.venv/bin/python eval/verify_pyshop.py
docker compose -f benchmarks/pyshop/docker-compose.yml down
```

`benchmarks/djshop` is a Django 5 app (gunicorn, `DEBUG = False`, CSRF on) with `include()` chains, converters, a class-based view, the ORM, a Form and templates; it listens on `127.0.0.1:8093` (`docker compose -f benchmarks/djshop/docker-compose.yml up -d --build`). PyGoat is fetched as a Django smoke test only: this version of it keeps its vulnerable labs in separate Flask apps, so it has no key.

It listens on `127.0.0.1:8089` only. `benchmarks/fastshop` is a single-file FastAPI app for the typed-API case; run it with `uvicorn main:app --host 127.0.0.1 --port 8091`. Never expose either to a network.

## Tests

```sh
.venv/bin/python -m pytest
```

## Open-source components

| Component | Used for |
|---|---|
| [tree-sitter](https://github.com/tree-sitter/py-tree-sitter) and [tree-sitter-php](https://github.com/tree-sitter/tree-sitter-php) | Parsing PHP |
| The Python standard library `ast` module and [PyYAML](https://github.com/yaml/pyyaml) | Parsing Python, and reading OpenAPI documents |
| [Semgrep](https://github.com/semgrep/semgrep) | Running the pattern rules. The rules in [sast/rules/php.yml](sast/rules/php.yml) and [sast/rules/python.yml](sast/rules/python.yml) are our own |
| [pytest](https://github.com/pytest-dev/pytest) and [jsonschema](https://github.com/python-jsonschema/jsonschema) | Tests |

Benchmark apps, downloaded at evaluation time and not part of this repo: [DVWA](https://github.com/digininja/DVWA), [Mutillidae](https://github.com/webpwnized/mutillidae), [bWAPP](https://github.com/raesene/bWAPP), [XVWA](https://github.com/s4n7h0/xvwa), [Vulpy](https://github.com/fportantier/vulpy), [VAmPI](https://github.com/erev0s/VAmPI), [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App).

The route map, taint interpreter and finding merge are our own work.
