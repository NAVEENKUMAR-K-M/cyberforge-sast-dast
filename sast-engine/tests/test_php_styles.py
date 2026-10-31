"""PHP written in styles none of the benchmark apps use. The tool has to work on any codebase,
so each style gets a test here, and they test mechanisms rather than particular libraries."""
import pytest

from conftest import open_findings, safe_findings

SQL = "'SELECT * FROM t WHERE id = ' . "


# --- SQL recognised by what the string says, whichever library runs it ---

@pytest.mark.parametrize("call", [
    "$conn->executeQuery(%s)",
    "$wpdb->get_results(%s)",
    "$adapter->fetchAllAssociative(%s)",
    "DB::select(%s)",
    "run_sql_somewhere(%s)",
    "$db->fetchAll(%s)",
    "$db->Execute(%s)",
    "$f = 'unknown_runner'; $f(%s)",
])
def test_sql_shaped_string_reaching_any_unseen_call_is_sql_injection(scan, call):
    code = call % (SQL + "$_GET['id']")
    found = open_findings(scan({"page.php": f"<?php {code};"}), 89)
    assert found, code
    assert found[0]["confidence"] == "medium", "the code that runs it isn't visible, so it can't rank high"
    assert found[0]["source_params"][0]["name"] == "id"


@pytest.mark.parametrize("code", [
    "$logger->info('SELECT * FROM t WHERE id = ' . $_GET['id']);",
    "error_log('SELECT * FROM t WHERE id = ' . $_GET['id']);",
    "$mailer->send('Please select from ' . $_GET['id']);",
    "$conn->executeQuery('SELECT * FROM t WHERE id = ?', [$_GET['id']]);",
    "$conn->executeQuery('SELECT * FROM t WHERE id = ' . (int) $_GET['id']);",
])
def test_things_that_arent_sql_injection_stay_quiet(scan, code):
    assert not open_findings(scan({"page.php": f"<?php {code}"}), 89), code


def test_stored_flow_read_through_an_unseen_library(scan):
    result = scan({
        "add.php": "<?php $s = $pdo->prepare('INSERT INTO notes (body) VALUES (?)'); $s->execute([$_POST['body']]);",
        "show.php": "<?php foreach ($wpdb->get_results('SELECT body FROM notes') as $n) { echo $n->body; }",
    })
    assert open_findings(result, 79)[0]["source_params"][0]["name"] == "body"


# --- Request objects recognised by role ---

@pytest.mark.parametrize("expression,name,location", [
    ("$request->query->get('id')", "id", "query"),
    ("$request->request->get('id')", "id", "body"),
    ("$request->cookies->get('id')", "id", "cookie"),
    ("$request->headers->get('id')", "id", "header"),
    ("$request->input('id')", "id", "any"),
    ("$request->id", "id", "any"),
    ("$request['id']", "id", "any"),
    ("$request->getParam('id')", "id", "any"),
    ("$req->getQueryParams()['id']", "id", "query"),
    ("$this->input->get('id')", "id", "any"),
    ("$this->input->post('id')", "id", "body"),
    ("$this->request->getGet('id')", "id", "query"),
    ("$this->request->post['id']", "id", "body"),
    ("$this->getRequest()->getParam('id')", "id", "any"),
    ("Yii::$app->request->get('id')", "id", "any"),
    ("request('id')", "id", "any"),
    ("request()->input('id')", "id", "any"),
])
def test_request_objects_are_input_whatever_framework_they_come_from(scan, expression, name, location):
    code = f"class C {{ function s() {{ $db->query({SQL}{expression}); }} }} (new C)->s();"
    found = open_findings(scan({"page.php": f"<?php {code}"}), 89)
    assert found, expression
    assert found[0]["source_params"][0] == {"name": name, "location": location}


def test_a_type_hint_is_stronger_evidence_than_a_name(scan):
    typed = "function f(ServerRequestInterface $x) { $db->query(%s$x->getQueryParams()['id']); }\nf($unknown);" % SQL
    guessed = "function f() { $db->query(%s$request->getParam('id')); }\nf();" % SQL
    assert open_findings(scan({"a.php": f"<?php {typed}"}), 89)[0]["confidence"] == "high"
    assert open_findings(scan({"a.php": f"<?php {guessed}"}), 89)[0]["confidence"] == "medium"


def test_the_project_own_class_named_request_isnt_input(scan):
    code = "class Request { public function get($k) { return 'fixed'; } }\nfunction f(Request $r) { $db->query(%s$r->get('id')); }\nf(new Request());" % SQL
    assert not open_findings(scan({"a.php": f"<?php {code}"}), 89)


def test_non_input_request_properties_stay_quiet(scan):
    assert not open_findings(scan({"a.php": "<?php echo $request->method; echo $request->ip;"}), 79)


# --- Language features ---

def test_method_from_a_trait(scan):
    code = "trait T { function f($x) { global $db; $db->query(%s$x); } }\nclass C { use T; }\n(new C)->f($_GET['id']);" % SQL
    assert open_findings(scan({"a.php": f"<?php {code}"}), 89)


def test_use_alias_resolves_to_the_real_class(scan):
    result = scan({
        "lib.php": "<?php namespace App; class Repo { static function find($x) { global $db; $db->query(%s$x); } }" % SQL,
        "a.php": "<?php use App\\Repo as R; require 'lib.php'; R::find($_GET['id']);",
    })
    assert open_findings(result, 89)


@pytest.mark.parametrize("code", [
    "array_map(function ($v) { echo $v; }, $_GET['a']);",
    "array_map(fn ($v) => print($v), $_GET['a']);",
    "array_walk($_GET['a'], function ($v) { echo $v; });",
    "array_filter($_GET['a'], function ($v) { echo $v; return true; });",
    "function show($v) { echo $v; }\narray_map('show', $_GET['a']);",
    "function show($v) { echo $v; }\ncall_user_func('show', $_GET['a']);",
    "function show($v) { echo $v; }\ncall_user_func_array('show', [$_GET['a']]);",
    "class C { function show($v) { echo $v; } function go() { array_map([$this, 'show'], $_GET['a']); } }\n(new C)->go();",
    "class C { static function show($v) { echo $v; } }\ncall_user_func(['C', 'show'], $_GET['a']);",
    "class C { static function show($v) { echo $v; } }\ncall_user_func('C::show', $_GET['a']);",
    "$f = function ($v) { echo $v; }; $f($_GET['a']);",
    "function show($v) { echo $v; }\n$f = show(...); $f($_GET['a']);",
    "class C { function show($v) { echo $v; } }\n$o = new C(); $f = $o->show(...); $f($_GET['a']);",
    "preg_replace_callback('/x/', function ($m) { echo $m[0]; return ''; }, $_GET['a']);",
])
def test_values_reach_callback_parameters(scan, code):
    assert open_findings(scan({"a.php": f"<?php {code}"}), 79), code


def test_callback_sanitiser_protects_the_result(scan):
    assert not open_findings(scan({"a.php": "<?php $v = array_map('intval', $_GET['a']); echo implode(',', $v);"}), 79)
    assert not open_findings(scan({"a.php": "<?php $v = array_map('htmlspecialchars', $_GET['a']); echo '<p>' . implode(',', $v) . '</p>';"}), 79)
    assert open_findings(scan({"a.php": "<?php $v = array_map('trim', $_GET['a']); echo implode(',', $v);"}), 79)


def test_closure_returning_input(scan):
    assert open_findings(scan({"a.php": "<?php $f = function () { return $_GET['a']; }; echo $f();"}), 79)


# --- Reachability: unknown stays unknown ---

def test_hand_written_mvc_isnt_marked_unreachable(scan):
    result = scan({
        "index.php": "<?php $c = $_GET['c'] . 'Controller'; $a = $_GET['a']; require 'controllers/' . $c . '.php'; $o = new $c(); $o->$a();",
        "controllers/OrdersController.php": "<?php class OrdersController { function show() { global $db; $db->query(%s$_GET['id']); } }" % SQL,
    })
    found = open_findings(result, 89)
    assert found, "dynamic dispatch means this may run, so it can't be called safe"
    assert found[0]["confidence"] == "low"
    assert found[0]["routes"] == []


def test_controller_extending_a_framework_class_isnt_marked_unreachable(scan):
    code = "class OrdersController extends BaseController { function show() { global $db; $db->query(%s$_GET['id']); } }" % SQL
    assert open_findings(scan({"a.php": f"<?php {code}"}), 89)[0]["confidence"] == "low"


def test_magic_method_isnt_marked_unreachable(scan):
    code = "class C { function __destruct() { system('rm ' . $_GET['f']); } }"
    assert open_findings(scan({"a.php": f"<?php {code}"}), 78)


def test_truly_dead_code_is_still_marked_unreachable(scan):
    assert "no route" in safe_findings(scan({"lib.php": "<?php function dead() { return shell_exec('ls ' . $_GET['x']); }"}), 78)[0]["suppression_reason"]
    code = "class Unused { function dead() { return shell_exec('ls ' . $_GET['x']); } }"
    assert "no route" in safe_findings(scan({"lib.php": f"<?php {code}"}), 78)[0]["suppression_reason"]


def test_dead_function_with_dynamic_calls_around_is_unknown_not_safe(scan):
    code = "function dead() { return shell_exec('ls ' . $_GET['x']); }\n$f = $_GET['f']; $f();"
    assert open_findings(scan({"a.php": f"<?php {code}"}), 78)[0]["confidence"] == "low"


# --- Routes declared in code ---

@pytest.mark.parametrize("declaration,path", [
    ("#[Route('/orders/{id}')]", "/orders/{id}"),
    ("#[Route('/orders/{id}', methods: ['POST'])]", "/orders/{id}"),
    ("#[\\Symfony\\Component\\Routing\\Attribute\\Route('/orders/{id}')]", "/orders/{id}"),
    ("#[Get('/orders/{id}')]", "/orders/{id}"),
    ("/** @Route(\"/orders/{id}\") */", "/orders/{id}"),
])
def test_route_attributes(scan, declaration, path):
    code = f"class C {{\n {declaration}\n public function show($id) {{ global $db; $db->query({SQL}$id); }}\n}}"
    found = open_findings(scan({"public/index.php": "<?php echo 1;", "src/C.php": f"<?php {code}"}), 89)
    assert found[0]["routes"][0]["path"] == path
    assert found[0]["source_params"] == [{"name": "id", "location": "path"}]
    assert found[0]["confidence"] == "high"


def test_class_level_route_prefix_and_method_list(scan):
    code = "#[Route('/admin')]\nclass C { #[Route('/run', methods: ['POST'])] public function run(Request $r) { global $db; $db->query(%s$r->request->get('id')); } }" % SQL
    route = open_findings(scan({"public/index.php": "<?php echo 1;", "src/C.php": f"<?php {code}"}), 89)[0]["routes"][0]
    assert route["path"] == "/admin/run" and route["methods"] == ["POST"]


@pytest.mark.parametrize("declaration,path", [
    ("$routes->get('orders/(:num)', 'Orders::show/$1');", "/orders/(:num)"),
    ("$router->get('/orders', 'Orders@show');", "/orders"),
    ("$app->get('/orders', [Orders::class, 'show']);", "/orders"),
    ("$app->group('/api', function ($g) { $g->get('/orders', 'Orders:show'); });", "/api/orders"),
    ("Route::group(['prefix' => 'api'], function () { Route::get('orders', 'Orders@show'); });", "/api/orders"),
    ("Route::resource('orders', Orders::class);", "/orders/{id}"),
])
def test_router_calls(scan, declaration, path):
    result = scan({
        "public/index.php": "<?php echo 1;",
        "routes.php": f"<?php {declaration}",
        "src/Orders.php": "<?php class Orders { public function show($id = 0) { global $db; $db->query(%s$_GET['q']); } }" % SQL,
    })
    assert path in {r["path"] for f in open_findings(result, 89) for r in f["routes"]}


def test_get_on_an_unrelated_object_isnt_a_route(scan):
    result = scan({"a.php": "<?php function show() { echo 1; }\n$cache->get('show', 'show');"})
    assert {r["path"] for r in result["routes"]} == {"/a.php"}


def test_slim_style_route_values_array(scan):
    code = "$app->get('/o/{id}', function ($req, $res, $args) { global $db; $db->query(%s$args['id']); });" % SQL
    assert open_findings(scan({"index.php": f"<?php {code}"}), 89)[0]["source_params"][0]["name"] == "id"


def test_int_typed_route_value_is_safe(scan):
    code = "class C { #[Route('/o/{id}')] function s(int $id) { global $db; $db->query(%s$id); } }" % SQL
    result = scan({"public/index.php": "<?php echo 1;", "src/C.php": f"<?php {code}"})
    assert not open_findings(result, 89)
    assert safe_findings(result, 89)


@pytest.mark.parametrize("rule,alias", [
    ("RewriteRule ^orders/([0-9]+)$ orders.php?id=$1 [L]", "/orders/{id}"),
    ("RewriteRule ^orders/([0-9]+)/?$ orders.php?id=$1", "/orders/{id}"),
    ("RewriteRule ^order-list$ orders.php [L]", "/order-list"),
])
def test_rewrite_rules_become_aliases(scan, tmp_path, rule, alias):
    (tmp_path / ".htaccess").write_text(f"RewriteEngine On\n{rule}\n")
    result = scan({"orders.php": "<?php echo 1;"})
    assert alias in next(r for r in result["routes"] if r["path"] == "/orders.php")["aliases"]
    assert result["stats"]["rewrite_rules_applied"] == 1


@pytest.mark.parametrize("rule", [
    "RewriteRule ^(.*)$ orders.php?u=$1 [L]",
    "RewriteRule .* orders.php [L]",
    "RewriteRule ^x$ https://example.test/ [R]",
    "RewriteRule ^x$ - [F]",
    "RewriteRule ^x$ missing.php [L]",
])
def test_rewrite_rules_it_cant_read_are_left_alone(scan, tmp_path, rule):
    (tmp_path / ".htaccess").write_text(f"RewriteEngine On\n{rule}\n")
    result = scan({"orders.php": "<?php echo 1;"})
    assert next(r for r in result["routes"] if r["path"] == "/orders.php")["aliases"] == []


def test_rewrite_to_a_page_chosen_by_query_targets_that_page(scan, tmp_path):
    (tmp_path / ".htaccess").write_text("RewriteRule ^orders$ index.php?page=orders [L]\n")
    result = scan({
        "index.php": "<?php $pages = ['orders' => 'pages/orders.php']; include $pages[$_GET['page']];",
        "pages/orders.php": "<?php echo $_GET['q'];",
    })
    route = next(r for r in result["routes"] if r["selector"] == "page=orders")
    assert "/orders" in route["aliases"]


# --- Templates ---

CONTROLLER = "<?php class C { function s() { %s } }\n(new C)->s();"


@pytest.mark.parametrize("files,render,line", [
    ({"resources/views/p.blade.php": "<p>{{ $n }}</p>\n<p>{!! $n !!}</p>"}, "return view('p', ['n' => $_GET['n']]);", 2),
    ({"resources/views/p.blade.php": "<p>{!! $n !!}</p>"}, "return view('p')->with('n', $_GET['n']);", 1),
    ({"resources/views/o/p.blade.php": "<p>{!! $n !!}</p>"}, "return view('o.p', compact('x') + ['n' => $_GET['n']]);", 1),
    ({"templates/p.html.twig": "<p>{{ n }}</p>\n<p>{{ n|raw }}</p>"}, "return $this->render('p.html.twig', ['n' => $_GET['n']]);", 2),
    ({"templates/p.twig": "{% autoescape false %}\n<p>{{ n }}</p>\n{% endautoescape %}"}, "return $twig->render('p.twig', ['n' => $_GET['n']]);", 2),
    ({"templates/p.tpl": "<p>{$n|escape}</p>\n<p>{$n}</p>"}, "$smarty->assign('n', $_GET['n']); $smarty->display('p.tpl');", 2),
])
def test_unescaped_template_output(scan, files, render, line):
    result = scan({**files, "c.php": CONTROLLER % render})
    found = [f for f in open_findings(result, 79) if f["file"] in files]
    assert found and found[0]["line"] == line, render


def test_escaped_template_output_stays_quiet(scan):
    result = scan({"templates/p.twig": "<p>{{ n }}</p>", "c.php": CONTROLLER % "return $twig->render('p.twig', ['n' => $_GET['n']]);"})
    assert not open_findings(result, 79)


def test_escaped_before_reaching_a_raw_template_is_safe(scan):
    result = scan({
        "resources/views/p.blade.php": "<p>{!! $n !!}</p>",
        "c.php": CONTROLLER % "return view('p', ['n' => htmlspecialchars($_GET['n'])]);",
    })
    assert not open_findings(result, 79) and safe_findings(result, 79)


def test_plain_php_view_rendered_through_an_unseen_loader(scan):
    result = scan({
        "application/views/home.php": "<h1><?= $name ?></h1>",
        "c.php": CONTROLLER % "$this->load->view('home', ['name' => $_GET['n']]);",
    })
    found = open_findings(result, 79)
    assert found and found[0]["file"] == "application/views/home.php"


def test_view_name_needs_a_render_verb(scan):
    result = scan({"views/home.php": "<?php echo $_GET['q'];", "c.php": "<?php $cache->get('home');"})
    assert all(r["path"] != "/c.php" for f in open_findings(result, 79) for r in f["routes"])


def test_php_in_tpl_and_html_files_is_analysed_when_included(scan):
    result = scan({"a.php": "<?php $n = $_GET['n']; include 'v.tpl'; include 'w.html';", "v.tpl": "<p><?= $n ?></p>", "w.html": "<b><?= $n ?></b>", "plain.html": "<p>static</p>"})
    assert {f["file"] for f in open_findings(result, 79)} == {"v.tpl", "w.html"}
    assert all(r["path"] != "/plain.html" for r in result["routes"])


# --- Secrets outside PHP code ---

@pytest.mark.parametrize("name,content", [
    (".env", "APP_NAME=shop\nDB_PASSWORD=hunter2live\n"),
    (".env.production", "JWT_SECRET=\"abc123def\"\n"),
    ("config/settings.ini", "[db]\npassword = hunter2live\n"),
    ("config/app.yml", "database:\n  password: hunter2live\n"),
    ("docker-compose.yml", "services:\n  db:\n    environment:\n      MYSQL_ROOT_PASSWORD: rootpw\n"),
    ("config/app.json", '{"db": {"password": "hunter2live"}}\n'),
    ("config/app.xml", "<db><password>hunter2live</password></db>\n"),
    ("web.config", '<connectionStrings><add name="main" password="hunter2live"/></connectionStrings>\n'),
    ("config/keys.yml", "aws: AKIAIOSFODNN7EXAMPLE\n"),
])
def test_secrets_in_config_files(scan, name, content):
    result = scan({"a.php": "<?php echo 1;", name: content})
    found = open_findings(result, 798)
    assert [f["file"] for f in found] == [name]
    assert found[0]["engines"] == ["config"]
    assert "hunter2live" not in found[0]["snippet"], "live secrets mustn't be copied into the output"


@pytest.mark.parametrize("name,content", [
    (".env", "DB_PASSWORD=\n"),
    (".env", "DB_PASSWORD=${VAULT_DB_PASSWORD}\n"),
    (".env", "# DB_PASSWORD=hunter2live\n"),
    ("config/app.yml", "password: %env(DB_PASSWORD)%\n"),
    ("config/app.yml", "password: true\n"),
    ("config/app.yml", "password_min_length: 8\n"),
    ("config/app.json", '{"password": "string"}\n'),
    ("composer.lock", '{"password": "hunter2live"}\n'),
    ("package.json", '{"token": "abcdef1234567890"}\n'),
])
def test_config_values_that_arent_secrets(scan, name, content):
    assert not open_findings(scan({"a.php": "<?php echo 1;", name: content}), 798), content


@pytest.mark.parametrize("line,expected", [
    ("$p = getenv('DB_PASSWORD') ?: 'p@ssw0rd';", True),
    ("$p = env('DB_PASSWORD', 'p@ssw0rd');", True),
    ("$p = getenv('DB_PASSWORD');", False),
    ("$p = env('DB_PASSWORD', '');", False),
    ("$p = getenv('DB_HOST') ?: 'localhost';", False),
])
def test_hard_coded_fallback_for_an_environment_variable(scan, line, expected):
    found = open_findings(scan({"a.php": f"<?php\n{line}\n"}, semgrep=True), 798)
    assert bool(found) is expected, line
