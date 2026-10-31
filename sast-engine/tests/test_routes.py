"""The route map (FR-4), framework routes, and fingerprint stability (FR-6)."""
import json
import os

from conftest import open_findings

SHOP = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "shop")


def by_path(result):
    return {(r["path"], r["selector"]): r for r in result["routes"]}


def test_included_only_files_arent_routes(scan):
    result = scan({
        "index.php": "<?php require 'lib/db.php'; echo 'hi';",
        "lib/db.php": "<?php $x = 1;",
        "classes/Foo.php": "<?php class Foo { function a() {} }",
    })
    assert set(by_path(result)) == {("/index.php", None)}


def test_index_php_has_a_folder_alias(scan):
    result = scan({"index.php": "<?php echo 1;", "shop/index.php": "<?php echo 2;"})
    assert by_path(result)[("/shop/index.php", None)]["aliases"] == ["/shop/"]
    assert by_path(result)[("/index.php", None)]["aliases"] == ["/"]


def test_public_folder_is_the_web_root(scan):
    result = scan({"public/index.php": "<?php echo 1;", "public/a.php": "<?php echo 2;", "app/job.php": "<?php echo 3;"})
    assert {"/index.php", "/a.php"} == {r["path"] for r in result["routes"]}


def test_base_path_prefixes_routes(scan):
    result = scan({"index.php": "<?php echo 1;"}, base_path="/dvwa/")
    assert result["routes"][0]["path"] == "/dvwa/index.php"
    assert result["routes"][0]["aliases"] == ["/dvwa/"]


def test_htaccess_deny_all_blocks_but_deny_then_allow_doesnt(scan):
    result = scan({"a/index.php": "<?php echo 1;", "index.php": "<?php echo 1;", "b/index.php": "<?php echo 2;"})
    assert ("/a/index.php", None) in by_path(result)


def test_htaccess_rules(tmp_path):
    from sast.lang.php.project import Project
    (tmp_path / "shut").mkdir()
    (tmp_path / "shut" / "a.php").write_text("<?php echo 1;")
    (tmp_path / "shut" / ".htaccess").write_text("Require all denied\n")
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "b.php").write_text("<?php echo 1;")
    (tmp_path / "local" / ".htaccess").write_text("Order Deny,Allow\nDeny from all\nAllow from 127.0.0.0/8\n")
    project = Project(str(tmp_path))
    assert project.is_blocked("shut/a.php")
    assert not project.is_blocked("local/b.php")


def test_direct_access_guard_means_not_an_entry(scan):
    result = scan({"index.php": "<?php echo 1;", "part.php": "<?php if (!defined('APP')) { exit; } echo 2;"})
    assert ("/part.php", None) not in by_path(result)


def test_front_controller_selector_routes(scan):
    result = scan({
        "index.php": "<?php $p = $_GET['page']; echo '<a href=\"index.php?page=dns.php\">x</a>'; include($p);",
        "dns.php": "<?php shell_exec('nslookup ' . $_POST['host']);",
    })
    routes = by_path(result)
    assert ("/index.php", "page=dns.php") in routes
    found = open_findings(result, 78)[0]
    assert {(r["path"], r["selector"]) for r in found["routes"]} == {("/index.php", "page=dns.php"), ("/dns.php", None)}
    assert open_findings(result, 22), "the dispatcher itself is still a file inclusion bug"


def test_map_based_dispatch_gets_a_selector_and_isnt_a_bug(scan):
    result = scan({
        "index.php": "<?php $pages = ['home' => 'home.php']; include $pages[$_GET['p']];",
        "home.php": "<?php echo $_GET['q'];",
    })
    assert not open_findings(result, 22)
    assert "p=home" in {r["selector"] for r in open_findings(result, 79)[0]["routes"]}


def test_switch_on_action_gives_each_bug_its_own_route(scan):
    code = """
    switch ($_GET['action']) {
        case 'view': $db->query('SELECT 1 WHERE a = ' . $_GET['a']); break;
        case 'edit': $db->query('SELECT 2 WHERE b = ' . $_GET['b']); break;
    }
    """
    found = open_findings(scan({"shop.php": f"<?php {code}"}), 89)
    assert {f["routes"][0]["selector"] for f in found} == {"action=view", "action=edit"}


def test_switch_that_only_sets_values_isnt_a_route(scan):
    code = "switch ($_POST['level']) { case '0': $l = 'low'; break; case '1': $l = 'high'; break; } echo 1;"
    assert {r["selector"] for r in scan({"a.php": f"<?php {code}"})["routes"]} == {None}


def test_path_dispatch_makes_routes(scan):
    code = "$u = $_SERVER['REQUEST_URI']; if ($u === '/orders') { shell_exec('ls ' . $_GET['x']); }"
    found = open_findings(scan({"index.php": f"<?php {code}"}), 78)
    assert found[0]["routes"][0]["path"] == "/orders"


def test_route_lists_params_guards_methods_and_forms(scan):
    code = """<?php if (isset($_POST['Submit'])) { echo htmlspecialchars($_POST['name']); }
    if ($_GET['mode'] == 'fast') { echo 1; } ?>
    <form method="post" action="a.php"><input name="name"><input type="submit" name="Submit" value="Go"></form>"""
    route = scan({"a.php": code})["routes"][0]
    assert set(route["methods"]) == {"GET", "POST"}
    assert {"name": "Submit", "location": "body"} in route["required_params"]
    assert {"name": "mode", "location": "query", "value": "fast"} in route["required_params"]
    assert route["form_fields"][0]["method"] == "POST"
    assert route["form_fields"][0]["fields"][1] == {"name": "Submit", "type": "submit", "value": "Go"}


def test_laravel_routes_controllers_and_blade(scan):
    result = scan({
        "public/index.php": "<?php echo 'boot';",
        "routes/web.php": """<?php
            Route::get('/orders/{id}', [OrderController::class, 'show']);
            Route::prefix('admin')->group(function () { Route::post('/run', 'OrderController@run'); });
        """,
        "app/OrderController.php": """<?php
        class OrderController {
            public function show(Request $request, $id) {
                DB::select(DB::raw('SELECT * FROM o WHERE id = ' . $id));
                $name = $request->input('name');
                return view('orders.show', ['name' => $name, 'ok' => 'x']);
            }
            public function run(Request $request) { return redirect($request->query('next')); }
        }""",
        "resources/views/orders/show.blade.php": "<h1>{{ $name }}</h1>\n<p>{!! $name !!}</p>\n<p>{!! $ok !!}</p>",
    })
    routes = by_path(result)
    assert ("/orders/{id}", None) in routes
    assert routes[("/orders/{id}", None)]["handler"]["function"] == "OrderController::show"
    assert ("/admin/run", None) in routes
    assert open_findings(result, 89)[0]["routes"][0]["path"] == "/orders/{id}"
    assert open_findings(result, 89)[0]["source_params"] == [{"name": "id", "location": "path"}]
    xss = open_findings(result, 79)
    assert len(xss) == 1 and xss[0]["line"] == 2 and xss[0]["file"].endswith("show.blade.php")
    assert open_findings(result, 601)[0]["source_params"][0]["name"] == "next"


def test_plain_router_with_handler_names(scan):
    result = scan({"index.php": """<?php
        $app->get('/ping', 'ping_handler');
        function ping_handler($host) { return shell_exec('ping ' . $host); }
    """})
    found = open_findings(result, 78)
    assert found[0]["routes"][0]["path"] == "/ping"


def test_fingerprint_survives_moved_lines(scan):
    source = "<?php\necho $_GET['a'];\nshell_exec('ls ' . $_GET['b']);\n"
    first = {f["fingerprint"] for f in scan({"a.php": source})["findings"]}
    moved = source.replace("<?php\n", "<?php\n\n// a new comment\n\n")
    second = {f["fingerprint"] for f in scan({"a.php": moved})["findings"]}
    assert first == second and len(first) == 2


def test_rescan_is_identical(scan):
    source = {"a.php": "<?php include 'b.php'; echo $v;", "b.php": "<?php $v = '<p>' . $_GET['a'];"}
    assert scan(source)["findings"] == scan(source)["findings"]


def test_same_sink_text_with_different_queries_are_two_bugs(scan):
    code = """
    if ($_POST['a']) { $sql = 'SELECT 1 WHERE a = ' . $_POST['a']; $r = $db->query($sql); }
    else { $sql = "SELECT 2 WHERE b LIKE '%" . $_POST['b'] . "%'"; $r = $db->query($sql); }
    """
    found = open_findings(scan({"a.php": f"<?php {code}"}), 89)
    assert len(found) == 2
    assert {f["source_params"][0]["name"] for f in found} == {"a", "b"}


def test_two_params_in_one_query_are_one_bug(scan):
    code = "$db->query(\"SELECT 1 WHERE a = '{$_GET['a']}' AND b = '{$_GET['b']}'\");"
    found = open_findings(scan({"a.php": f"<?php {code}"}), 89)
    assert len(found) == 1
    assert {p["name"] for p in found[0]["source_params"]} == {"a", "b"}


def test_shared_helper_is_one_finding_with_every_route(scan):
    result = scan({
        "lib.php": "<?php function go($u) { header('Location: ' . $u); }",
        "a.php": "<?php require 'lib.php'; go($_GET['x']);",
        "b.php": "<?php require 'lib.php'; go($_POST['y']);",
    })
    found = open_findings(result, 601)
    assert len(found) == 1
    assert {r["path"] for r in found[0]["routes"]} == {"/a.php", "/b.php"}
    assert {p["name"] for p in found[0]["source_params"]} == {"x", "y"}


def test_shop_route_map_matches_a_hand_written_list():
    from sast.core.language import ScanOptions
    from sast.lang.php.adapter import PhpAdapter
    expected = {
        "/index.php", "/search.php", "/products.php", "/product.php", "/reviews.php", "/category.php", "/shop.php",
        "/api/orders.php", "/api/convert.php", "/account/orders.php", "/login.php", "/register.php", "/reset.php",
        "/contact.php", "/gallery.php", "/profile.php", "/export.php", "/download.php", "/page.php", "/invoice.php",
        "/attachment.php", "/report.php", "/go.php", "/logout.php", "/lang.php", "/welcome.php", "/cart/checkout.php",
        "/cart/index.php", "/tools/ping.php", "/tools/lookup.php", "/tools/dns.php", "/admin/backup.php",
        "/admin/login.php", "/debug.php",
    }
    result = PhpAdapter().scan(SHOP, ScanOptions(use_semgrep=False))
    assert {r["path"] for r in result.routes} == expected
    assert result.web_root == "app/public"
    assert {r["selector"] for r in result.routes if r["path"] == "/shop.php"} >= {"action=view", "action=track"}
    json.dumps(result.routes)
