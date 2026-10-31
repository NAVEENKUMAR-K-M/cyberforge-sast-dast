"""Laravel conventions: how routes are declared and mounted, Blade, and the DB facade."""
from conftest import open_findings, safe_findings

ROUTES = """<?php
use App\\Http\\Controllers\\ShopController;
use Illuminate\\Support\\Facades\\Route;
Route::get('/search', [ShopController::class, 'search']);
Route::match(['get', 'post'], '/tools/ping', [ShopController::class, 'ping']);
Route::any('/any', [ShopController::class, 'anything']);
Route::get('/items/{id}', [ShopController::class, 'show'])->whereNumber('id');
Route::get('/names/{name}', [ShopController::class, 'named'])->where('name', '[A-Za-z]+');
Route::get('/plain/{id}', [ShopController::class, 'plain']);
"""

CONTROLLER = """<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\DB;
class ShopController extends Controller {
    public function search(Request $request) { return view('s', ['q' => $request->input('q')]); }
    public function ping(Request $request) { return shell_exec('ping ' . $request->input('host')); }
    public function anything(Request $request) { return 'x'; }
    public function show($id) { return DB::select('SELECT * FROM items WHERE id = ' . $id); }
    public function named($name) { return DB::select("SELECT * FROM n WHERE name = '" . $name . "'"); }
    public function plain($id) { return DB::select('SELECT * FROM p WHERE id = ' . $id); }
}
"""


def laravel(scan, extra=None, **options):
    files = {"routes/web.php": ROUTES, "app/Http/Controllers/ShopController.php": CONTROLLER}
    files.update(extra or {})
    return scan(files, **options)


def test_route_match_declares_the_methods_it_lists(scan):
    result = laravel(scan)
    ping = next(r for r in result["routes"] if r["path"] == "/tools/ping")
    assert ping["methods"] == ["GET", "POST"] and ping["handler"]["function"] == "ShopController::ping"
    assert [f["routes"][0]["path"] for f in open_findings(result, 78)] == ["/tools/ping"]


def test_route_files_are_not_pages(scan):
    result = laravel(scan, {"bootstrap/app.php": "<?php\nreturn Application::configure();\n"})
    paths = {r["path"] for r in result["routes"]}
    assert not paths & {"/web.php", "/api.php", "/app.php"}


def test_routes_in_routes_api_are_mounted_under_api(scan):
    result = scan({
        "routes/api.php": "<?php\nRoute::get('/orders', [OrderController::class, 'index']);\n",
        "app/Http/Controllers/OrderController.php": "<?php\nclass OrderController { public function index(Request $r) { return DB::select(\"SELECT * FROM o WHERE c = '\" . $r->query('c') . \"'\"); } }\n",
    })
    assert [r["path"] for r in result["routes"]] == ["/api/orders"]
    assert [f["routes"][0]["path"] for f in open_findings(result, 89)] == ["/api/orders"]


def test_route_constraints_limit_what_reaches_the_handler(scan):
    result = laravel(scan)
    open_routes = {f["routes"][0]["path"] for f in open_findings(result, 89)}
    assert open_routes == {"/plain/{id}"}  # whereNumber and a letters-only where() cannot be injected
    safe = {f["routes"][0]["path"]: f["suppression_reason"] for f in safe_findings(result, 89)}
    assert safe["/items/{id}"] == "numeric cast or validation"
    typed = {p["name"]: p.get("type") for r in result["routes"] for p in r["params"] if r["path"] == "/items/{id}"}
    assert typed == {"id": "validated"}


def test_download_and_file_responses_are_path_sinks(scan):
    result = scan({
        "routes/web.php": "<?php\nRoute::get('/d', [FileController::class, 'get']);\n",
        "app/Http/Controllers/FileController.php": "<?php\nclass FileController { public function get(Request $r) { return response()->download(storage_path('app/' . $r->query('f'))); } }\n",
    })
    found = open_findings(result, 22)
    assert [f["routes"][0]["path"] for f in found] == ["/d"] and found[0]["source_params"][0]["name"] == "f"
    assert open_findings(result, 89) == []  # not mistaken for a query


def test_blade_foreach_makes_the_collection_the_unescaped_value(scan):
    result = scan({
        "routes/web.php": "<?php\nRoute::get('/p', [PostController::class, 'show']);\nRoute::post('/p', [PostController::class, 'store']);\n",
        "app/Http/Controllers/PostController.php": """<?php
class PostController {
    public function store(Request $r) { DB::insert('INSERT INTO posts (body) VALUES (?)', [$r->input('body')]); return 'ok'; }
    public function show() { $posts = DB::select('SELECT body FROM posts'); return view('p', ['posts' => $posts]); }
}
""",
        "resources/views/p.blade.php": "@foreach ($posts as $post)\n<li>{!! $post->body !!}</li>\n@endforeach\n<p>{{ $title }}</p>\n",
    })
    found = open_findings(result, 79)
    assert len(found) == 1 and found[0]["file"] == "resources/views/p.blade.php"
    assert found[0]["stored_flow"]["store"].endswith("posts")
    assert [r["path"] for r in found[0]["stored_flow"]["write_routes"]] == ["/p"]  # GET and POST on one path are one route


def test_a_query_result_is_not_read_as_a_second_query(scan):
    result = scan({
        "routes/api.php": "<?php\nRoute::get('/o', [OrderController::class, 'index']);\nRoute::post('/o', [OrderController::class, 'store']);\n",
        "app/Http/Controllers/OrderController.php": """<?php
class OrderController {
    public function store(Request $r) { DB::insert('INSERT INTO orders (c) VALUES (?)', [$r->input('c')]); return 'ok'; }
    public function index() { return response()->json(DB::select('SELECT * FROM orders')); }
}
""",
    })
    assert open_findings(result, 89) == []  # the stored value is bound on the way in and never built into SQL


def test_framework_defaults_are_not_secrets(scan):
    result = scan({
        "config/auth.php": "<?php\nreturn ['passwords' => env('AUTH_PASSWORD_BROKER', 'users'), 'table' => env('AUTH_PASSWORD_RESET_TOKEN_TABLE', 'password_reset_tokens')];\n",
        "app/Models/User.php": "<?php\nclass User { protected function casts(): array { return ['email_verified_at' => 'datetime', 'password' => 'hashed']; } }\n",
        "config/shop.php": "<?php\nreturn ['payment_secret' => 'demo_payment_key_for_testing'];\n",
    }, semgrep=True)
    assert [f["file"] for f in open_findings(result, 798)] == ["config/shop.php"]
