import pytest
from helpers import write

from sca.phpindex import Index

LIB = {
    "lib/src/Base.php": """<?php
namespace Lib;
class Base {
    public function run() { return $this->step(); }
    public function step() { return Helper::go(); }
}
""",
    "lib/src/Child.php": """<?php
namespace Lib;
class Child extends Base {
    public function step() { return 1; }
}
""",
    "lib/src/Helper.php": """<?php
namespace Lib;
use function Lib\\fmt;
class Helper {
    public static function go() { return fmt('x'); }
    public function make(): Base { return new Base(); }
}
function fmt($s) { return $s; }
""",
}


@pytest.fixture
def index(tmp_path):
    for rel, text in LIB.items():
        write(str(tmp_path), rel, text)
    idx = Index(str(tmp_path))
    idx.add_tree(str(tmp_path / "lib"), "lib/lib", "lib")
    idx.prefixes.append(("lib\\", "lib/lib"))
    return idx


def app(tmp_path, index, code):
    write(str(tmp_path), "app/index.php", "<?php\nuse Lib\\Base;\nuse Lib\\Helper;\n" + code)
    index.add_file(str(tmp_path / "app/index.php"), "app/index.php", "<root>")
    return index.files["app/index.php"]["top"]


def sites(index, fn, this=None):
    return {s.text: s for s in index.calls(fn, this)}


def test_new_runs_the_constructor_and_this_is_exact(tmp_path, index):
    top = app(tmp_path, index, "$b = new Base(); $b->run();")
    run = sites(index, top)["$b->run()"]
    assert run.exact and [t.label for t, _ in run.targets] == ["Lib\\Base::run"]
    base_run = index.funcs["lib\\base::run"]
    step = sites(index, base_run, "Lib\\Base")["$this->step()"]
    assert step.exact and [t.label for t, _ in step.targets] == ["Lib\\Base::step"]


def test_this_without_a_known_class_includes_overrides_as_candidates(index):
    step = sites(index, index.funcs["lib\\base::run"], None)["$this->step()"]
    assert not step.exact and {t.label for t, _ in step.targets} == {"Lib\\Base::step", "Lib\\Child::step"}


def test_a_typed_parameter_counts_every_override(tmp_path, index):
    write(str(tmp_path), "app/f.php", "<?php\nuse Lib\\Base;\nfunction handle(Base $b) { $b->step(); }\n")
    index.add_file(str(tmp_path / "app/f.php"), "app/f.php", "<root>")
    site = sites(index, index.funcs["handle"])["$b->step()"]
    assert not site.exact and site.how == "typed receiver" and len(site.targets) == 2


def test_static_and_namespaced_function_calls_resolve(index):
    go = sites(index, index.funcs["lib\\base::step"])["Helper::go()"]
    assert go.exact and go.targets[0][0].label == "Lib\\Helper::go"
    fmt = sites(index, index.funcs["lib\\helper::go"])["fmt('x')"]
    assert fmt.exact and fmt.targets[0][0].label == "Lib\\fmt"


def test_return_types_type_the_receiver(tmp_path, index):
    top = app(tmp_path, index, "$h = new Helper(); $x = $h->make(); $x->run();")
    site = sites(index, top)["$x->run()"]
    assert site.how == "typed receiver" and {t.label for t, _ in site.targets} == {"Lib\\Base::run"}


def test_dynamic_method_on_a_known_class_is_a_candidate_set(tmp_path, index):
    top = app(tmp_path, index, "$b = new Base(); $m = $_GET['m']; $b->$m();")
    site = sites(index, top)["$b->$m()"]
    assert not site.exact and site.unresolved is None and {t.name for t, _ in site.targets} == {"run", "step"}


def test_an_unknown_receiver_is_resolved_by_method_name_only(tmp_path, index):
    top = app(tmp_path, index, "$x = $GLOBALS['thing']; $x->step();")
    site = sites(index, top)["$x->step()"]
    assert not site.exact and len(site.targets) == 2


@pytest.mark.parametrize("code,text", [
    ("$f = $_GET['f']; $f();", "$f()"),
    ("call_user_func($_GET['f']);", "call_user_func($_GET['f'])"),
    ("$c = $_GET['c']; new $c();", "new $c()"),
    ("include $_GET['page'];", "include $_GET['page']"),
])
def test_unresolvable_calls_are_kept_as_unresolved(tmp_path, index, code, text):
    site = sites(index, app(tmp_path, index, code))[text]
    assert site.unresolved == "any" and not site.exact


def test_a_data_argument_of_array_map_is_not_a_callable(tmp_path, index):
    top = app(tmp_path, index, "$items = $_GET['i']; array_map('trim', $items);")
    assert all(s.unresolved is None for s in index.calls(top, None))


def test_literal_callables_resolve_as_candidates(tmp_path, index):
    top = app(tmp_path, index, "call_user_func('Lib\\\\Helper::go'); call_user_func([Helper::class, 'go']);")
    found = [s for s in index.calls(top, None) if s.how.startswith("callable")]
    assert all(not s.exact and s.targets[0][0].label == "Lib\\Helper::go" for s in found) and len(found) == 2


def test_a_class_missing_from_a_packages_source_is_unresolved_for_that_package(tmp_path, index):
    site = sites(index, app(tmp_path, index, "$x = new \\Lib\\Gone();"))["new \\Lib\\Gone()"]
    assert site.unresolved == "missing:lib/lib"


def test_closures_are_their_own_candidate_functions(tmp_path, index):
    top = app(tmp_path, index, "$cb = function () { Helper::go(); }; $cb();")
    closure = [s for s in index.calls(top, None) if s.how.startswith("closure")]
    assert len(closure) == 1 and not closure[0].exact
    inner = closure[0].targets[0][0]
    assert [s.text for s in index.calls(inner, None)] == ["Helper::go()"]
    assert all(s.unresolved is None for s in index.calls(top, None))    # $cb() calls the closure it was given


def test_functions_declared_under_a_condition_are_candidates(tmp_path):
    write(str(tmp_path), "lib/f.php", "<?php\nif (!function_exists('poly')) { function poly() {} }\n")
    write(str(tmp_path), "app.php", "<?php\npoly();\n")
    idx = Index(str(tmp_path))
    idx.add_file(str(tmp_path / "lib/f.php"), "lib/f.php", "x/poly")
    idx.add_file(str(tmp_path / "app.php"), "app.php", "<root>")
    site = idx.calls(idx.files["app.php"]["top"], None)[0]
    assert site.targets[0][0].label == "poly" and not site.exact


def test_literal_includes_and_the_autoloader(tmp_path, index):
    write(str(tmp_path), "app/lib.php", "<?php\nfunction helper() {}\n")
    index.add_file(str(tmp_path / "app/lib.php"), "app/lib.php", "<root>")
    top = app(tmp_path, index, "require __DIR__ . '/lib.php';\nrequire dirname(__DIR__) . '/vendor/autoload.php';")
    hows = {s.how: s for s in index.calls(top, None)}
    assert hows["include"].targets[0][0].key == "file:app/lib.php" and hows["autoload"].exact


def test_typed_properties_and_constructor_assignments_type_receivers(tmp_path, index):
    write(str(tmp_path), "app/S.php", """<?php
use Lib\\Base;
class Service {
    private Base $typed;
    private $made;
    public function __construct(Base $typed) { $this->typed = $typed; $this->made = new Base(); }
    public function go() { $this->typed->run(); $this->made->run(); }
}
""")
    index.add_file(str(tmp_path / "app/S.php"), "app/S.php", "<root>")
    found = sites(index, index.funcs["service::go"])
    assert found["$this->made->run()"].exact
    assert found["$this->typed->run()"].how == "typed receiver"


def test_group_use_and_aliases_resolve(tmp_path, index):
    write(str(tmp_path), "app/g.php", "<?php\nuse Lib\\{Helper as H, Base};\nH::go(); new Base();\n")
    index.add_file(str(tmp_path / "app/g.php"), "app/g.php", "<root>")
    labels = [s.targets[0][0].label for s in index.calls(index.files["app/g.php"]["top"], None) if s.targets]
    assert labels == ["Lib\\Helper::go"]       # Base has no constructor, so `new Base()` calls nothing
    assert "Lib\\Base" in index.references(index.files["app/g.php"]["top"])
