"""Flows and protections, one behaviour per test. Each mirrors a real pattern from a benchmark app."""
import pytest

from conftest import open_findings, safe_findings


@pytest.mark.parametrize("cwe,code", [
    (89, "$db->query('SELECT * FROM t WHERE id = ' . $_GET['id']);"),
    (89, "mysqli_query($c, \"SELECT * FROM t WHERE id = '{$_GET['id']}'\");"),
    (79, "echo $_GET['id'];"),
    (79, "print('<b>' . $_GET['id'] . '</b>');"),
    (78, "shell_exec('ping ' . $_GET['id']);"),
    (78, "$out = `ls {$_GET['id']}`;"),
    (22, "readfile('files/' . $_GET['id']);"),
    (22, "include($_GET['id']);"),
    (601, "header('Location: ' . $_GET['id']);"),
    (502, "unserialize($_GET['id']);"),
])
def test_direct_flow_is_found(scan, cwe, code):
    result = scan({"page.php": f"<?php {code}"})
    found = open_findings(result, cwe)
    assert found, code
    assert found[0]["source_params"][0]["name"] == "id"


@pytest.mark.parametrize("cwe,code,reason", [
    (89, "$id = (int) $_GET['id']; $db->query('SELECT * FROM t WHERE id = ' . $id);", "numeric"),
    (89, "$id = intval($_GET['id']); $db->query('SELECT * FROM t WHERE id = ' . $id);", "numeric"),
    (89, "$s = $db->prepare('SELECT 1 WHERE a = ?'); $s->execute([$_GET['id']]);", "bound"),
    (89, "$id = mysqli_real_escape_string($c, $_GET['id']); mysqli_query($c, \"SELECT 1 WHERE a = '$id'\");", "SQL escaping"),
    (79, "echo '<p>' . htmlspecialchars($_GET['id']) . '</p>';", "HTML escaping"),
    (78, "shell_exec('ping ' . escapeshellarg($_GET['id']));", "escapeshellarg"),
    (22, "readfile('files/' . basename($_GET['id']));", "basename"),
    (601, "$to = $_GET['id']; if (!in_array($to, ['/a', '/b'])) { exit; } header('Location: ' . $to);", "allowlist"),
    (601, "header('Location: /fixed/page.php?x=' . $_GET['id']);", "fixed URL"),
])
def test_real_protection_is_marked_safe(scan, cwe, code, reason):
    result = scan({"page.php": f"<?php {code}"})
    assert not open_findings(result, cwe), code
    assert reason in safe_findings(result, cwe)[0]["suppression_reason"]


@pytest.mark.parametrize("cwe,code", [
    (89, "$id = mysqli_real_escape_string($c, $_GET['id']); mysqli_query($c, 'SELECT 1 WHERE a = ' . $id);"),
    (89, "$id = addslashes($_GET['id']); $db->query('SELECT 1 ORDER BY ' . $id);"),
    (89, "$s = $db->prepare('SELECT 1 WHERE a = ' . $_GET['id']); $s->execute();"),
    (79, "$v = htmlspecialchars($_GET['id']); echo '<img src=' . $v . '>';"),
    (79, "$v = htmlspecialchars($_GET['id']); echo '<script>var a = ' . $v . ';</script>';"),
    (79, "$v = htmlspecialchars($_GET['id'], ENT_NOQUOTES); echo \"<input value='\" . $v . \"'>\";"),
    (79, "echo strip_tags($_GET['id']);"),
    (78, "$v = str_replace(';', '', $_GET['id']); system('ping ' . $v);"),
    (22, "$v = str_replace('../', '', $_GET['id']); readfile('files/' . $v);"),
    (601, "$v = $_GET['id']; if (strpos($v, 'site.test') !== false) { header('Location: ' . $v); }"),
    (601, "header('Location: /' . $_GET['id']);"),
])
def test_protection_that_doesnt_fit_stays_open(scan, cwe, code):
    assert open_findings(scan({"page.php": f"<?php {code}"}), cwe), code


def test_check_in_one_branch_doesnt_leak_past_the_if(scan):
    code = "if (is_numeric($_GET['id'])) { echo 'ok'; } echo $_GET['id'];"
    assert open_findings(scan({"page.php": f"<?php {code}"}), 79)


def test_validation_with_early_exit_protects_the_rest(scan):
    code = "$id = $_GET['id']; if (!is_numeric($id)) { die('no'); } echo $id;"
    result = scan({"page.php": f"<?php {code}"})
    assert not open_findings(result, 79)
    assert safe_findings(result, 79)


def test_and_of_not_equal_checks_is_an_allowlist(scan):
    code = "$f = $_GET['f']; if ($f != 'a.php' && $f != 'b.php') { exit; } include($f);"
    assert not open_findings(scan({"page.php": f"<?php {code}"}), 22)


def test_partial_allowlist_stays_open(scan):
    code = "$f = $_GET['f']; if (!fnmatch('file*', $f) && $f != 'a.php') { exit; } include($f);"
    assert open_findings(scan({"page.php": f"<?php {code}"}), 22)


def test_assignment_inside_a_ternary_is_seen(scan):
    code = "$c = true; $c ? $x = $_POST['a'] : $x = $_REQUEST['a']; shell_exec('ls ' . $x);"
    assert open_findings(scan({"page.php": f"<?php {code}"}), 78)


def test_array_plus_merges_instead_of_doing_arithmetic(scan):
    code = "function show($d) { echo $d['n']; }\nshow(['x' => 1] + ['n' => $_GET['n']]);"
    assert open_findings(scan({"page.php": f"<?php {code}"}), 79)
    assert safe_findings(scan({"page.php": "<?php echo 1 + $_GET['n'];"}), 79)


def test_tainted_key_on_a_fixed_map_is_safe(scan):
    code = "$cols = ['n' => 'name', 'p' => 'price']; $c = $cols[$_GET['s']]; $db->query('SELECT 1 ORDER BY ' . $c);"
    assert not open_findings(scan({"page.php": f"<?php {code}"}), 89)


def test_non_html_response_isnt_xss(scan):
    code = "header('Content-Type: application/json'); echo json_encode($_GET['id']);"
    assert not open_findings(scan({"page.php": f"<?php {code}"}), 79)


def test_inline_html_context_is_used(scan):
    code = "<?php $v = htmlspecialchars($_GET['id']); ?><input value=<?= $v ?>>"
    assert open_findings(scan({"page.php": code}), 79)


def test_sink_across_files_with_shared_variables(scan):
    result = scan({
        "index.php": "<?php include 'source.php'; echo $html;",
        "source.php": "<?php $html = '<pre>' . $_GET['name'] . '</pre>';",
    })
    found = open_findings(result, 79)
    assert found[0]["file"] == "source.php", "the fix belongs where the input was added"
    assert found[0]["routes"][0]["path"] == "/index.php"


def test_variable_include_follows_a_switch(scan):
    result = scan({
        "index.php": "<?php $v = ''; switch ($_COOKIE['level']) { case 'a': $v = 'low.php'; break; default: $v = 'safe.php'; }\nrequire_once \"source/{$v}\";",
        "source/low.php": "<?php shell_exec('ls ' . $_GET['x']);",
        "source/safe.php": "<?php shell_exec('ls ' . escapeshellarg($_GET['x']));",
    })
    found = open_findings(result, 78)
    assert [f["file"] for f in found] == ["source/low.php"]
    assert found[0]["conditions"] == ["$v == 'low.php'"]
    assert safe_findings(result, 78)[0]["file"] == "source/safe.php"


def test_wrapper_keeps_the_parameter_name(scan):
    code = "function input($k) { return $_REQUEST[$k]; }\n$q = input('term'); echo $q;"
    assert open_findings(scan({"page.php": f"<?php {code}"}), 79)[0]["source_params"][0]["name"] == "term"


def test_function_and_method_flows(scan):
    code = """
    class Repo {
        private $db;
        public function __construct($db) { $this->db = $db; }
        public function find($id) { return $this->run("SELECT 1 WHERE id = $id"); }
        private function run($sql) { return $this->db->query($sql); }
    }
    $r = new Repo($conn);
    $r->find($_GET['id']);
    """
    found = open_findings(scan({"page.php": f"<?php {code}"}), 89)
    assert found and found[0]["source_params"][0]["name"] == "id"


def test_static_method_and_sanitising_wrapper(scan):
    code = """
    class Html { public static function esc($v) { return htmlspecialchars($v); } }
    echo '<p>' . Html::esc($_GET['a']) . '</p>';
    echo '<p>' . $_GET['b'] . '</p>';
    """
    found = open_findings(scan({"page.php": f"<?php {code}"}), 79)
    assert [p["name"] for f in found for p in f["source_params"]] == ["b"]


def test_extract_into_a_template(scan):
    result = scan({
        "page.php": "<?php function render($t, $vars) { extract($vars); include __DIR__ . \"/views/$t.php\"; }\nrender('home', ['name' => $_GET['n'], 'safe' => 'x']);",
        "views/home.php": "<h1><?= $name ?></h1><p><?= $safe ?></p>",
    })
    found = open_findings(result, 79)
    assert len(found) == 1 and found[0]["file"] == "views/home.php"


def test_extract_of_a_superglobal_taints_unset_variables(scan):
    assert open_findings(scan({"page.php": "<?php extract($_GET); echo $anything;"}), 79)


def test_json_body_names_its_parameter(scan):
    code = "$d = json_decode(file_get_contents('php://input'), true); shell_exec('ls ' . $d['host']);"
    found = open_findings(scan({"page.php": f"<?php {code}"}), 78)
    assert found[0]["source_params"][0] == {"name": "host", "location": "json"}


def test_handler_registered_by_name_treats_parameters_as_input(scan):
    code = "$server->register('lookup');\nfunction lookup($host) { return shell_exec('nslookup ' . $host); }"
    found = open_findings(scan({"svc.php": f"<?php {code}"}), 78)
    assert found and found[0]["confidence"] == "medium"


def test_stored_xss_through_string_query(scan):
    result = scan({
        "add.php": "<?php $m = mysqli_real_escape_string($c, $_POST['msg']); mysqli_query($c, \"INSERT INTO book (m) VALUES ('$m')\");",
        "show.php": "<?php $r = mysqli_query($c, 'SELECT m FROM book'); while ($row = mysqli_fetch_assoc($r)) { echo '<p>' . $row['m'] . '</p>'; }",
    })
    assert not open_findings(result, 89), "the INSERT itself is escaped inside quotes"
    found = open_findings(result, 79)[0]
    assert found["file"] == "show.php"
    assert found["source_params"][0]["name"] == "msg"
    assert found["stored_flow"]["store"] == "db:book"
    assert found["stored_flow"]["write_routes"][0]["path"] == "/add.php"


def test_stored_xss_through_bound_parameters(scan):
    result = scan({
        "add.php": "<?php $s = $pdo->prepare('INSERT INTO notes (body) VALUES (?)'); $s->execute([$_POST['body']]);",
        "show.php": "<?php $s = $pdo->query('SELECT body FROM notes'); foreach ($s->fetchAll() as $n) { echo $n['body']; }",
    })
    assert not open_findings(result, 89)
    assert open_findings(result, 79)[0]["source_params"][0]["name"] == "body"


def test_escaped_on_write_is_safe_on_read(scan):
    result = scan({
        "add.php": "<?php $s = $pdo->prepare('INSERT INTO notes (body) VALUES (?)'); $s->execute([htmlspecialchars($_POST['body'])]);",
        "show.php": "<?php $s = $pdo->query('SELECT body FROM notes'); foreach ($s->fetchAll() as $n) { echo '<p>' . $n['body'] . '</p>'; }",
    })
    assert not open_findings(result, 79)


def test_read_with_no_tainted_write_is_clean(scan):
    code = "$s = $pdo->query('SELECT body FROM notes'); foreach ($s->fetchAll() as $n) { echo $n['body']; }"
    assert not open_findings(scan({"show.php": f"<?php {code}"}), 79)


def test_session_carries_taint_between_pages(scan):
    result = scan({
        "set.php": "<?php $_SESSION['id'] = $_POST['id'];",
        "get.php": "<?php $id = $_SESSION['id']; mysqli_query($c, \"SELECT 1 WHERE a = '$id'\");",
    })
    found = open_findings(result, 89)[0]
    assert found["file"] == "get.php"
    assert found["stored_flow"]["store"] == "session:id"


def test_uncalled_function_is_marked_unreachable(scan):
    result = scan({"lib.php": "<?php function dead() { return shell_exec('ls ' . $_GET['x']); }"})
    assert not open_findings(result, 78)
    assert "no route" in safe_findings(result, 78)[0]["suppression_reason"]


def test_function_named_elsewhere_stays_open_at_low_confidence(scan):
    result = scan({
        "lib.php": "<?php function maybe() { return shell_exec('ls ' . $_GET['x']); }",
        "page.php": "<?php $name = 'may' . 'be'; echo 'maybe';",
    })
    assert open_findings(result, 78)[0]["confidence"] == "low"


def test_weak_hash_on_password_found_however_it_got_there(scan):
    result = scan({"page.php": "<?php $p = $_POST['password']; $h = md5($p); $k = hash('sha1', $_POST['pwd']); $x = md5($_GET['etag']);"})
    assert len(open_findings(result, 327)) == 2


def test_recursion_and_include_cycles_terminate(scan):
    result = scan({
        "a.php": "<?php include 'b.php'; function loop($x) { return loop($x); } echo loop($_GET['x']);",
        "b.php": "<?php include 'a.php';",
    })
    assert result["stats"]["budget_exhausted_entries"] == 0


def test_syntax_error_doesnt_stop_the_scan(scan):
    result = scan({"broken.php": "<?php if ( { echo", "good.php": "<?php echo $_GET['x'];"})
    assert any(f["file"] == "good.php" for f in open_findings(result, 79))


@pytest.mark.parametrize("write", [
    "mysqli_query($c, \"INSERT INTO blog (entry, owner) VALUES ('{$_POST['entry']}', 'bob')\");",
    "$e = $_POST['entry']; mysqli_query($c, \"UPDATE blog SET entry = '$e', owner = 'bob' WHERE id = 1\");",
    "$s = $pdo->prepare('INSERT INTO blog (entry, owner) VALUES (?, ?)'); $s->execute([$_POST['entry'], 'bob']);",
    "$s = $pdo->prepare('INSERT INTO blog (entry, owner) VALUES (:e, :o)'); $s->bindValue(':e', $_POST['entry']); $s->bindValue(':o', 'bob'); $s->execute();",
])
def test_stored_flow_tracks_the_column(scan, write):
    read = "$r = mysqli_query($c, 'SELECT * FROM blog'); while ($row = mysqli_fetch_assoc($r)) { %s }"
    tainted = scan({"add.php": f"<?php {write}", "show.php": "<?php " + read % "echo '<p>' . $row['entry'] . '</p>';"})
    assert open_findings(tainted, 79)[0]["source_params"][0]["name"] == "entry"
    clean = scan({"add.php": f"<?php {write}", "show.php": "<?php " + read % "echo '<p>' . $row['owner'] . '</p>';"})
    assert not open_findings(clean, 79)


def test_stored_flow_read_by_position_could_be_any_column(scan):
    result = scan({
        "add.php": "<?php $s = $pdo->prepare('INSERT INTO blog (entry) VALUES (?)'); $s->execute([$_POST['entry']]);",
        "show.php": "<?php $r = $pdo->query('SELECT * FROM blog'); foreach ($r as $row) { echo $row[0]; }",
    })
    assert open_findings(result, 79)


def test_stored_flow_read_as_object_property(scan):
    result = scan({
        "add.php": "<?php $s = $pdo->prepare('INSERT INTO blog (entry) VALUES (?)'); $s->execute([$_POST['entry']]);",
        "show.php": "<?php $r = $pdo->query('SELECT * FROM blog'); while ($row = $r->fetch_object()) { echo $row->entry; }",
    })
    assert open_findings(result, 79)


def test_unparseable_write_falls_back_to_the_whole_table(scan):
    result = scan({
        "add.php": "<?php mysqli_query($c, 'INSERT INTO blog VALUES (' . $_POST['entry'] . ')');",
        "show.php": "<?php $r = mysqli_query($c, 'SELECT * FROM blog'); while ($row = mysqli_fetch_assoc($r)) { echo $row['anything']; }",
    })
    assert open_findings(result, 79)


@pytest.mark.parametrize("markup,dangerous", [
    ("<a href='%s'>", True),
    ("<form action=\"%s\">", True),
    ("<iframe src='%s'>", True),
    ("<img src='%s'>", False),
    ("<a href='/page?x=%s'>", False),
    ("<input value='%s'>", False),
])
def test_escaping_inside_url_attributes(scan, markup, dangerous):
    before, after = markup.split("%s")
    code = f"$v = htmlspecialchars($_GET['a']); echo {before!r} . $v . {after!r};"
    assert bool(open_findings(scan({"page.php": f"<?php {code}"}), 79)) is dangerous


def test_buffered_output_ranks_lower(scan):
    code = "function dump($d) { ob_start(); var_dump($d); return ob_get_clean(); } $s = dump($_GET['a']);"
    assert open_findings(scan({"page.php": f"<?php {code}"}), 79)[0]["confidence"] != "high"
