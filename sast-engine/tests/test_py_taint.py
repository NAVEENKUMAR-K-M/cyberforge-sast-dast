"""The Python taint analysis: what it reports, what it clears, and what it must not clear."""
import textwrap

import pytest

from conftest import open_findings, safe_findings

HEADER = """\
import os, re, sqlite3, subprocess, shlex, html, pickle, yaml
from urllib.parse import urlparse
from flask import Flask, request, redirect, jsonify, render_template_string, send_file, abort, url_for, make_response
from werkzeug.utils import secure_filename
from markupsafe import escape

app = Flask(__name__)
db = sqlite3.connect("shop.db")
BASE = "/srv/files"
ALLOWED_COLUMNS = ("name", "price")
"""


def sources(files):
    """The test files, with the indentation of their triple-quoted strings removed."""
    return {name: textwrap.dedent(body) for name, body in files.items()}


def app_with(body):
    return {"app.py": HEADER + "\n@app.route('/x', methods=['GET', 'POST'])\ndef handler():\n" + textwrap.indent(textwrap.dedent(body), "    ")}


def kinds(result, cwe):
    return len(open_findings(result, cwe)), len(safe_findings(result, cwe))


SQLI_OPEN = {
    "fstring": """
        q = request.args.get("q")
        db.cursor().execute(f"SELECT * FROM items WHERE name = '{q}'")
        return "ok"
    """,
    "concat": """
        q = request.args["q"]
        db.execute("SELECT * FROM items WHERE name = '" + q + "'")
        return "ok"
    """,
    "percent": """
        q = request.form["q"]
        db.execute("SELECT * FROM items WHERE name = '%s'" % q)
        return "ok"
    """,
    "format": """
        q = request.values.get("q")
        db.execute("SELECT * FROM items WHERE name = '{}'".format(q))
        return "ok"
    """,
    "json_body": """
        data = request.get_json()
        db.execute(f"SELECT * FROM items WHERE name = '{data['name']}'")
        return "ok"
    """,
    "through_a_variable": """
        q = request.args.get("q", "")
        where = "name = '" + q + "'"
        sql = "SELECT * FROM items WHERE " + where
        cur = db.cursor()
        cur.execute(sql)
        return "ok"
    """,
    "replace_is_not_a_fix": """
        q = request.args.get("q", "").replace("'", "")
        db.execute(f"SELECT * FROM items WHERE name = {q}")
        return "ok"
    """,
}


@pytest.mark.parametrize("name", SQLI_OPEN)
def test_sql_injection_is_reported(py_scan, name):
    result = py_scan(app_with(SQLI_OPEN[name]))
    found = open_findings(result, 89)
    assert len(found) == 1, result["findings"]
    assert found[0]["routes"][0]["path"] == "/x"
    assert found[0]["source_params"][0]["name"] in ("q", "name")


SQLI_SAFE = {
    "bound_tuple": ("""
        q = request.args.get("q")
        db.execute("SELECT * FROM items WHERE name = ?", (q,))
        return "ok"
    """, None),
    "bound_percent_style": ("""
        q = request.args.get("q")
        db.cursor().execute("SELECT * FROM items WHERE name = %s", [q])
        return "ok"
    """, None),
    "int_cast": ("""
        item = int(request.args["id"])
        db.execute(f"SELECT * FROM items WHERE id = {item}")
        return "ok"
    """, "numeric cast or validation"),
    "type_int": ("""
        item = request.args.get("id", type=int)
        db.execute(f"SELECT * FROM items WHERE id = {item}")
        return "ok"
    """, "numeric cast or validation"),
    "column_allowlist": ("""
        col = request.args.get("sort")
        if col not in ALLOWED_COLUMNS:
            abort(400)
        db.execute(f"SELECT * FROM items ORDER BY {col}")
        return "ok"
    """, "value checked against an allowlist"),
    "isdigit_guard": ("""
        item = request.args.get("id")
        if not item.isdigit():
            return "bad", 400
        db.execute("SELECT * FROM items WHERE id = " + item)
        return "ok"
    """, "numeric cast or validation"),
    "dict_lookup": ("""
        order = {"a": "name", "b": "price"}.get(request.args.get("o"), "name")
        db.execute(f"SELECT * FROM items ORDER BY {order}")
        return "ok"
    """, None),
}


@pytest.mark.parametrize("name", SQLI_SAFE)
def test_sql_injection_is_cleared_when_protected(py_scan, name):
    body, reason = SQLI_SAFE[name]
    result = py_scan(app_with(body))
    assert open_findings(result, 89) == [], result["findings"]
    if reason:
        assert [f["suppression_reason"] for f in safe_findings(result, 89)] == [reason]


XSS_OPEN = {
    "concat": """
        return "<h1>Hello " + request.args.get("name", "") + "</h1>"
    """,
    "fstring": """
        name = request.args["name"]
        return f"<p>{name}</p>"
    """,
    "tuple_with_status": """
        return f"<p>{request.args['name']}</p>", 200
    """,
    "template_string": """
        return render_template_string("<p>" + request.args["name"] + "</p>")
    """,
    "escape_does_not_fit_a_script": """
        n = html.escape(request.args["name"])
        return f"<script>var name = '{n}';</script>"
    """,
    "unquoted_attribute": """
        n = html.escape(request.args["name"])
        return f"<input value={n}>"
    """,
    "quote_false_in_attribute": """
        n = html.escape(request.args["name"], quote=False)
        return f'<input value="{n}">'
    """,
    "response_object": """
        return make_response("<b>" + request.args["name"] + "</b>")
    """,
}


@pytest.mark.parametrize("name", XSS_OPEN)
def test_xss_is_reported(py_scan, name):
    result = py_scan(app_with(XSS_OPEN[name]))
    assert len(open_findings(result, 79)) == 1, result["findings"]


XSS_SAFE = {
    "html_escape": 'return "<p>" + html.escape(request.args["name"]) + "</p>"',
    "markupsafe_escape": 'return f"<p>{escape(request.args[\'name\'])}</p>"',
    "jsonify": 'return jsonify({"name": request.args["name"]})',
    "dict_return": 'return {"name": request.args["name"]}',
    "json_mimetype": 'return make_response(request.args["name"], 200, {"Content-Type": "application/json"})',
    "int_value": 'return f"<p>{int(request.args[\'n\'])}</p>"',
    "plain_literal": 'return "<p>static</p>"',
}


@pytest.mark.parametrize("name", XSS_SAFE)
def test_xss_is_not_reported_when_output_is_safe(py_scan, name):
    result = py_scan(app_with(XSS_SAFE[name]))
    assert open_findings(result, 79) == [], result["findings"]


CMD = {
    "os_system": ('os.system("ping -c 1 " + request.args["host"])\nreturn "ok"', True),
    "shell_true": ('subprocess.run(f"ping -c 1 {request.args[\'host\']}", shell=True)\nreturn "ok"', True),
    "popen": ('out = os.popen("nslookup " + request.form["d"]).read()\nreturn "ok"', True),
    "check_output_shell": ('subprocess.check_output("ls " + request.args["d"], shell=True)\nreturn "ok"', True),
    "list_form": ('subprocess.run(["ping", "-c", "1", request.args["host"]])\nreturn "ok"', False),
    "split_no_shell": ('subprocess.run(("ping -c 1 " + request.args["host"]).split())\nreturn "ok"', False),
    "shlex_quote": ('subprocess.run("ping -c 1 " + shlex.quote(request.args["host"]), shell=True)\nreturn "ok"', False),
    "list_with_user_program": ('subprocess.run([request.args["bin"], "--version"])\nreturn "ok"', True),
}


@pytest.mark.parametrize("name", CMD)
def test_command_injection(py_scan, name):
    body, vulnerable = CMD[name]
    result = py_scan(app_with(body))
    assert (len(open_findings(result, 78)) == 1) == vulnerable, result["findings"]


PATHS = {
    "open_concat": ('with open(BASE + "/" + request.args["f"]) as fh:\n    data = fh.read()\nreturn "ok"', True),
    "send_file": ('return send_file(request.args["f"])', True),
    "os_path_join": ('return send_file(os.path.join(BASE, request.args["f"]))', True),
    "listdir": ('return str(os.listdir(request.args["d"]))', True),
    "secure_filename": ('return send_file(os.path.join(BASE, secure_filename(request.args["f"])))', False),
    "basename": ('open(os.path.join(BASE, os.path.basename(request.args["f"])))\nreturn "ok"', False),
    "realpath_prefix_check": ("""
        full = os.path.realpath(os.path.join(BASE, request.args["f"]))
        if not full.startswith(BASE):
            abort(403)
        return send_file(full)
    """, False),
    "dotdot_blacklist_is_not_enough": ("""
        name = request.args["f"]
        if ".." in name:
            abort(400)
        return send_file(os.path.join(BASE, name))
    """, True),
    "startswith_without_realpath_is_not_enough": ("""
        full = os.path.join(BASE, request.args["f"])
        if not full.startswith(BASE):
            abort(403)
        return send_file(full)
    """, True),
}


@pytest.mark.parametrize("name", PATHS)
def test_path_traversal(py_scan, name):
    body, vulnerable = PATHS[name]
    result = py_scan(app_with(body))
    assert (len(open_findings(result, 22)) == 1) == vulnerable, result["findings"]


REDIRECTS = {
    "plain": ('return redirect(request.args["next"])', True),
    "with_default": ('return redirect(request.args.get("next") or "/")', True),
    "slash_prefix_is_open": ('return redirect("/" + request.args["next"])', True),
    "host_prefix_fixed": ('return redirect("https://example.com/" + request.args["next"])', False),
    "path_prefix_fixed": ('return redirect("/account/" + request.args["next"])', False),
    "allowlist": ("""
        target = request.args.get("next")
        if target not in ("/home", "/cart"):
            abort(400)
        return redirect(target)
    """, False),
    "url_for": ('return redirect(url_for("index"))', False),
}


@pytest.mark.parametrize("name", REDIRECTS)
def test_open_redirect(py_scan, name):
    body, vulnerable = REDIRECTS[name]
    result = py_scan(app_with(body))
    assert (len(open_findings(result, 601)) == 1) == vulnerable, result["findings"]


def test_deserialization_and_eval(py_scan):
    result = py_scan(app_with("""
        a = pickle.loads(request.get_data())
        b = yaml.load(request.form["y"])
        c = yaml.safe_load(request.form["y"])
        d = eval(request.args["expr"])
        return "ok"
    """))
    assert len(open_findings(result, 502)) == 2
    assert len(open_findings(result, 94)) == 1


def test_flow_through_project_functions_and_methods(py_scan):
    result = py_scan(sources({
        "repo.py": """
            import sqlite3
            class OrderRepo:
                def __init__(self, conn):
                    self.conn = conn
                def find(self, name):
                    return self.conn.execute(f"SELECT * FROM orders WHERE name = '{name}'").fetchall()
                def by_id(self, order_id):
                    return self.conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchall()
        """,
        "views.py": """
            import sqlite3
            from flask import Flask, request
            from repo import OrderRepo
            app = Flask(__name__)
            repo = OrderRepo(sqlite3.connect("x.db"))

            def clean(value):
                return value.strip()

            @app.route("/orders")
            def orders():
                return str(repo.find(clean(request.args.get("name"))))

            @app.route("/orders/<int:order_id>")
            def one(order_id):
                return str(repo.by_id(order_id))
        """,
    }))
    found = open_findings(result, 89)
    assert len(found) == 1
    assert found[0]["file"] == "repo.py" and found[0]["function"] == "OrderRepo.find"
    assert [r["path"] for r in found[0]["routes"]] == ["/orders"]
    assert [p["name"] for p in found[0]["source_params"]] == ["name"]


def test_stored_cross_site_scripting(py_scan):
    result = py_scan(sources({"app.py": """
        import sqlite3
        from flask import Flask, request
        app = Flask(__name__)
        db = sqlite3.connect("x.db")

        @app.route("/comment", methods=["POST"])
        def add():
            db.execute("INSERT INTO comments (body) VALUES (?)", (request.form["body"],))
            return "saved"

        @app.route("/comments")
        def show():
            rows = db.execute("SELECT body FROM comments").fetchall()
            return "<ul>" + "".join("<li>" + row[0] + "</li>" for row in rows) + "</ul>"
    """}))
    found = open_findings(result, 79)
    assert len(found) == 1
    flow = found[0]["stored_flow"]
    assert flow["store"] == "comments"
    assert [r["path"] for r in flow["write_routes"]] == ["/comment"]
    assert [r["path"] for r in found[0]["routes"]] == ["/comments"]


def test_fastapi_handlers(py_scan):
    result = py_scan(sources({"main.py": """
        import sqlite3
        from fastapi import FastAPI, Header
        from fastapi.responses import HTMLResponse
        from pydantic import BaseModel

        app = FastAPI()
        db = sqlite3.connect("x.db")

        class Search(BaseModel):
            term: str
            limit: int = 10

        @app.post("/search")
        def search(body: Search):
            db.execute(f"SELECT * FROM t WHERE x LIKE '%{body.term}%' LIMIT {body.limit}")
            return {"ok": True}

        @app.get("/items/{item_id}")
        def item(item_id: int, q: str = ""):
            db.execute(f"SELECT * FROM t WHERE id = {item_id} AND name = '{q}'")
            return {"ok": True}

        @app.get("/hello", response_class=HTMLResponse)
        def hello(name: str):
            return f"<h1>{name}</h1>"

        @app.get("/plain")
        def plain(name: str):
            return f"<h1>{name}</h1>"
    """}))
    sql = {(f["routes"][0]["path"], f["source_params"][0]["name"]) for f in open_findings(result, 89)}
    assert sql == {("/search", "term"), ("/items/{item_id}", "q")}
    # `limit` and `item_id` are parsed as integers before the handler runs. They share a query with an input that
    # can do harm, so the finding names only that input.
    assert not [f for f in open_findings(result, 89) if {p["name"] for p in f["source_params"]} & {"limit", "item_id"}]
    xss = open_findings(result, 79)
    assert [f["routes"][0]["path"] for f in xss] == ["/hello"]  # a plain str return is JSON in FastAPI


def test_code_nothing_calls_is_marked_unreachable(py_scan):
    result = py_scan(sources({"app.py": """
        import os
        from flask import request
        def never_used():
            os.system("echo " + request.args["x"])
    """}))
    assert open_findings(result, 78) == []
    assert [f["suppression_reason"] for f in safe_findings(result, 78)] == ["no route can reach this code"]


def test_output_is_deterministic(py_scan, tmp_path):
    first = py_scan(app_with(SQLI_OPEN["through_a_variable"]))
    second = py_scan(app_with(SQLI_OPEN["through_a_variable"]))
    first["stats"].pop("seconds"), second["stats"].pop("seconds")
    assert first == second


# ---- pattern rules (need Semgrep) ----------------------------------------------------------------------------------

semgrep_missing = pytest.mark.skipif(__import__("sast.semgrep_runner", fromlist=["x"])._binary() is None, reason="semgrep isn't installed")


@semgrep_missing
def test_secrets_and_weak_crypto_are_found(py_scan):
    result = py_scan(sources({"app.py": """
        import hashlib, os, random
        from flask import Flask
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "s3cr3t-signing-key-123"
        DB_URL = "postgresql://shop:hunter2pass@db.internal/shop"
        API_PASSWORD = "Tr0ub4dor&3xyz"
        PLACEHOLDER_PASSWORD = "your-password-here"
        TOKEN = os.environ.get("API_TOKEN", "fallback-token-abc123")
        EMPTY_SECRET = ""

        def make_token():
            reset_token = str(random.randint(1000, 9999))
            return reset_token

        def store(password):
            return hashlib.md5(password.encode()).hexdigest()

        if __name__ == "__main__":
            app.run(debug=True)
    """}), semgrep=True)
    assert result["stats"]["semgrep_error"] is None
    by_cwe = {}
    for f in open_findings(result):
        by_cwe.setdefault(f["cwe_family"], []).append(f["line"])
    assert sorted(by_cwe["CWE-798"]) == [5, 6, 7, 9]  # config key, URL, literal password, env fallback
    assert 12 in by_cwe["CWE-330"] or 13 in by_cwe["CWE-330"]
    assert by_cwe["CWE-327"] == [17]
    assert by_cwe["CWE-489"] == [20]


@semgrep_missing
def test_secrets_in_config_files(py_scan):
    result = py_scan({".env": "DB_PASSWORD=Sup3rSecretValue99\nDEBUG=true\n", "app.py": "x = 1\n"}, semgrep=False)
    assert [f["file"] for f in open_findings(result, 798)] == [".env"]


def test_routes_list_the_parameters_the_code_reads(py_scan):
    result = py_scan(sources({"app.py": """
        from flask import Flask, request, jsonify
        app = Flask(__name__)

        @app.route("/items/<int:item_id>", methods=["GET", "POST"])
        def items(item_id):
            q = request.args.get("q", "")
            name = request.form["name"]
            token = request.headers.get("X-Token")
            data = request.get_json(silent=True) or {}
            qty = data.get("qty")
            return jsonify(q=q, name=name, token=token, qty=qty)
    """}))
    route = result["routes"][0]
    params = {(p["name"], p["location"]) for p in route["params"]}
    assert params == {("item_id", "path"), ("q", "query"), ("name", "body"), ("X-Token", "header"), ("qty", "json")}
    required = {(p["name"], p["location"]) for p in route["required_params"]}
    assert required == {("item_id", "path"), ("name", "body")}  # a subscript has to be there; .get() may be missing


# ---- Jinja templates, framework callbacks, responses built in steps --------------------------------------------------

def test_a_template_that_prints_unescaped_makes_the_value_a_sink(py_scan):
    result = py_scan(sources({
        "app.py": """
            import sqlite3
            from flask import Flask, request, render_template
            app = Flask(__name__)
            db = sqlite3.connect("x.db")

            @app.route("/post", methods=["POST"])
            def add():
                db.execute("INSERT INTO posts (text) VALUES (?)", (request.form["text"],))
                return "ok"

            @app.route("/posts")
            def show():
                rows = db.execute("SELECT text FROM posts").fetchall()
                posts = [dict(zip(["text"], row)) for row in rows]
                return render_template("posts.html", posts=posts, title=request.args.get("t"))
        """,
        "templates/posts.html": "<h1>{{ title }}</h1>{% for post in posts %}<li>{{ post.text | safe }}</li>{% endfor %}",
    }))
    found = open_findings(result, 79)
    assert len(found) == 1                                  # the escaped `title` is not a finding
    assert found[0]["stored_flow"]["store"] == "posts"
    assert [r["path"] for r in found[0]["stored_flow"]["write_routes"]] == ["/post"]


def test_autoescape_off_and_included_templates(py_scan):
    result = py_scan(sources({
        "app.py": """
            from flask import Flask, request, render_template
            app = Flask(__name__)

            @app.route("/a")
            def a():
                return render_template("a.html", note=request.args["note"], name=request.args["name"])
        """,
        "templates/a.html": "{% include 'part.html' %}<p>{{ name }}</p>",
        "templates/part.html": "{% autoescape false %}<b>{{ note }}</b>{% endautoescape %}",
    }))
    found = open_findings(result, 79)
    assert [p["name"] for f in found for p in f["source_params"]] == ["note"]


def test_a_function_the_framework_calls_is_not_dead_code(py_scan):
    result = py_scan(sources({"app.py": """
        from flask import Flask, request, render_template_string
        app = Flask(__name__)

        @app.errorhandler(404)
        def not_found(e):
            return render_template_string("<h3>" + request.url + "</h3>"), 404
    """}))
    assert len(open_findings(result, 79)) == 1


def test_a_response_whose_type_is_set_afterwards_is_not_a_page(py_scan):
    result = py_scan(sources({"app.py": """
        import json
        from flask import Flask, request, Response
        app = Flask(__name__)

        @app.route("/login", methods=["POST"])
        def login():
            name = request.json["username"]
            resp = Response(json.dumps({"user": name}))
            resp.mimetype = "application/json"
            return resp

        @app.route("/other", methods=["POST"])
        def other():
            name = request.json["username"]
            resp = Response(json.dumps({"user": name}))
            resp.headers["Content-Type"] = "application/json"
            return resp

        @app.route("/page", methods=["POST"])
        def page():
            return Response("<p>" + request.json["username"] + "</p>")
    """}))
    assert [f["routes"][0]["path"] for f in open_findings(result, 79)] == ["/page"]


def test_a_method_called_through_its_class_is_a_plain_function(py_scan):
    result = py_scan(sources({"app.py": """
        import sqlite3
        from flask import Flask
        app = Flask(__name__)
        db = sqlite3.connect("x.db")

        class User:
            def get_user(username):
                return db.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()

        @app.route("/users/<username>")
        def show(username):
            return str(User.get_user(username))
    """}))
    assert [p["name"] for f in open_findings(result, 89) for p in f["source_params"]] == ["username"]
