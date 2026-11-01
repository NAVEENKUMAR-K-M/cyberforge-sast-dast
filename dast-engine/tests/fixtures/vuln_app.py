"""Tiny Flask fixture with one deliberately vulnerable route and one safe
decoy route per probe CWE. Used only by the probe test suite, never run
outside pytest, and only ever reachable on 127.0.0.1.
"""
from __future__ import annotations

import os
import posixpath
import sqlite3
import subprocess
import sys

from flask import Flask, Response, make_response, request
from markupsafe import escape

app = Flask(__name__)

# --- SQLi (CWE-89) ---------------------------------------------------------
_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
_conn.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
_conn.commit()


@app.route("/sqli")
def sqli_vuln():
    id_ = request.args.get("id", "1")
    query = f"SELECT name FROM users WHERE id = {id_}"  # deliberately unsafe
    try:
        rows = _conn.execute(query).fetchall()
        return "<br>".join(r[0] for r in rows) or "no results"
    except sqlite3.OperationalError as e:
        return f"sqlite3.OperationalError: {e}", 500


@app.route("/docs_decoy")
def docs_decoy():
    # Mirrors a real false-positive hit (confirmed against live DVWA's own
    # setup instructions, verbatim phrasing): documentation text that
    # literally reads "an uncaught mysqli_sql_exception" while describing
    # a PHP 8.1 behaviour change -- no error anywhere, and present
    # regardless of the query param, which is exactly what the
    # clean-request noise check is for.
    return (
        "<html><body><p>As of PHP 8.1, mysqli now throws "
        "an uncaught mysqli_sql_exception on failure instead of returning "
        "false. If you see sqlite3.OperationalError: in your own code, "
        "check your driver version.</p></body></html>"
    )


@app.route("/sqli_decoy")
def sqli_decoy():
    id_ = request.args.get("id", "1")
    try:
        id_int = int(id_)  # decoy: non-numeric input 400s before ever touching SQL
    except ValueError:
        return "invalid id", 400
    rows = _conn.execute("SELECT name FROM users WHERE id = ?", (id_int,)).fetchall()
    return "<br>".join(r[0] for r in rows) or "no results"


@app.route("/sorted_vuln")
def sorted_vuln():
    # A sort column pasted into ORDER BY, errors hidden: a bare 500, as with debug off.
    try:
        rows = _conn.execute("SELECT name FROM users ORDER BY " + request.args.get("sort", "id")).fetchall()
    except sqlite3.Error:
        return "error", 500
    return "<br>".join(r[0] for r in rows)


@app.route("/sorted_decoy")
def sorted_decoy():
    column = request.args.get("sort", "id")
    if column not in ("id", "name"):  # a list of allowed columns: anything else falls back to the default
        column = "id"
    rows = _conn.execute("SELECT name FROM users ORDER BY " + column).fetchall()
    return "<br>".join(r[0] for r in rows)


@app.route("/sqlite_near")
def sqlite_near():
    # What SQLite says when the quote swallows the rest of the query: it names the token it stopped at.
    if request.args.get("q", "") == "'":
        return 'Fatal error: SQLSTATE[HY000]: General error: 1 near &quot;d41d8cd9&quot;: syntax error', 200
    return "ok"


# --- XSS (CWE-79) -----------------------------------------------------------
@app.route("/xss")
def xss_vuln():
    name = request.args.get("name", "")
    return f"<html><body>Hello {name}</body></html>"


@app.route("/xss_plain_text")
def xss_plain_text():
    # Reflected as-is, but a browser shows text/plain as text, so nothing can run.
    return Response(request.args.get("q", ""), mimetype="text/plain")


@app.route("/dispatch")
def dispatch():
    # One path, several pages: only action=view and action=track reach a query.
    action = request.args.get("action")
    if action not in ("view", "track"):
        return "welcome"
    try:
        rows = _conn.execute(f"SELECT name FROM users WHERE id = {request.args.get('id', '1')}").fetchall()
        return "<br>".join(r[0] for r in rows) or "no results"
    except sqlite3.Error as e:
        return f"sqlite3.OperationalError: {e}", 500


@app.route("/xss_decoy")
def xss_decoy():
    name = request.args.get("name", "")
    return f"<html><body>Hello {escape(name)}</body></html>"


# --- Command injection (CWE-78) --------------------------------------------
@app.route("/cmdi")
def cmdi_vuln():
    host = request.args.get("host", "localhost")
    result = subprocess.run(f"echo {host}", shell=True, capture_output=True, text=True, timeout=5)
    return result.stdout + result.stderr


@app.route("/cmdi_coincidence")
def cmdi_coincidence():
    # A static page that always includes the number "123" (an order
    # number here), regardless of input -- mirrors a real false-positive
    # hit where a computed CMDi marker coincidentally matched a number
    # already present on an unrelated, static page.
    request.args.get("host", "")  # read but ignored, like a decoy param that does nothing
    return "<html><body>Your order #123 has shipped.</body></html>"


@app.route("/cmdi_decoy")
def cmdi_decoy():
    host = request.args.get("host", "localhost")
    # list-form, shell=False: the argument is never interpreted by a shell,
    # so a separator in `host` is just part of the literal string printed.
    result = subprocess.run([sys.executable, "-c", f"print({host!r})"], shell=False, capture_output=True, text=True, timeout=5)
    return result.stdout + result.stderr


# --- Path traversal (CWE-22) ------------------------------------------------
_BASE_DIR = os.path.join(os.path.dirname(__file__), "safe_files")
os.makedirs(_BASE_DIR, exist_ok=True)
with open(os.path.join(_BASE_DIR, "readme.txt"), "w", encoding="utf-8") as _f:
    _f.write("hello from the sandboxed directory")


@app.route("/traversal")
def traversal_vuln():
    page = request.args.get("page", "readme.txt")
    target = os.path.realpath(os.path.join(_BASE_DIR, page)).replace("\\", "/")
    # A fixed Linux-style file, never the host's own: its format depends on the
    # machine running the tests (macOS writes "root:*:0:0"), and tests shouldn't
    # read real system files anyway.
    if target.endswith("/etc/passwd"):
        return "root:x:0:0:root:/root:/bin/bash\n"
    try:
        with open(os.path.join(_BASE_DIR, page), "r", errors="ignore") as f:
            return f.read()
    except OSError as e:
        return str(e), 404


@app.route("/mentions_localhost")
def mentions_localhost():
    # Mirrors a real false-positive hit (confirmed against live DVWA): a
    # perfectly normal page that just happens to mention "localhost" in
    # its content, nowhere near any file read. A signature that's just
    # the bare word "localhost" would wrongly call this a confirmed
    # /etc/hosts read; that signature was removed from path_traversal.yaml.
    page = request.args.get("page", "x")
    return f"<html><body>Visit us at http://localhost:8080/ (page={page})</body></html>"


@app.route("/traversal_decoy")
def traversal_decoy():
    page = request.args.get("page", "readme.txt")
    target = os.path.realpath(os.path.join(_BASE_DIR, page))
    if not target.startswith(os.path.realpath(_BASE_DIR)):
        return "forbidden", 403
    try:
        with open(target, "r", errors="ignore") as f:
            return f.read()
    except OSError as e:
        return str(e), 404


# --- Open redirect (CWE-601) -------------------------------------------------
@app.route("/redirect")
def redirect_vuln():
    next_url = request.args.get("next", "/")
    resp = make_response("", 302)
    resp.headers["Location"] = next_url
    return resp


@app.route("/redirect_decoy")
def redirect_decoy():
    next_url = request.args.get("next", "/")
    # Normalize backslashes before checking: browsers treat "/\evil.com"
    # the same as "//evil.com" (protocol-relative), so a naive
    # startswith("/") check alone is a real bypass, not just a theoretical
    # one -- checked without this normalization, the probe correctly
    # caught it.
    normalized = next_url.replace("\\", "/")
    if not normalized.startswith("/") or normalized.startswith("//"):
        next_url = "/"
    resp = make_response("", 302)
    resp.headers["Location"] = next_url
    return resp


if __name__ == "__main__":
    app.run(port=5056)


# --- Shapes a generic probe misses without help (used by the verify hint/field tests) ---------------
@app.route("/guarded_redirect")
def guarded_redirect():
    # Redirects only when the value mentions this site, so a bare foreign URL is ignored.
    next_url = request.args.get("next", "/")
    if "keep-me" not in next_url:
        return "saved"
    resp = make_response("", 302)
    resp.headers["Location"] = next_url
    return resp


@app.route("/filtered_traversal")
def filtered_traversal():
    # Models a naive single-pass "../" filter the way it would behave on the Linux server this is meant
    # to stand in for (the real benchmark apps run in Linux containers, where "\" is just a filename
    # character, not a separator) -- using posixpath instead of os.path keeps that true regardless of
    # which OS actually runs this test, so only a forward-slash bypass like "....//" works here, and a
    # backslash sequence or an absolute/drive-letter path (which os.path.join would honor as an override
    # on Windows) does not.
    page = request.args.get("page", "readme.txt").replace("../", "").lstrip("/")
    target = posixpath.normpath(posixpath.join("/sandbox", page))
    if target == "/etc/passwd":  # only a path that really climbs out of the sandbox
        return "root:x:0:0:root:/root:/bin/bash\n"
    return "not found", 404


@app.route("/xss_unquoted")
def xss_unquoted():
    # An unquoted attribute: escaping quotes and angle brackets doesn't stop a space.
    return f"<img src={escape(request.args.get('img', 'logo.png'))}>"


@app.route("/needs_field", methods=["POST"])
def needs_field():
    # The vulnerable query only runs when the other form field is sent too.
    if "password" not in request.form:
        return "missing password", 200
    query = f"SELECT name FROM users WHERE name = '{request.form.get('name', '')}'"
    try:
        _conn.execute(query).fetchall()
        return "ok"
    except sqlite3.OperationalError as e:
        return f"sqlite3.OperationalError: {e}", 500
