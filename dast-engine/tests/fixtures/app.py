"""Tiny Flask fixture app used by the test suite.

Exposes one "vulnerable" route and one "decoy/secure" route per passive
check, plus a comment form/listing pair for the stored-marker test. This
app is never run against anything but localhost, and only from pytest.
"""
from __future__ import annotations

from flask import Flask, make_response, request

app = Flask(__name__)
_comments: list[str] = []


@app.route("/bad-redirect")
def bad_redirect():
    # Mirrors a fuzzed param reflected straight into Location: not a valid
    # URL (missing leading slash for a path, raw spaces, etc).
    reflected = request.args.get("to", "info.php?id=1")
    resp = make_response("", 302)
    resp.headers["Location"] = reflected
    return resp


@app.route("/insecure")
def insecure():
    resp = make_response(
        "<html><body>Hello <!-- Server: Apache/2.4.41 (Ubuntu) --></body></html>"
    )
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.set_cookie("session", "abc123")  # no HttpOnly/Secure/SameSite
    return resp


@app.route("/secure")
def secure():
    resp = make_response("<html><body>Hello</body></html>")
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.set_cookie("session", "abc123", httponly=True, samesite="Strict")
    return resp


@app.route("/stack-trace")
def stack_trace():
    return (
        "Warning: mysqli_query(): in /var/www/html/index.php on line 42\n"
        "Fatal error: Uncaught Error on line 99",
        500,
    )


@app.route("/comment", methods=["POST"])
def comment():
    _comments.append(request.form.get("message", ""))
    return "thanks"


@app.route("/comments")
def comments():
    return "<html><body>" + "<br>".join(_comments) + "</body></html>"


@app.route("/comment-form")
def comment_form():
    return """
    <html><body>
    <form method="POST" action="/comment">
      <input type="text" name="message" value="">
      <input type="submit" value="Post">
    </form>
    </body></html>
    """


if __name__ == "__main__":
    app.run(port=5055)
