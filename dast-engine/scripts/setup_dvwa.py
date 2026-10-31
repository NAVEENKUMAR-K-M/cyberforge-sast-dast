"""Creates DVWA's database, the one-time step its setup page normally asks for.

Usage:  python scripts/setup_dvwa.py [--target http://127.0.0.1:8080]

Waits for DVWA and its database to come up. Only ever talks to loopback, since
this resets the database of whatever it's pointed at.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from urllib.parse import urlparse

import httpx

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
TOKEN = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]")
WAIT_SECONDS = 90


def create_database(client: httpx.Client, target: str) -> bool:
    page = client.get(f"{target}/setup.php")
    token = TOKEN.search(page.text)
    if page.status_code != 200 or not token:
        return False
    client.post(f"{target}/setup.php", data={"create_db": "Create / Reset Database", "user_token": token.group(1)})
    login_page = client.get(f"{target}/login.php")
    login_token = TOKEN.search(login_page.text)
    if not login_token:
        return False
    # DVWA's default account only exists once the tables do.
    landed = client.post(
        f"{target}/login.php",
        data={"username": "admin", "password": "password", "Login": "Login", "user_token": login_token.group(1)},
    )
    return "login.php" not in str(landed.url)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:8080")
    target = parser.parse_args().target.rstrip("/")
    if urlparse(target).hostname not in LOOPBACK:
        print(f"Refusing {target}: this resets the database, so it only runs against loopback.", file=sys.stderr)
        return 2

    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            with httpx.Client(follow_redirects=True, timeout=10) as client:
                if create_database(client, target):
                    print(f"DVWA is ready at {target}")
                    return 0
        except httpx.HTTPError:
            pass  # still starting up
        time.sleep(3)
    print(f"DVWA at {target} wasn't ready after {WAIT_SECONDS}s. Is the stack running?", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
