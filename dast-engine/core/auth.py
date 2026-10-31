"""Generic form-login handler.

Given a login URL + username/password + field name hints, this:
  1. GETs the login page
  2. Auto-detects the CSRF token field (any hidden <input> whose name/value
     looks token-like, or an explicit field name from config)
  3. POSTs the form with credentials + token
  4. Confirms success (status/redirect/absence of login form) and stores
     the resulting session cookies on the RequestManager
"""
from __future__ import annotations

import logging
import re

from bs4 import BeautifulSoup

from core.request_manager import RequestManager

logger = logging.getLogger("dast.auth")

TOKEN_NAME_HINTS = re.compile(r"(csrf|token|_token|authenticity|nonce)", re.I)


def _find_hidden_fields(html: str) -> dict[str, str]:
    soup = BeautifulSoup(html, "lxml")
    fields: dict[str, str] = {}
    form = soup.find("form")
    if not form:
        return fields
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        value = inp.get("value", "")
        if itype == "hidden" or TOKEN_NAME_HINTS.search(name):
            fields[name] = value
    return fields


async def login(rm: RequestManager, auth_cfg: dict) -> bool:
    """Perform generic form login per auth_cfg. Returns True on apparent success."""
    if not auth_cfg or not auth_cfg.get("enabled", False):
        return True

    login_url = auth_cfg["login_url"]
    username_field = auth_cfg.get("username_field", "username")
    password_field = auth_cfg.get("password_field", "password")
    username = auth_cfg.get("username", "")
    password = auth_cfg.get("password", "")
    extra_fields = auth_cfg.get("extra_fields", {})  # e.g. {"Login": "Login"}
    success_indicator = auth_cfg.get("success_indicator")  # substring that must appear/disappear

    resp = await rm.get(login_url)
    if resp is None:
        logger.warning("Could not fetch login page %s", login_url)
        return False

    hidden_fields = _find_hidden_fields(resp.text)
    rm.cookies.update(dict(resp.cookies))

    form_data = {**hidden_fields, username_field: username, password_field: password, **extra_fields}

    post_resp = await rm.post(login_url, data=form_data, cookies=dict(resp.cookies))
    if post_resp is None:
        return False
    rm.cookies.update(dict(post_resp.cookies))

    if success_indicator:
        body = post_resp.text
        ok = success_indicator in body if not success_indicator.startswith("!") else success_indicator[1:] not in body
        if not ok:
            logger.warning("Login success indicator not matched for %s", login_url)
        return ok

    # Heuristic fallback: a redirect away from the login page, or a 2xx
    # response that no longer contains a password field, counts as success.
    if post_resp.status_code in (301, 302, 303):
        return True
    if password_field.encode() not in post_resp.content:
        return True
    return False
