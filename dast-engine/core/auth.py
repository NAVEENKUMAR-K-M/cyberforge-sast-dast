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

    # A login POST almost always answers with a redirect (empty body), so
    # checking success_indicator against *that* response is unreliable --
    # an absent indicator in an empty body "passes" even on a rejected
    # login (observed in testing). Re-fetching login_url itself doesn't
    # work either: many apps (DVWA included) render the same login form
    # there regardless of auth state -- only the redirect *target* reflects
    # whether login actually succeeded (e.g. redirected to index.php vs.
    # bounced right back to login.php). Follow that one redirect and check
    # the indicator on the page it actually lands on.
    confirm_resp = post_resp
    if post_resp.is_redirect and "location" in post_resp.headers:
        from urllib.parse import urljoin

        landing_url = urljoin(login_url, post_resp.headers["location"])
        confirm_resp = await rm.get(landing_url)
        if confirm_resp is None:
            logger.warning("Could not confirm login result at %s", landing_url)
            return False
        rm.cookies.update(dict(confirm_resp.cookies))
    body = confirm_resp.text

    if success_indicator:
        ok = success_indicator in body if not success_indicator.startswith("!") else success_indicator[1:] not in body
    else:
        ok = password_field.encode() not in confirm_resp.content

    if not ok:
        logger.warning("Login did not appear to succeed for %s", login_url)
    else:
        await _run_post_login_actions(rm, auth_cfg.get("post_login", []))
    return ok


async def _run_post_login_actions(rm: RequestManager, actions: list[dict]) -> None:
    """Optional, config-driven steps to run once right after a successful
    login — e.g. DVWA stores its difficulty level per-session, so a fresh
    login always resets it; this is how the engine pins it back to a known
    state without hardcoding any target-specific behaviour into auth.py.

    Each action: {"url": ..., "fields": {...}}. The CSRF/hidden-field
    auto-detection from the login form is reused here too.
    """
    for action in actions or []:
        url = action.get("url")
        fields = action.get("fields", {})
        if not url:
            continue
        get_resp = await rm.get(url, bypass_denylist=True)
        if get_resp is None:
            logger.warning("post_login action: could not fetch %s", url)
            continue
        rm.cookies.update(dict(get_resp.cookies))
        hidden = _find_hidden_fields(get_resp.text)
        data = {**hidden, **fields}
        post_resp = await rm.post(url, data=data, bypass_denylist=True)
        if post_resp is None:
            logger.warning("post_login action: POST to %s failed", url)
            continue
        rm.cookies.update(dict(post_resp.cookies))
