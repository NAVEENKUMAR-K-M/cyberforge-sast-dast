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
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.request_manager import RequestManager

logger = logging.getLogger("dast.auth")

TOKEN_NAME_HINTS = re.compile(r"(csrf|token|_token|authenticity|nonce)", re.I)
_PASSWORD_INPUT = re.compile(r"""<input\b[^>]*\btype\s*=\s*["']?password""", re.I)


def _login_form(html: str):
    """The form holding a password field. A page's first form is often a search box."""
    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    for form in forms:
        if form.find("input", attrs={"type": lambda t: (t or "").lower() == "password"}):
            return form
    return forms[0] if forms else None


def _find_hidden_fields(html: str) -> dict[str, str]:
    form = _login_form(html)
    fields: dict[str, str] = {}
    if not form:
        return fields
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        value = inp.get("value", "")
        # A browser sends the submit button too, and some apps check for it.
        if itype in ("hidden", "submit") or TOKEN_NAME_HINTS.search(name):
            fields[name] = value
    button = form.find("button", attrs={"name": True})
    if button is not None:
        fields.setdefault(button["name"], button.get("value", ""))
    return fields


def _field_names(html: str, username_field: str, password_field: str) -> tuple[str, str]:
    """Uses the configured field names if the form has them, or else works them out from the
    form, so an app needs only its credentials: names like `email` and `pwd` are common."""
    form = _login_form(html)
    if not form:
        return username_field, password_field
    inputs = [i for i in form.find_all("input") if i.get("name")]
    names = {i["name"] for i in inputs}
    if password_field not in names:
        password_field = next((i["name"] for i in inputs if (i.get("type") or "").lower() == "password"), password_field)
    if username_field not in names:
        visible = [i["name"] for i in inputs if (i.get("type") or "text").lower() in ("text", "email")]
        username_field = visible[0] if visible else username_field
    return username_field, password_field


def _apply_static_auth(rm: RequestManager, auth_cfg: dict) -> None:
    """Credentials that need no login step: API keys, bearer tokens and existing session cookies."""
    rm.extra_headers.update(auth_cfg.get("headers") or {})
    rm.cookies.update(auth_cfg.get("cookies") or {})
    if auth_cfg.get("bearer_token"):
        rm.extra_headers["Authorization"] = f"Bearer {auth_cfg['bearer_token']}"


async def _json_login(rm: RequestManager, auth_cfg: dict) -> bool:
    """Logs in to a JSON API, keeping the token from the response and any cookies."""
    body = {
        auth_cfg.get("username_field", "username"): auth_cfg.get("username", ""),
        auth_cfg.get("password_field", "password"): auth_cfg.get("password", ""),
        **(auth_cfg.get("extra_fields") or {}),
    }
    resp = await rm.post(auth_cfg["login_url"], json=body)
    if resp is None or resp.status_code >= 400:
        logger.warning("JSON login failed for %s", auth_cfg["login_url"])
        return False
    rm.cookies.update(dict(resp.cookies))
    try:
        data = resp.json()
    except ValueError:
        return True
    names = [auth_cfg.get("token_field"), "token", "access_token", "jwt", "id_token"]
    token = next((data[n] for n in names if n and isinstance(data, dict) and isinstance(data.get(n), str)), None)
    if token:
        rm.extra_headers["Authorization"] = f"Bearer {token}"
    return True


async def login(rm: RequestManager, auth_cfg: dict) -> bool:
    """Perform generic form login per auth_cfg. Returns True on apparent success."""
    auth_cfg = auth_cfg or {}
    _apply_static_auth(rm, auth_cfg)
    if not auth_cfg.get("enabled", False):
        return True
    if auth_cfg.get("json"):
        return await _json_login(rm, auth_cfg)

    login_url = auth_cfg["login_url"]
    username = auth_cfg.get("username", "")
    password = auth_cfg.get("password", "")
    extra_fields = auth_cfg.get("extra_fields", {})  # e.g. {"Login": "Login"}
    success_indicator = auth_cfg.get("success_indicator")  # substring that must appear/disappear

    resp = await rm.get(login_url)
    if resp is None:
        logger.warning("Could not fetch login page %s", login_url)
        return False

    username_field, password_field = _field_names(
        resp.text, auth_cfg.get("username_field", "username"), auth_cfg.get("password_field", "password")
    )
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
        rm.landing_url = str(confirm_resp.url)
        await _run_post_login_actions(rm, auth_cfg.get("post_login", []))
    return ok


class SessionKeeper:
    """Notices when a scan has lost its login and logs in again. Login only happens once, so
    without this every later request is silently anonymous and the results just look clean."""

    check_every = 10

    def __init__(self, rm: RequestManager, auth_cfg: dict):
        self.rm, self.auth_cfg = rm, auth_cfg or {}
        self.relogins = 0
        self._check_url = None
        self._has_password_field = False

    async def start(self) -> None:
        """Remembers what the logged-in page looks like. Call this right after logging in."""
        url = self.rm.landing_url
        if not self.auth_cfg.get("enabled") or self.auth_cfg.get("json") or not url or not self.rm.scope_guard.is_in_scope(url):
            return
        resp = await self.rm.get(url)
        if resp is not None:
            self._check_url = url
            self._has_password_field = _PASSWORD_INPUT.search(resp.text) is not None

    def _looks_logged_out(self, resp) -> bool:
        login_path = urlparse(self.auth_cfg["login_url"]).path
        if resp.is_redirect and urlparse(urljoin(self._check_url, resp.headers.get("location", ""))).path == login_path:
            return True
        return not self._has_password_field and _PASSWORD_INPUT.search(resp.text) is not None

    async def ensure(self) -> None:
        if self._check_url is None:
            return
        resp = await self.rm.get(self._check_url)
        if resp is None or not self._looks_logged_out(resp):
            return
        logger.warning("Session was lost during the scan; logging in again")
        self.rm.clear_session()
        if await login(self.rm, self.auth_cfg):
            self.relogins += 1


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
