"""Optional Playwright-based confirmation pass (off by default).

Used to bump a 'firm' reflected/DOM-XSS finding to 'confirmed' by actually
loading the page in headless Chromium and checking whether a harmless
marker call (window.__dastConfirm) fired — i.e. real script execution, not
just an unencoded reflection in the HTML. No-ops cleanly if Playwright
isn't installed, so it's safe to leave wired in without the dependency.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("dast.browser_verifier")

MARKER_FLAG = "__dastConfirm"


def is_available() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except ImportError:
        return False


async def confirm_execution(url: str, marker: str, timeout_ms: int = 5000) -> bool:
    """Loads `url` (which must already contain `marker` wired to call
    window.__dastConfirm(marker) if it were to execute as script) and
    reports whether that flag was actually set. Returns False (not an
    error) if Playwright is unavailable."""
    if not is_available():
        logger.debug("Playwright not installed; skipping browser confirmation for %s", url)
        return False

    from playwright.async_api import async_playwright

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.add_init_script(
                    f"window.{MARKER_FLAG} = null;"
                )
                await page.goto(url, timeout=timeout_ms)
                await page.wait_for_timeout(500)
                flag = await page.evaluate(f"window.{MARKER_FLAG}")
                return flag == marker
            finally:
                await browser.close()
    except Exception as exc:
        logger.warning("Browser confirmation failed for %s: %s", url, exc)
        return False
