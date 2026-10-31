"""Scope enforcement: only ever touch allowlisted hosts, never follow an
off-host redirect, and never request a denylisted (destructive) path.

This is the one module everything else must go through before a request
leaves the process.
"""
from __future__ import annotations

import ipaddress
import fnmatch
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScopeGuard:
    allowed_hosts: list[str] = field(default_factory=list)
    denylist_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.allowed_hosts = [h.lower() for h in self.allowed_hosts]

    @classmethod
    def from_config(cls, cfg: dict) -> "ScopeGuard":
        return cls(
            allowed_hosts=cfg.get("allowlist", []) or [],
            denylist_patterns=cfg.get("denylist", []) or [],
        )

    def _host_matches(self, host: str) -> bool:
        host = host.lower().split(":")[0]
        for allowed in self.allowed_hosts:
            allowed_host = allowed.lower().split("://")[-1].split(":")[0].rstrip("/")
            if host == allowed_host:
                return True
            # allow localhost <-> 127.0.0.1 <-> ::1 equivalence explicitly
            loopback = {"localhost", "127.0.0.1", "::1"}
            if host in loopback and allowed_host in loopback:
                return True
            if fnmatch.fnmatch(host, allowed_host):
                return True
        return False

    def is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        if not self._host_matches(parsed.hostname or ""):
            return False
        if self.is_denylisted(url):
            return False
        return True

    def is_denylisted(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        for pattern in self.denylist_patterns:
            pattern = pattern.lower()
            if fnmatch.fnmatch(path, pattern) or pattern in path:
                return True
        return False

    def check_redirect(self, original_url: str, location: str) -> bool:
        """Return True only if following `location` from `original_url` stays in scope."""
        from urllib.parse import urljoin

        absolute = urljoin(original_url, location)
        return self.is_in_scope(absolute)

    def assert_in_scope(self, url: str) -> None:
        if not self.is_in_scope(url):
            raise ScopeViolation(f"URL out of scope or denylisted: {url}")


class ScopeViolation(Exception):
    pass
