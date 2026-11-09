"""Scan scope / authorization enforcement.

A scan is authorised only when:
  * the target is local (localhost / 127.0.0.1 / ::1 / *.test / *.local), OR
  * the operator passes --authorize (explicit, auditable consent), OR
  * the host is on an explicit --allow list.
Requester blocks every out-of-scope request; scanners never bypass it.
"""
from __future__ import annotations
import logging
from urllib.parse import urlparse

log = logging.getLogger("spyder.scope")

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
LOCAL_SUFFIXES = (".test", ".local", ".localhost")


def is_local_host(host: str) -> bool:
    h = (host or "").lower().strip("[]")
    return h in LOCAL_HOSTS or h.endswith(LOCAL_SUFFIXES) or h.startswith("127.")


class Scope:
    def __init__(self, target_url: str, authorized: bool = False, allow_hosts=None, allow_paths=None):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_host = (parsed.hostname or "").lower()
        self.allowed_hosts = {self.target_host}
        for h in (allow_hosts or []):
            self.allowed_hosts.add(h.lower().strip())
        self.allowed_paths = list(allow_paths or [])
        self.authorized = bool(authorized)

    @property
    def is_local(self) -> bool:
        return is_local_host(self.target_host)

    def check_authorization(self):
        """Raise ValueError if the target may not be scanned."""
        if self.is_local or self.authorized:
            return True
        raise ValueError(
            f"Refusing to scan {self.target_url}: not a local target and --authorize was not given. "
            "Spider-Strick only scans targets you are authorised to test. "
            "Re-run with --authorize (only if you have written permission) or --allow to add hosts."
        )

    def is_allowed(self, url: str) -> bool:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        if host in self.allowed_hosts:
            if self.allowed_paths:
                path = urlparse(url).path
                return any(path.startswith(p) for p in self.allowed_paths)
            return True
        return False

    def enforce(self, url: str):
        if not self.is_allowed(url):
            raise PermissionError(f"Out-of-scope request blocked: {url} (allowed hosts: {sorted(self.allowed_hosts)})")
