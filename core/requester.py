"""HTTP requester: session reuse, scope enforcement, rate limiting,
configurable TLS verification (default True), timeout, retries with
backoff only on transient errors. Returns ALL responses (no discarding
by status code). Logs via logging, never prints tracebacks.
"""
from __future__ import annotations
import logging, time
import requests
import urllib3

log = logging.getLogger("spyder.requester")

_TRANSIENT = (429, 500, 502, 503, 504)


class Requester:
    def __init__(self, config=None, scope=None, rate_limiter=None, user_agent=None):
        from core.config import ScanConfig
        self.config = config or ScanConfig()
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent or self.config.user_agent})
        if self.config.auth:
            if self.config.auth.lower().startswith("bearer "):
                self.session.headers["Authorization"] = self.config.auth
            elif ":" in self.config.auth:
                u, p = self.config.auth.split(":", 1)
                self.session.auth = (u, p)
        if self.config.cookies:
            for pair in self.config.cookies.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())
        if not self.config.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log.warning("TLS verification DISABLED (--no-verify). Only use against test targets.")

    def _check(self, url):
        if self.scope is not None:
            self.scope.enforce(url)
        if self.rate_limiter is not None:
            self.rate_limiter.wait()

    def request(self, method, url, **kwargs):
        self._check(url)
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_tls)
        kwargs.setdefault("allow_redirects", True)
        last_exc = None
        for attempt in range(3):
            try:
                resp = self.session.request(method, url, **kwargs)
                if resp.status_code in _TRANSIENT and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return resp
            except requests.RequestException as exc:
                last_exc = exc
                log.debug("request %s %s failed (attempt %d): %s", method, url, attempt + 1, exc)
                time.sleep(0.5 * (attempt + 1))
        log.warning("request %s %s failed after retries: %s", method, url, last_exc)
        return None

    def get(self, url, params=None, **kwargs):
        return self.request("GET", url, params=params, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url, data=None, json=None, **kwargs):
        return self.request("PUT", url, data=data, json=json, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)
