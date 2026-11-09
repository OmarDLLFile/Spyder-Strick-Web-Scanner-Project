"""Token-bucket rate limiter: minimum delay between requests + burst cap."""
from __future__ import annotations
import threading, time


class RateLimiter:
    def __init__(self, delay: float = 0.0, max_requests: int = 0):
        self.delay = max(0.0, float(delay))
        self.max_requests = int(max_requests or 0)
        self._lock = threading.Lock()
        self._last = 0.0
        self.count = 0

    def wait(self):
        with self._lock:
            if self.max_requests and self.count >= self.max_requests:
                raise RuntimeError(f"Request budget exhausted ({self.max_requests} requests)")
            now = time.monotonic()
            sleep_for = self.delay - (now - self._last)
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last = time.monotonic()
            self.count += 1
