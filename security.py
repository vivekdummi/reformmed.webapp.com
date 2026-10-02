"""
Small security helpers shared by the blueprints: safe redirect targets and an
in-process rate limiter for login / password-reset endpoints.
"""
import threading
import time
from urllib.parse import urlparse

from flask import request


def safe_next_url(target, fallback):
    """Only allow same-site relative paths as a post-login redirect, so
    /login?next=https://evil.example can't bounce users off-site."""
    if not target:
        return fallback
    target = target.strip()
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") \
            or target.startswith("//") or "\\" in target:
        return fallback
    return target


class RateLimiter:
    """Sliding-window counter kept in memory. The webapp runs as a single
    process, so this is enough to stop online password / OTP guessing."""

    def __init__(self, limit, window_secs):
        self.limit = limit
        self.window = window_secs
        self._hits = {}
        self._lock = threading.Lock()

    def _prune(self, key, now):
        hits = [t for t in self._hits.get(key, ()) if now - t < self.window]
        if hits:
            self._hits[key] = hits
        else:
            self._hits.pop(key, None)
        return hits

    def blocked(self, key):
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self.limit

    def hit(self, key):
        with self._lock:
            now = time.monotonic()
            hits = self._prune(key, now)
            hits.append(now)
            self._hits[key] = hits
            # keep memory bounded if someone sprays random keys
            if len(self._hits) > 10000:
                for k in list(self._hits)[:5000]:
                    self._hits.pop(k, None)

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)


def client_ip():
    # ProxyFix (app.py) has already applied X-Forwarded-For from the trusted proxy.
    return request.remote_addr or "?"
