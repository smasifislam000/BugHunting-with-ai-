"""
core/rate_limiter.py
--------------------
Per-host rate limiting to avoid getting IP-blocked.
Thread-safe. Blocks when host exceeds quota.
"""

import time
import threading
from collections import defaultdict
from typing import Optional
from urllib.parse import urlparse

from core.logger import get_logger, warn
from core.config_loader import get_config

log = get_logger("rate_limiter")
cfg = get_config()


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
DEFAULT_PER_HOST = 50        # requests per second per host
DEFAULT_MAX_PER_HOST = 10000 # total per host per scan
DEFAULT_WINDOW = 1.0         # seconds


class _HostBucket:
    __slots__ = ("tokens", "last_refill", "total_count", "lock")

    def __init__(self, max_tokens: int):
        self.tokens = max_tokens
        self.last_refill = time.time()
        self.total_count = 0
        self.lock = threading.Lock()


class RateLimiter:
    """
    Token-bucket rate limiter per host.
    """

    def __init__(self, per_second: int = DEFAULT_PER_HOST,
                 max_per_host: int = DEFAULT_MAX_PER_HOST):
        self.per_second = max(1, per_second)
        self.max_per_host = max_per_host
        self._buckets = defaultdict(lambda: _HostBucket(self.per_second))
        self._lock = threading.Lock()
        self._blocked: set = set()

    def _host_of(self, url: str) -> str:
        try:
            p = urlparse(url)
            return p.netloc or p.path or "unknown"
        except Exception:
            return "unknown"

    def acquire(self, url: str, timeout: float = 30.0) -> bool:
        """
        Block until a token is available for this host.
        Returns False if host is hard-blocked (max_per_host exceeded).
        """
        host = self._host_of(url)

        with self._lock:
            if host in self._blocked:
                return False

        bucket = self._buckets[host]
        deadline = time.time() + timeout

        while True:
            with bucket.lock:
                if bucket.total_count >= self.max_per_host:
                    with self._lock:
                        self._blocked.add(host)
                    warn(f"Host {host} exceeded max requests ({self.max_per_host})")
                    return False

                now = time.time()
                elapsed = now - bucket.last_refill
                refill = elapsed * self.per_second
                if refill > 0:
                    bucket.tokens = min(self.per_second, bucket.tokens + refill)
                    bucket.last_refill = now

                if bucket.tokens >= 1:
                    bucket.tokens -= 1
                    bucket.total_count += 1
                    return True

            if time.time() >= deadline:
                warn(f"Rate limit timeout for {host}")
                return False
            time.sleep(0.05)

    def is_blocked(self, url_or_host: str) -> bool:
        host = self._host_of(url_or_host)
        with self._lock:
            return host in self._blocked

    def stats(self) -> dict:
        with self._lock:
            return {
                "hosts_tracked": len(self._buckets),
                "hosts_blocked": len(self._blocked),
                "blocked_list": sorted(self._blocked)[:20],
                "per_second_limit": self.per_second,
                "max_per_host": self.max_per_host,
            }

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
            self._blocked.clear()


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_LIMITER: Optional[RateLimiter] = None
_LIMITER_LOCK = threading.Lock()


def get_limiter() -> RateLimiter:
    global _LIMITER
    with _LIMITER_LOCK:
        if _LIMITER is None:
            per_sec = cfg.get("safety.rate_limit_per_host", DEFAULT_PER_HOST)
            max_host = cfg.get("safety.max_requests_per_host", DEFAULT_MAX_PER_HOST)
            _LIMITER = RateLimiter(per_second=per_sec, max_per_host=max_host)
        return _LIMITER


def acquire(url: str, timeout: float = 30.0) -> bool:
    """Shortcut for get_limiter().acquire(url)."""
    return get_limiter().acquire(url, timeout)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser(description="Rate limiter")
    p.add_argument("--test", action="store_true", help="Run stress test")
    p.add_argument("--urls", type=int, default=100)
    args = p.parse_args()

    if args.test:
        rl = RateLimiter(per_second=10, max_per_host=50)
        t0 = time.time()
        for i in range(args.urls):
            rl.acquire("https://example.com/test")
        elapsed = time.time() - t0
        print(f"{args.urls} requests in {elapsed:.2f}s")
        print(f"Effective rate: {args.urls / elapsed:.1f} req/s")
        print(json.dumps(rl.stats(), indent=2))
    else:
        print(json.dumps(get_limiter().stats(), indent=2))