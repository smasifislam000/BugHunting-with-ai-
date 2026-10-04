"""
core/proxy_rotator.py
---------------------
Multi-proxy rotation for scan traffic.

Supports:
  - HTTP/HTTPS proxies
  - SOCKS4/SOCKS5 proxies
  - Tor (via SOCKS5 on 9050)
  - Auto-rotate on 403/429/block detection
  - Health checks
"""

import time
import random
import threading
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config
from core.utils import safe_request

log = get_logger("proxy_rotator")
cfg = get_config()


# ─────────────────────────────────────────
# Proxy pool
# ─────────────────────────────────────────
DEFAULT_HEALTH_URL = "https://httpbin.org/ip"


class Proxy:
    __slots__ = ("url", "scheme", "host", "port", "failures", "successes",
                 "last_used", "banned")

    def __init__(self, url: str):
        self.url = url
        p = urlparse(url)
        self.scheme = p.scheme or "http"
        self.host = p.hostname or ""
        self.port = p.port or 0
        self.failures = 0
        self.successes = 0
        self.last_used = 0.0
        self.banned = False

    def score(self) -> float:
        """Higher = better."""
        if self.banned:
            return -1.0
        total = self.successes + self.failures
        if total == 0:
            return 1.0  # untested = neutral-positive
        rate = self.successes / total
        # Prefer less-recently-used
        age = time.time() - self.last_used
        return rate + min(age / 60.0, 1.0) * 0.5


class ProxyRotator:
    def __init__(self, proxies: Optional[List[str]] = None,
                 max_failures: int = 5,
                 health_timeout: int = 8):
        self.proxies: List[Proxy] = []
        self.max_failures = max_failures
        self.health_timeout = health_timeout
        self._lock = threading.Lock()
        self._idx = 0
        self.enabled = False

        if proxies:
            for p in proxies:
                self.add(p)
            self.enabled = bool(self.proxies)

    # ── Proxy management ──
    def add(self, url: str) -> None:
        if not url or "://" not in url:
            url = "http://" + url
        with self._lock:
            if any(p.url == url for p in self.proxies):
                return
            self.proxies.append(Proxy(url))

    def add_tor(self, host: str = "127.0.0.1", port: int = 9050) -> None:
        """Add Tor SOCKS5 proxy."""
        self.add(f"socks5://{host}:{port}")

    def remove_banned(self) -> int:
        with self._lock:
            before = len(self.proxies)
            self.proxies = [p for p in self.proxies if not p.banned]
            return before - len(self.proxies)

    # ── Selection ──
    def _pick_best(self) -> Optional[Proxy]:
        with self._lock:
            if not self.proxies:
                return None
            # Sort by score, pick from top 3 randomly for fairness
            active = [p for p in self.proxies if not p.banned]
            if not active:
                return None
            active.sort(key=lambda x: -x.score())
            top = active[:3]
            choice = random.choice(top)
            choice.last_used = time.time()
            return choice

    def _pick_round_robin(self) -> Optional[Proxy]:
        with self._lock:
            active = [p for p in self.proxies if not p.banned]
            if not active:
                return None
            self._idx = (self._idx + 1) % len(active)
            p = active[self._idx]
            p.last_used = time.time()
            return p

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Return requests-compatible proxy dict."""
        if not self.enabled:
            return None
        p = self._pick_best()
        if not p:
            return None
        return {"http": p.url, "https": p.url}

    # ── Feedback ──
    def mark_success(self, proxy_url: str) -> None:
        for p in self.proxies:
            if p.url == proxy_url:
                p.successes += 1
                p.failures = 0
                break

    def mark_failure(self, proxy_url: str) -> None:
        for p in self.proxies:
            if p.url == proxy_url:
                p.failures += 1
                if p.failures >= self.max_failures:
                    p.banned = True
                    warn(f"Proxy banned after {p.failures} failures: {proxy_url}")
                break

    def mark_current_failed(self) -> None:
        """Mark the most recently used proxy as failed."""
        with self._lock:
            if not self.proxies:
                return
            recent = max(self.proxies, key=lambda x: x.last_used)
            self.mark_failure(recent.url)

    # ── Health check ──
    def check_proxy(self, proxy_url: str) -> bool:
        try:
            r = safe_request(DEFAULT_HEALTH_URL,
                             proxies={"http": proxy_url, "https": proxy_url},
                             timeout=self.health_timeout)
            return r is not None and r.status_code == 200
        except Exception:
            return False

    def health_check_all(self) -> Dict[str, bool]:
        """Test all proxies. Returns dict of proxy_url → healthy."""
        results = {}
        for p in self.proxies:
            healthy = self.check_proxy(p.url)
            results[p.url] = healthy
            if not healthy:
                p.failures += 1
                if p.failures >= self.max_failures:
                    p.banned = True
            else:
                p.successes += 1
                p.failures = 0
        return results

    # ── Stats ──
    def stats(self) -> Dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "total": len(self.proxies),
                "active": len([p for p in self.proxies if not p.banned]),
                "banned": len([p for p in self.proxies if p.banned]),
                "proxies": [
                    {
                        "url": p.url,
                        "successes": p.successes,
                        "failures": p.failures,
                        "banned": p.banned,
                    }
                    for p in self.proxies
                ],
            }


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_ROTATOR: Optional[ProxyRotator] = None


def get_rotator() -> ProxyRotator:
    global _ROTATOR
    if _ROTATOR is None:
        proxies_cfg = cfg.get("proxy.proxies", []) or []
        _ROTATOR = ProxyRotator(proxies=proxies_cfg)
        if cfg.get("proxy.tor_enabled", False):
            _ROTATOR.add_tor()
    return _ROTATOR


def get_proxies() -> Optional[Dict[str, str]]:
    """Shortcut: return proxies dict or None."""
    rot = get_rotator()
    if not rot.enabled:
        return None
    return rot.get_proxy_dict()


def report_block() -> None:
    """Call when a block is detected (403/429) to rotate."""
    rot = get_rotator()
    if rot.enabled:
        rot.mark_current_failed()


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser(description="Proxy rotator")
    p.add_argument("--add", action="append", help="Add proxy (e.g. http://ip:port)")
    p.add_argument("--tor", action="store_true", help="Add Tor SOCKS5")
    p.add_argument("--check", action="store_true", help="Health check all")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--test", help="Test URL via rotator")
    args = p.parse_args()

    rot = get_rotator()
    if args.add:
        for a in args.add:
            rot.add(a)
        rot.enabled = True
    if args.tor:
        rot.add_tor()
        rot.enabled = True

    if args.check:
        results = rot.health_check_all()
        for url, healthy in results.items():
            print(f"  {'✓' if healthy else '✗'} {url}")
    elif args.stats:
        print(json.dumps(rot.stats(), indent=2))
    elif args.test:
        proxies = get_proxies()
        print(f"Using proxy: {proxies}")
        r = safe_request(args.test, proxies=proxies, timeout=15)
        if r:
            print(f"Status: {r.status_code}")
            print(f"Response preview: {r.text[:200]}")
        else:
            print("Request failed")
    else:
        print(json.dumps(rot.stats(), indent=2))