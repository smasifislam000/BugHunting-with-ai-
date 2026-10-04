"""
intel/cache_manager.py
----------------------
Specialized cache for API intelligence sources.
Larger TTLs, per-source TTLs, quota tracking.
Prevents duplicate API calls and protects free-tier quotas.
"""

import json
import time
from pathlib import Path
from typing import Any, Optional, Dict
from datetime import datetime, timedelta

from core.logger import get_logger, info, warn, skip
from core.cache_manager import CacheManager
from core.config_loader import get_config

log = get_logger("intel_cache")
cfg = get_config()


# ─────────────────────────────────────────
# Per-source TTLs (seconds)
# ─────────────────────────────────────────
SOURCE_TTL = {
    "shodan":          86400 * 7,     # 7 days (expensive)
    "censys":          86400 * 7,     # 7 days
    "virustotal":      86400 * 2,     # 2 days
    "securitytrails":  86400 * 5,     # 5 days
    "nvd":             86400 * 14,    # 14 days (CVE rarely changes)
    "exploitdb":       86400 * 14,    # 14 days
    "github":          86400,         # 1 day
    "chaos":           86400 * 3,     # 3 days
    "crtsh":           86400,         # 1 day
}


# ─────────────────────────────────────────
# Per-source quotas (daily)
# ─────────────────────────────────────────
SOURCE_QUOTA = {
    "shodan":         100,    # per day on free tier
    "censys":         250,
    "virustotal":     500,
    "securitytrails": 50,
    "nvd":            1000,
    "github":         5000,
}


# ─────────────────────────────────────────
# Manager
# ─────────────────────────────────────────
class IntelCache:
    def __init__(self, cache_dir: str = ".cache/intel"):
        self.cache = CacheManager(cache_dir=cache_dir, default_ttl=86400)
        self.quota_file = Path(cache_dir) / "_quota.json"
        self.quota_file.parent.mkdir(parents=True, exist_ok=True)

    # ── Key building ──
    def _key(self, source: str, query: str) -> str:
        return f"{source}:{query.strip().lower()}"

    # ── Get / Set ──
    def get(self, source: str, query: str) -> Optional[Any]:
        return self.cache.get(self._key(source, query))

    def set(self, source: str, query: str, value: Any) -> bool:
        ttl = SOURCE_TTL.get(source, 86400)
        return self.cache.set(self._key(source, query), value, ttl=ttl)

    def cached(self, source: str, query: str,
               producer) -> Any:
        """
        Cache-aware call with quota check.
        Returns None if quota exceeded.
        """
        # Cache hit
        hit = self.get(source, query)
        if hit is not None:
            log.debug(f"intel cache hit: {source}:{query[:40]}")
            return hit

        # Quota check
        if not self._consume_quota(source):
            warn(f"Quota exceeded for {source} — skipping '{query[:40]}'")
            return None

        # Produce
        try:
            value = producer()
        except Exception as e:
            log.debug(f"producer failed for {source}:{query[:40]}: {e}")
            return None

        if value is not None:
            self.set(source, query, value)
        return value

    # ── Quota tracking ──
    def _load_quota(self) -> Dict:
        if not self.quota_file.exists():
            return {}
        try:
            with open(self.quota_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_quota(self, data: Dict) -> None:
        try:
            with open(self.quota_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.debug(f"quota save failed: {e}")

    def _today(self) -> str:
        return datetime.utcnow().strftime("%Y-%m-%d")

    def _consume_quota(self, source: str) -> bool:
        """Increment usage for source; return False if over quota."""
        today = self._today()
        data = self._load_quota()
        data.setdefault(source, {})
        day_data = data[source].setdefault(today, {"count": 0})

        limit = SOURCE_QUOTA.get(source)
        if limit and day_data["count"] >= limit:
            return False

        day_data["count"] += 1
        data[source][today] = day_data

        # Trim old entries
        cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        for src, days in list(data.items()):
            data[src] = {d: v for d, v in days.items() if d >= cutoff}

        self._save_quota(data)
        return True

    # ── Quota report ──
    def quota_report(self) -> Dict:
        today = self._today()
        data = self._load_quota()
        report = {}
        for source, limit in SOURCE_QUOTA.items():
            used = data.get(source, {}).get(today, {}).get("count", 0)
            report[source] = {
                "used_today": used,
                "limit": limit,
                "remaining": max(0, limit - used),
                "percent": round((used / limit) * 100, 1) if limit else 0,
            }
        return report

    def print_quota(self) -> None:
        info("API quota status (today):")
        for src, data in self.quota_report().items():
            bar = "█" * int(data["percent"] / 10) + "░" * (10 - int(data["percent"] / 10))
            log.info(f"  {src:16s} {bar} {data['used_today']}/{data['limit']}")

    # ── Stats ──
    def stats(self) -> Dict:
        base = self.cache.stats()
        base["quota"] = self.quota_report()
        return base

    def clear(self) -> int:
        return self.cache.clear()

    def cleanup(self) -> int:
        return self.cache.cleanup_expired()


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_CACHE: Optional[IntelCache] = None


def get_intel_cache() -> IntelCache:
    global _CACHE
    if _CACHE is None:
        _CACHE = IntelCache()
    return _CACHE


def cached_intel(source: str, query: str, producer) -> Any:
    return get_intel_cache().cached(source, query, producer)


# ─────────────────────────────────────────
# Convenience wrappers for common sources
# ─────────────────────────────────────────
def shodan_lookup(ip: str, producer) -> Any:
    return cached_intel("shodan", ip, producer)


def censys_lookup(ip: str, producer) -> Any:
    return cached_intel("censys", ip, producer)


def vt_lookup(query: str, producer) -> Any:
    return cached_intel("virustotal", query, producer)


def st_lookup(domain: str, producer) -> Any:
    return cached_intel("securitytrails", domain, producer)


def nvd_lookup(keyword: str, producer) -> Any:
    return cached_intel("nvd", keyword, producer)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Intel cache")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--quota", action="store_true")
    p.add_argument("--clear", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    args = p.parse_args()

    c = get_intel_cache()
    if args.stats:
        print(json.dumps(c.stats(), indent=2))
    elif args.quota:
        c.print_quota()
    elif args.clear:
        print(f"Cleared {c.clear()} entries")
    elif args.cleanup:
        print(f"Cleaned {c.cleanup()} expired entries")
    else:
        c.print_quota()
        print(json.dumps(c.stats(), indent=2))