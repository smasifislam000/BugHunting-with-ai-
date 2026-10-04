"""
core/cache_manager.py
---------------------
Disk-based JSON cache with TTL.
Used to avoid re-fetching expensive results (API calls, DNS lookups).
Thread-safe. Never crashes — cache miss returns None.
"""

import os
import json
import time
import hashlib
import threading
from pathlib import Path
from typing import Any, Optional, Callable, Dict

from core.logger import get_logger

log = get_logger("cache_manager")


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
DEFAULT_CACHE_DIR = ".cache/general"
DEFAULT_TTL = 86400  # 24 hours


# ─────────────────────────────────────────
# Cache entry
# ─────────────────────────────────────────
class _Entry:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: Any, ttl: int):
        self.value = value
        self.expires_at = time.time() + ttl if ttl > 0 else 0

    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at


# ─────────────────────────────────────────
# Cache Manager
# ─────────────────────────────────────────
class CacheManager:
    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR,
                 default_ttl: int = DEFAULT_TTL):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self._mem: Dict[str, _Entry] = {}
        self._lock = threading.Lock()

    # ── Key hashing ──
    def _key_path(self, key: str) -> Path:
        h = hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()
        return self.cache_dir / f"{h}.json"

    # ── Get ──
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            # Memory first
            if key in self._mem:
                entry = self._mem[key]
                if not entry.is_expired():
                    return entry.value
                else:
                    del self._mem[key]

        # Disk
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            expires_at = data.get("expires_at", 0)
            if expires_at and time.time() > expires_at:
                path.unlink(missing_ok=True)
                return None
            value = data.get("value")
            # Repopulate memory
            with self._lock:
                self._mem[key] = _Entry(value, 0)
                self._mem[key].expires_at = expires_at
            return value
        except Exception as e:
            log.debug(f"cache get failed for {key[:50]}: {e}")
            return None

    # ── Set ──
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        ttl = self.default_ttl if ttl is None else ttl
        entry = _Entry(value, ttl)
        with self._lock:
            self._mem[key] = entry
        try:
            path = self._key_path(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "key": key[:200],
                    "value": value,
                    "expires_at": entry.expires_at,
                    "created_at": time.time(),
                }, f, ensure_ascii=False)
            return True
        except Exception as e:
            log.debug(f"cache set failed for {key[:50]}: {e}")
            return False

    # ── Delete ──
    def delete(self, key: str) -> bool:
        with self._lock:
            self._mem.pop(key, None)
        path = self._key_path(key)
        if path.exists():
            try:
                path.unlink()
                return True
            except Exception:
                return False
        return False

    # ── Clear ──
    def clear(self) -> int:
        with self._lock:
            self._mem.clear()
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except Exception:
                pass
        return count

    # ── Stats ──
    def stats(self) -> Dict:
        files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in files if f.exists())
        return {
            "memory_entries": len(self._mem),
            "disk_entries": len(files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
        }

    # ── Wrapper ──
    def cached(self, key: str, producer: Callable[[], Any],
               ttl: Optional[int] = None) -> Any:
        """
        Get from cache, or compute via producer() and store.
        """
        hit = self.get(key)
        if hit is not None:
            return hit
        try:
            value = producer()
        except Exception as e:
            log.debug(f"producer failed for {key[:50]}: {e}")
            return None
        if value is not None:
            self.set(key, value, ttl=ttl)
        return value

    def cleanup_expired(self) -> int:
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                expires_at = data.get("expires_at", 0)
                if expires_at and time.time() > expires_at:
                    f.unlink()
                    count += 1
            except Exception:
                try:
                    f.unlink()
                    count += 1
                except Exception:
                    pass
        return count


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_CACHE: Optional[CacheManager] = None
_LOCK = threading.Lock()


def get_cache() -> CacheManager:
    global _CACHE
    with _LOCK:
        if _CACHE is None:
            _CACHE = CacheManager()
        return _CACHE


def cached_call(key: str, producer: Callable[[], Any],
                ttl: Optional[int] = None) -> Any:
    return get_cache().cached(key, producer, ttl=ttl)


# ─────────────────────────────────────────
# Convenience: key builders
# ─────────────────────────────────────────
def cache_key(*parts: str) -> str:
    """Build a stable cache key from parts."""
    return "|".join(str(p) for p in parts if p)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Cache manager")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--clear", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    p.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"))
    p.add_argument("--get", metavar="KEY")
    args = p.parse_args()

    cache = get_cache()

    if args.stats:
        print(json.dumps(cache.stats(), indent=2))
    elif args.clear:
        n = cache.clear()
        print(f"Cleared {n} entries")
    elif args.cleanup:
        n = cache.cleanup_expired()
        print(f"Cleaned up {n} expired entries")
    elif args.set:
        ok = cache.set(args.set[0], args.set[1], ttl=300)
        print("Set OK" if ok else "Set failed")
    elif args.get:
        v = cache.get(args.get)
        print(json.dumps(v, indent=2) if v is not None else "NOT FOUND")
    else:
        print(json.dumps(cache.stats(), indent=2))