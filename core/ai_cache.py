"""
core/ai_cache.py
----------------
Semantic caching layer for AI calls.

Compares new prompts to cached ones using fuzzy similarity.
If match found → return cached answer without calling AI.
Saves token cost massively.
"""

import os
import re
import json
import time
import hashlib
import threading
from pathlib import Path
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Any, Tuple

from core.logger import get_logger, info, ok, warn

log = get_logger("ai_cache")


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
CACHE_DIR = Path(".cache/ai_cache")
SIMILARITY_THRESHOLD = 0.90    # 90% similar = reuse
DEFAULT_TTL = 86400 * 7        # 7 days
MAX_ENTRIES = 5000


# ─────────────────────────────────────────
# Cache entry
# ─────────────────────────────────────────
class AIEntry:
    __slots__ = ("key", "prompt_hash", "prompt_preview", "response",
                 "provider", "created_at", "expires_at", "hits", "tokens_saved")

    def __init__(self, prompt: str, response: Dict,
                 provider: str = "", ttl: int = DEFAULT_TTL,
                 tokens_saved: int = 0):
        self.prompt_hash = _hash_prompt(prompt)
        self.prompt_preview = prompt[:300]
        self.response = response
        self.provider = provider
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl if ttl > 0 else 0
        self.hits = 0
        self.tokens_saved = tokens_saved
        self.key = self.prompt_hash

    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    def to_dict(self) -> Dict:
        return {
            "key": self.key,
            "prompt_hash": self.prompt_hash,
            "prompt_preview": self.prompt_preview,
            "response": self.response,
            "provider": self.provider,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "hits": self.hits,
            "tokens_saved": self.tokens_saved,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "AIEntry":
        e = cls.__new__(cls)
        e.key = data.get("key", "")
        e.prompt_hash = data.get("prompt_hash", "")
        e.prompt_preview = data.get("prompt_preview", "")
        e.response = data.get("response", {})
        e.provider = data.get("provider", "")
        e.created_at = data.get("created_at", 0)
        e.expires_at = data.get("expires_at", 0)
        e.hits = data.get("hits", 0)
        e.tokens_saved = data.get("tokens_saved", 0)
        return e


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def _hash_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8", errors="ignore")).hexdigest()


def _normalize(text: str) -> str:
    """
    Normalize for fuzzy comparison.
    """
    t = text.lower()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[^\w\s]", "", t)
    return t.strip()


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


# ─────────────────────────────────────────
# Manager
# ─────────────────────────────────────────
class AICache:
    def __init__(self, cache_dir: Path = CACHE_DIR):
        self.dir = cache_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.dir / "_index.json"
        self._mem: Dict[str, AIEntry] = {}
        self._lock = threading.Lock()
        self._load_index()

    def _entry_path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def _load_index(self) -> None:
        if not self.index_file.exists():
            return
        try:
            with open(self.index_file, "r", encoding="utf-8") as f:
                index = json.load(f)
            for key in index.get("keys", []):
                p = self._entry_path(key)
                if p.exists():
                    try:
                        with open(p, "r", encoding="utf-8") as fh:
                            self._mem[key] = AIEntry.from_dict(json.load(fh))
                    except Exception:
                        continue
        except Exception as e:
            log.debug(f"index load failed: {e}")

    def _save_index(self) -> None:
        try:
            keys = list(self._mem.keys())
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump({"keys": keys, "saved_at": time.time()}, f)
        except Exception as e:
            log.debug(f"index save failed: {e}")

    def _persist(self, entry: AIEntry) -> None:
        try:
            with open(self._entry_path(entry.key), "w", encoding="utf-8") as f:
                json.dump(entry.to_dict(), f, ensure_ascii=False)
        except Exception as e:
            log.debug(f"persist failed: {e}")

    # ── Get by exact hash ──
    def get_exact(self, prompt: str) -> Optional[AIEntry]:
        h = _hash_prompt(prompt)
        with self._lock:
            entry = self._mem.get(h)
            if entry and not entry.is_expired():
                entry.hits += 1
                self._persist(entry)
                return entry
            if entry and entry.is_expired():
                self._mem.pop(h, None)
        return None

    # ── Get by similarity ──
    def get_similar(self, prompt: str,
                    threshold: float = SIMILARITY_THRESHOLD
                    ) -> Optional[Tuple[AIEntry, float]]:
        target = _normalize(prompt)
        if not target:
            return None

        best: Optional[AIEntry] = None
        best_score = 0.0

        with self._lock:
            for entry in list(self._mem.values()):
                if entry.is_expired():
                    continue
                score = _similarity(target, _normalize(entry.prompt_preview))
                if score > best_score:
                    best_score = score
                    best = entry

        if best and best_score >= threshold:
            with self._lock:
                best.hits += 1
                self._persist(best)
            return best, best_score
        return None

    # ── Combined get ──
    def get(self, prompt: str,
            threshold: float = SIMILARITY_THRESHOLD
            ) -> Optional[Tuple[AIEntry, float]]:
        """
        Try exact first, then similar.
        Returns (entry, similarity) or None.
        """
        exact = self.get_exact(prompt)
        if exact:
            return exact, 1.0
        return self.get_similar(prompt, threshold)

    # ── Store ──
    def put(self, prompt: str, response: Dict,
            provider: str = "",
            tokens_saved: int = 0,
            ttl: int = DEFAULT_TTL) -> AIEntry:
        entry = AIEntry(prompt, response, provider=provider,
                        ttl=ttl, tokens_saved=tokens_saved)
        with self._lock:
            self._mem[entry.key] = entry
        self._persist(entry)
        self._save_index()

        # Trim if too big
        if len(self._mem) > MAX_ENTRIES:
            self._trim()
        return entry

    def _trim(self) -> None:
        with self._lock:
            items = sorted(
                self._mem.values(),
                key=lambda e: (e.hits, e.created_at),
                reverse=True,
            )[:MAX_ENTRIES]
            keep = {e.key for e in items}
            for k in list(self._mem.keys()):
                if k not in keep:
                    try:
                        self._entry_path(k).unlink(missing_ok=True)
                    except Exception:
                        pass
                    self._mem.pop(k, None)
        self._save_index()

    # ── Clear ──
    def clear(self) -> int:
        with self._lock:
            count = len(self._mem)
            for k in list(self._mem.keys()):
                try:
                    self._entry_path(k).unlink(missing_ok=True)
                except Exception:
                    pass
            self._mem.clear()
        self._save_index()
        return count

    def cleanup_expired(self) -> int:
        removed = 0
        with self._lock:
            for k, e in list(self._mem.items()):
                if e.is_expired():
                    try:
                        self._entry_path(k).unlink(missing_ok=True)
                    except Exception:
                        pass
                    self._mem.pop(k, None)
                    removed += 1
        self._save_index()
        return removed

    # ── Stats ──
    def stats(self) -> Dict:
        with self._lock:
            total = len(self._mem)
            hits = sum(e.hits for e in self._mem.values())
            tokens_saved = sum(e.tokens_saved * max(e.hits, 1) for e in self._mem.values())
        return {
            "entries": total,
            "total_hits": hits,
            "tokens_saved_est": tokens_saved,
            "cost_saved_est_usd": round(tokens_saved / 1_000_000 * 0.15, 4),
            "cache_dir": str(self.dir),
            "similarity_threshold": SIMILARITY_THRESHOLD,
        }


# ─────────────────────────────────────────
# Singleton + wrapper
# ─────────────────────────────────────────
_CACHE: Optional[AICache] = None
_LOCK = threading.Lock()


def get_ai_cache() -> AICache:
    global _CACHE
    with _LOCK:
        if _CACHE is None:
            _CACHE = AICache()
        return _CACHE


def cached_ai_call(prompt: str, producer,
                   provider: str = "",
                   tokens_estimate: int = 1000,
                   threshold: float = SIMILARITY_THRESHOLD) -> Dict:
    """
    Wrap any AI call:
      cached_ai_call(prompt, lambda: ask_ai(prompt))
    """
    cache = get_ai_cache()

    hit = cache.get(prompt, threshold)
    if hit:
        entry, score = hit
        log.debug(f"ai cache hit (score={score:.2f}, hits={entry.hits})")
        return {
            "from_cache": True,
            "similarity": round(score, 3),
            "answer": entry.response,
            "provider": entry.provider,
        }

    # Miss → call producer
    try:
        response = producer()
    except Exception as e:
        log.debug(f"producer failed: {e}")
        return {"from_cache": False, "answer": None, "error": str(e)}

    if response:
        cache.put(prompt, response, provider=provider,
                  tokens_saved=tokens_estimate)
    return {
        "from_cache": False,
        "similarity": 0.0,
        "answer": response,
        "provider": provider,
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI cache")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--clear", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    p.add_argument("--test", action="store_true", help="Run a quick cache test")
    args = p.parse_args()

    c = get_ai_cache()
    if args.stats:
        print(json.dumps(c.stats(), indent=2))
    elif args.clear:
        print(f"Cleared {c.clear()} entries")
    elif args.cleanup:
        print(f"Removed {c.cleanup_expired()} expired entries")
    elif args.test:
        prompt1 = "Find XSS on example.com"
        prompt2 = "Find XSS on example.com "  # almost same
        r1 = cached_ai_call(prompt1, lambda: {"answer": "test", "ok": True})
        r2 = cached_ai_call(prompt2, lambda: {"answer": "test", "ok": True})
        print("First call:", json.dumps(r1, indent=2))
        print("Second call:", json.dumps(r2, indent=2))
    else:
        print(json.dumps(c.stats(), indent=2))