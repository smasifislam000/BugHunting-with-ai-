"""
core/ai_sliding_window.py
-------------------------
Sliding window context optimization for AI calls.

Handles large contexts (many findings, big reports) by:
  1. Splitting into chunks
  2. Selecting the most relevant chunks per query
  3. Summarizing old context into memory
  4. Keeping the last N recent items
"""

import re
import math
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter

from core.logger import get_logger, info, warn

log = get_logger("ai_sliding_window")


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
DEFAULT_MAX_TOKENS = 8000          # approximate tokens
DEFAULT_WINDOW_SIZE = 10           # keep last N items
DEFAULT_OVERLAP = 2                # overlap between chunks


# ─────────────────────────────────────────
# Token estimation (no external tiktoken)
# ─────────────────────────────────────────
def estimate_tokens(text: str) -> int:
    """
    Rough token count: 1 token ≈ 4 chars for English, ~1.5 chars for others.
    """
    if not text:
        return 0
    # Count by words + punctuation
    words = len(re.findall(r"\S+", text))
    return int(words * 1.3)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """
    Truncate text to approximate token limit.
    """
    if estimate_tokens(text) <= max_tokens:
        return text
    # Ratio
    ratio = max_tokens / max(1, estimate_tokens(text))
    keep_chars = int(len(text) * ratio * 0.95)
    truncated = text[:keep_chars]
    # Cut at last space
    idx = truncated.rfind(" ")
    if idx > 0:
        truncated = truncated[:idx]
    return truncated + "\n[...truncated]"


# ─────────────────────────────────────────
# Chunking
# ─────────────────────────────────────────
def chunk_items(items: List[Any], window: int = DEFAULT_WINDOW_SIZE,
                overlap: int = DEFAULT_OVERLAP) -> List[List[Any]]:
    """
    Split a list into overlapping windows.
    """
    if not items:
        return []
    chunks: List[List[Any]] = []
    step = max(1, window - overlap)
    for i in range(0, len(items), step):
        chunk = items[i:i + window]
        if chunk:
            chunks.append(chunk)
    return chunks


# ─────────────────────────────────────────
# Relevance scoring
# ─────────────────────────────────────────
STOPWORDS = {
    "the", "is", "at", "which", "on", "a", "an", "and", "or", "but",
    "in", "with", "to", "for", "of", "by", "from", "as", "that", "this",
}


def _tokens(text: str) -> Counter:
    text = text.lower()
    text = re.sub(r"[^a-z0-9_\-\.]+", " ", text)
    return Counter(t for t in text.split() if t and t not in STOPWORDS and len(t) > 1)


def _relevance(query: str, item_text: str) -> float:
    q = _tokens(query)
    d = _tokens(item_text)
    if not q or not d:
        return 0.0
    common = set(q.keys()) & set(d.keys())
    num = sum(q[k] * d[k] for k in common)
    na = math.sqrt(sum(v * v for v in q.values()))
    nb = math.sqrt(sum(v * v for v in d.values()))
    if na == 0 or nb == 0:
        return 0.0
    return num / (na * nb)


# ─────────────────────────────────────────
# Sliding window builder
# ─────────────────────────────────────────
def build_sliding_context(query: str, items: List[Any],
                          item_to_text=lambda x: str(x),
                          max_tokens: int = DEFAULT_MAX_TOKENS,
                          keep_recent: int = 3) -> str:
    """
    Build a context string that:
      1. Contains the most relevant items to the query
      2. Always keeps the last `keep_recent` items
      3. Respects max_tokens
    """
    if not items:
        return ""

    texts = [item_to_text(i) for i in items]
    scored = [(i, texts[i], _relevance(query, texts[i])) for i in range(len(items))]

    # Always include last `keep_recent`
    recent_set = set(range(max(0, len(items) - keep_recent), len(items)))

    # Sort non-recent by relevance
    scored_non_recent = [s for s in scored if s[0] not in recent_set]
    scored_non_recent.sort(key=lambda x: -x[2])

    selected = []
    used = 0

    # Add high-relevance items first
    for idx, text, score in scored_non_recent:
        tok = estimate_tokens(text) + 5
        if used + tok > max_tokens:
            break
        selected.append((idx, text, score))
        used += tok

    # Add recent items (always)
    for idx in sorted(recent_set):
        text = texts[idx]
        tok = estimate_tokens(text) + 5
        if used + tok > max_tokens:
            # Truncate recent one to fit
            remaining = max_tokens - used
            if remaining > 100:
                selected.append((idx, truncate_to_tokens(text, remaining), 0))
            break
        selected.append((idx, text, 0))
        used += tok

    # Sort selected by original index (chronological order)
    selected.sort(key=lambda x: x[0])

    parts = []
    for idx, text, score in selected:
        marker = "recent" if idx in recent_set else f"score={score:.2f}"
        parts.append(f"--- Item {idx + 1} [{marker}] ---\n{text}")

    return "\n\n".join(parts)


# ─────────────────────────────────────────
# Rolling summary (memory)
# ─────────────────────────────────────────
class RollingSummary:
    """
    Maintains a running summary of past context.
    When new items arrive, old ones get summarized.
    """

    def __init__(self, max_tokens: int = 1500):
        self.max_tokens = max_tokens
        self.summary = ""

    def update(self, new_items: List[str]) -> str:
        """
        Add items to summary, truncating as needed.
        """
        combined = self.summary + "\n" + "\n".join(new_items)
        if estimate_tokens(combined) > self.max_tokens:
            combined = truncate_to_tokens(combined, self.max_tokens)
        self.summary = combined
        return self.summary

    def reset(self) -> None:
        self.summary = ""


# ─────────────────────────────────────────
# High-level wrapper
# ─────────────────────────────────────────
def ask_with_sliding_context(query: str, context_items: List[Any],
                             system: str = "You are an expert bug bounty hunter.",
                             json_mode: bool = True,
                             timeout: int = 60,
                             max_tokens: int = DEFAULT_MAX_TOKENS,
                             item_to_text=lambda x: str(x)) -> Optional[Dict]:
    """
    Ask AI with sliding-window context from a large list of items.
    """
    context = build_sliding_context(query, context_items,
                                    item_to_text=item_to_text,
                                    max_tokens=max_tokens)
    prompt = (
        f"### Context (selected relevant items)\n"
        f"{context}\n\n"
        f"### Task\n{query}"
    )
    try:
        from core.ai_engine import ask_ai
        return ask_ai(prompt, system=system,
                      json_mode=json_mode, timeout=timeout)
    except Exception as e:
        log.debug(f"sliding ask failed: {e}")
        return None


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Sliding window context")
    p.add_argument("--estimate", help="Estimate tokens for text")
    p.add_argument("--truncate", nargs=2, metavar=("TEXT", "MAX_TOKENS"))
    p.add_argument("--test", action="store_true")
    args = p.parse_args()

    if args.estimate:
        print(f"Tokens: {estimate_tokens(args.estimate)}")
    elif args.truncate:
        text, mt = args.truncate
        print(truncate_to_tokens(text, int(mt)))
    elif args.test:
        items = [f"Finding {i}: XSS in /page{i}?q=1" for i in range(20)]
        ctx = build_sliding_context("XSS on /page5", items, max_tokens=500)
        print(ctx)
        print()
        print(f"Total tokens: {estimate_tokens(ctx)}")
    else:
        print("Use --estimate, --truncate, or --test")