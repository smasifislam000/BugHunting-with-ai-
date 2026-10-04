"""
core/ai_rag.py
--------------
Retrieval-Augmented Generation for AI triage.

Stores:
  - Previous bug bounty reports
  - HackerOne public disclosures
  - CVE descriptions
  - Custom knowledge base

Retrieves relevant context for each new finding,
improving AI accuracy massively.
"""

import os
import json
import time
import math
import hashlib
import threading
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter

from core.logger import get_logger, info, ok, warn, skip

log = get_logger("ai_rag")


# ─────────────────────────────────────────
# Storage
# ─────────────────────────────────────────
RAG_DIR = Path(".cache/rag")
DOCS_FILE = RAG_DIR / "documents.json"


# ─────────────────────────────────────────
# Lightweight embedding (no external model)
# ─────────────────────────────────────────
STOPWORDS = {
    "the", "is", "at", "which", "on", "a", "an", "and", "or", "but",
    "in", "with", "to", "for", "of", "by", "from", "as", "that", "this",
    "it", "be", "are", "was", "were", "has", "have", "had", "do", "does",
    "did", "will", "would", "should", "could", "can", "may", "might",
}


def _tokenize(text: str) -> List[str]:
    text = text.lower()
    text = re.sub(r"[^a-z0-9_\-\.]+", " ", text)
    return [t for t in text.split() if t and t not in STOPWORDS and len(t) > 1]


def _embed(text: str) -> Counter:
    """
    Simple bag-of-words embedding. No neural network needed.
    """
    return Counter(_tokenize(text))


def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    common = set(a.keys()) & set(b.keys())
    num = sum(a[k] * b[k] for k in common)
    if num == 0:
        return 0.0
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return num / (na * nb)


# ─────────────────────────────────────────
# RAG store
# ─────────────────────────────────────────
class RAGStore:
    def __init__(self, path: Path = DOCS_FILE):
        self.path = path
        self._lock = threading.Lock()
        self.docs: List[Dict] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.docs = json.load(f)
        except Exception as e:
            log.debug(f"rag load failed: {e}")
            self.docs = []

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.docs, f, ensure_ascii=False)
        except Exception as e:
            log.debug(f"rag save failed: {e}")

    # ── Add ──
    def add(self, text: str, metadata: Optional[Dict] = None,
            doc_id: Optional[str] = None) -> str:
        """
        Add a document. Returns its ID.
        """
        if not text or len(text.strip()) < 10:
            return ""
        doc_id = doc_id or hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:12]
        with self._lock:
            # Avoid duplicates
            if any(d.get("id") == doc_id for d in self.docs):
                return doc_id
            self.docs.append({
                "id": doc_id,
                "text": text[:5000],
                "metadata": metadata or {},
                "added_at": time.time(),
            })
        self._save()
        return doc_id

    # ── Search ──
    def search(self, query: str, top_k: int = 5,
               min_score: float = 0.05) -> List[Dict]:
        """
        Return top_k most relevant docs.
        """
        q_emb = _embed(query)
        if not q_emb:
            return []

        scored = []
        with self._lock:
            for doc in self.docs:
                score = _cosine(q_emb, _embed(doc["text"]))
                if score >= min_score:
                    scored.append((score, doc))

        scored.sort(key=lambda x: -x[0])
        return [
            {"score": round(s, 4), **doc}
            for s, doc in scored[:top_k]
        ]

    # ── Context builder ──
    def build_context(self, query: str, max_docs: int = 5,
                      max_chars: int = 4000) -> str:
        """
        Build a context string from top docs to inject into AI prompt.
        """
        docs = self.search(query, top_k=max_docs)
        if not docs:
            return ""

        chunks = ["### Relevant previous cases:"]
        total = len(chunks[0])
        for d in docs:
            preview = d["text"][:600]
            chunk = f"\n[score={d['score']}] {preview}"
            if total + len(chunk) > max_chars:
                break
            chunks.append(chunk)
            total += len(chunk)
        return "\n".join(chunks)

    # ── Stats ──
    def stats(self) -> Dict:
        with self._lock:
            return {
                "documents": len(self.docs),
                "size_bytes": self.path.stat().st_size if self.path.exists() else 0,
            }

    def clear(self) -> int:
        with self._lock:
            n = len(self.docs)
            self.docs = []
        self._save()
        return n


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_STORE: Optional[RAGStore] = None
_LOCK = threading.Lock()


def get_rag() -> RAGStore:
    global _STORE
    with _LOCK:
        if _STORE is None:
            _STORE = RAGStore()
        return _STORE


# ─────────────────────────────────────────
# High-level: ask with RAG
# ─────────────────────────────────────────
def ask_with_rag(question: str, system: str = "You are an expert bug bounty hunter.",
                 json_mode: bool = True, timeout: int = 60,
                 use_cache: bool = True) -> Optional[Dict]:
    """
    Enrich question with RAG context before sending to AI.
    """
    try:
        from core.ai_engine import ask_ai, is_ai_available
    except Exception:
        return None
    if not is_ai_available():
        return None

    rag = get_rag()
    context = rag.build_context(question, max_docs=5, max_chars=3000)

    if context:
        enriched = f"{context}\n\n### Now answer:\n{question}"
    else:
        enriched = question

    return ask_ai(enriched, system=system, json_mode=json_mode, timeout=timeout)


# ─────────────────────────────────────────
# Bulk ingestion helpers
# ─────────────────────────────────────────
def ingest_reports_dir(directory: str) -> int:
    """
    Ingest all .md / .json files from a reports directory.
    """
    rag = get_rag()
    count = 0
    root = Path(directory)
    if not root.exists():
        return 0
    for p in root.rglob("*.md"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
            if len(text) > 50:
                rid = rag.add(text, metadata={"source": str(p), "type": "report"})
                if rid:
                    count += 1
        except Exception:
            continue
    return count


def ingest_cve(cve_id: str, description: str) -> str:
    """Ingest a CVE description."""
    rag = get_rag()
    return rag.add(
        f"CVE {cve_id}: {description}",
        metadata={"type": "cve", "cve_id": cve_id}
    )


def ingest_finding(finding: Dict) -> str:
    """Ingest a confirmed finding for future learning."""
    rag = get_rag()
    text = json.dumps(finding, ensure_ascii=False)
    return rag.add(text, metadata={"type": "finding"})


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI RAG store")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--add", help="Add text document")
    p.add_argument("--search", help="Search query")
    p.add_argument("--context", help="Build context for query")
    p.add_argument("--clear", action="store_true")
    p.add_argument("--ingest-dir", help="Ingest all reports in a directory")
    args = p.parse_args()

    rag = get_rag()
    if args.stats:
        print(json.dumps(rag.stats(), indent=2))
    elif args.clear:
        print(f"Cleared {rag.clear()} docs")
    elif args.add:
        rid = rag.add(args.add)
        print(f"Added: {rid}")
    elif args.search:
        results = rag.search(args.search, top_k=5)
        print(json.dumps(results, indent=2, default=str))
    elif args.context:
        print(rag.build_context(args.context))
    elif args.ingest_dir:
        n = ingest_reports_dir(args.ingest_dir)
        print(f"Ingested {n} reports")
    else:
        print(json.dumps(rag.stats(), indent=2))