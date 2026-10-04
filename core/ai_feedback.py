"""
core/ai_feedback.py
-------------------
Feedback loop for AI-generated answers.

Stores which AI answers were accepted (true positive) or rejected
(false positive) and uses this to improve future prompts:
  - Adds few-shot examples from accepted answers
  - Adds negative examples from rejected answers
  - Tracks accuracy per task type
"""

import json
import time
import hashlib
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.logger import get_logger, info, ok, warn

log = get_logger("ai_feedback")


# ─────────────────────────────────────────
# Storage
# ─────────────────────────────────────────
FEEDBACK_FILE = Path(".cache/ai_feedback.json")


class AIFeedback:
    def __init__(self, path: Path = FEEDBACK_FILE):
        self.path = path
        self._lock = threading.Lock()
        self.data = self._load()

    def _load(self) -> Dict:
        if not self.path.exists():
            return {
                "positive": [],   # list of {task, prompt, answer}
                "negative": [],
                "stats": {"pos": 0, "neg": 0},
            }
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            d.setdefault("positive", [])
            d.setdefault("negative", [])
            d.setdefault("stats", {"pos": 0, "neg": 0})
            return d
        except Exception:
            return {"positive": [], "negative": [],
                    "stats": {"pos": 0, "neg": 0}}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.debug(f"feedback save failed: {e}")

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:12]

    # ── Record ──
    def record(self, task: str, prompt: str, answer: Any,
               accepted: bool) -> None:
        entry = {
            "id": self._hash(prompt + json.dumps(answer, default=str)[:200]),
            "task": task,
            "prompt": prompt[:1500],
            "answer": answer if isinstance(answer, (dict, list)) else str(answer)[:1500],
            "ts": time.time(),
        }
        with self._lock:
            if accepted:
                self.data["positive"].append(entry)
                self.data["stats"]["pos"] = self.data["stats"].get("pos", 0) + 1
            else:
                self.data["negative"].append(entry)
                self.data["stats"]["neg"] = self.data["stats"].get("neg", 0) + 1

            # Trim
            self.data["positive"] = self.data["positive"][-500:]
            self.data["negative"] = self.data["negative"][-500:]
        self._save()

    # ── Few-shot builder ──
    def build_few_shot(self, task: str, max_examples: int = 2,
                       max_chars: int = 2000) -> str:
        """
        Build a few-shot block from previous accepted answers for this task.
        """
        with self._lock:
            positives = [e for e in self.data["positive"] if e.get("task") == task]
            negatives = [e for e in self.data["negative"] if e.get("task") == task]

        if not positives:
            return ""

        parts = ["### Examples of previously ACCEPTED answers (learn from these):"]
        count = 0
        for e in reversed(positives[-max_examples:]):
            snippet = (
                f"\nQ: {e['prompt'][:400]}\n"
                f"A: {json.dumps(e['answer'], ensure_ascii=False)[:400]}"
            )
            if sum(len(p) for p in parts) + len(snippet) > max_chars:
                break
            parts.append(snippet)
            count += 1

        # Add one negative if available
        if negatives:
            e = negatives[-1]
            snippet = (
                f"\n### Example of REJECTED answer (do NOT produce this):"
                f"\nQ: {e['prompt'][:300]}"
                f"\nA (wrong): {json.dumps(e['answer'], ensure_ascii=False)[:300]}"
            )
            if sum(len(p) for p in parts) + len(snippet) <= max_chars:
                parts.append(snippet)

        return "\n".join(parts) if count else ""

    # ── Stats ──
    def stats(self) -> Dict:
        with self._lock:
            pos = self.data["stats"].get("pos", 0)
            neg = self.data["stats"].get("neg", 0)
            total = pos + neg
            by_task: Dict[str, Dict[str, int]] = {}
            for e in self.data["positive"]:
                t = e.get("task", "unknown")
                by_task.setdefault(t, {"pos": 0, "neg": 0})
                by_task[t]["pos"] += 1
            for e in self.data["negative"]:
                t = e.get("task", "unknown")
                by_task.setdefault(t, {"pos": 0, "neg": 0})
                by_task[t]["neg"] += 1

        return {
            "positive_total": pos,
            "negative_total": neg,
            "total": total,
            "accuracy": round(pos / total, 3) if total else 0.0,
            "by_task": by_task,
        }

    def clear(self) -> None:
        with self._lock:
            self.data = {
                "positive": [],
                "negative": [],
                "stats": {"pos": 0, "neg": 0},
            }
        self._save()


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_FEEDBACK: Optional[AIFeedback] = None
_LOCK = threading.Lock()


def get_ai_feedback() -> AIFeedback:
    global _FEEDBACK
    with _LOCK:
        if _FEEDBACK is None:
            _FEEDBACK = AIFeedback()
        return _FEEDBACK


def record_accepted(task: str, prompt: str, answer: Any) -> None:
    get_ai_feedback().record(task, prompt, answer, accepted=True)


def record_rejected(task: str, prompt: str, answer: Any) -> None:
    get_ai_feedback().record(task, prompt, answer, accepted=False)


# ─────────────────────────────────────────
# Wrapper: enriched prompt with few-shot
# ─────────────────────────────────────────
def ask_with_feedback(task: str, prompt: str,
                      system: str = "You are an expert bug bounty hunter.",
                      json_mode: bool = True,
                      timeout: int = 60) -> Optional[Dict]:
    fb = get_ai_feedback()
    few_shot = fb.build_few_shot(task)

    full_prompt = prompt
    if few_shot:
        full_prompt = f"{few_shot}\n\n### Now answer:\n{prompt}"

    try:
        from core.ai_engine import ask_ai
        return ask_ai(full_prompt, system=system,
                      json_mode=json_mode, timeout=timeout)
    except Exception as e:
        log.debug(f"ask_with_feedback failed: {e}")
        return None


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI feedback loop")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--clear", action="store_true")
    p.add_argument("--accept", nargs=3, metavar=("TASK", "PROMPT", "ANSWER"))
    p.add_argument("--reject", nargs=3, metavar=("TASK", "PROMPT", "ANSWER"))
    args = p.parse_args()

    fb = get_ai_feedback()
    if args.clear:
        fb.clear()
        ok("Feedback cleared")
    elif args.accept:
        fb.record(args.accept[0], args.accept[1], args.accept[2], True)
        ok("Recorded accepted")
    elif args.reject:
        fb.record(args.reject[0], args.reject[1], args.reject[2], False)
        ok("Recorded rejected")
    else:
        print(json.dumps(fb.stats(), indent=2))