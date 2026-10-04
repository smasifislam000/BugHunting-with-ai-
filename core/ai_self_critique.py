"""
core/ai_self_critique.py
------------------------
Self-critique and adversarial prompting to reduce false positives.

Techniques:
  1. Self-critique: ask AI to critique its own answer.
  2. Adversarial: ask AI to prove the opposite (devil's advocate).
  3. Multi-perspective: get 2-3 independent answers and compare.
"""

import json
import hashlib
from typing import Dict, List, Optional, Any

from core.logger import get_logger, info, ok, warn, skip

log = get_logger("ai_self_critique")


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def _call(prompt: str, system: str = "You are an expert bug bounty hunter.",
          json_mode: bool = True, timeout: int = 60) -> Optional[Any]:
    try:
        from core.ai_engine import ask_ai
        return ask_ai(prompt, system=system, json_mode=json_mode, timeout=timeout)
    except Exception as e:
        log.debug(f"call failed: {e}")
        return None


def _hash(obj: Any) -> str:
    try:
        s = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    except Exception:
        s = str(obj)
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()


# ─────────────────────────────────────────
# 1. Self-critique
# ─────────────────────────────────────────
def self_critique(question: str, first_answer: Any,
                  timeout: int = 60) -> Optional[Dict]:
    """
    Ask the AI to critique its own first answer.
    """
    prompt = f"""
You previously answered this question:

Question:
{question}

Your answer (as JSON):
{json.dumps(first_answer, indent=2, ensure_ascii=False)[:3000]}

Now, act as a STRICT CRITIC. Review your own answer and:

1. Identify any false assumptions.
2. Identify anything that might be a false positive.
3. Identify missing considerations.
4. If you would change your answer, provide the corrected version.

Return JSON:
{{
  "critique": "...",
  "confidence_in_original": 0-100,
  "issues": ["...", "..."],
  "revised_answer": {{ ... }} or null
}}
"""
    return _call(prompt, timeout=timeout)


# ─────────────────────────────────────────
# 2. Adversarial (devil's advocate)
# ─────────────────────────────────────────
def adversarial_check(claim: str, evidence: str = "",
                      timeout: int = 60) -> Optional[Dict]:
    """
    Ask the AI to argue AGAINST the claim.
    If it succeeds → claim is weak.
    """
    prompt = f"""
Your job is to be a DEVIL'S ADVOCATE.
Attack this claim and try to disprove it. Be brutally honest.

Claim:
{claim}

Evidence (if any):
{evidence[:2000]}

Return JSON:
{{
  "counter_arguments": ["...", "..."],
  "is_claim_likely_false": true/false,
  "weakest_point": "...",
  "confidence_claim_is_false": 0-100
}}
"""
    return _call(prompt, timeout=timeout)


# ─────────────────────────────────────────
# 3. Multi-perspective
# ─────────────────────────────────────────
def multi_perspective(question: str, perspectives: Optional[List[str]] = None,
                      timeout: int = 60) -> Dict:
    """
    Ask the same question from multiple expert perspectives.
    """
    perspectives = perspectives or [
        "a senior penetration tester",
        "a bug bounty triage analyst",
        "the target's security engineer",
    ]
    results = []
    for p in perspectives:
        sys = f"You are {p}. Answer strictly from that role."
        ans = _call(question, system=sys, timeout=timeout)
        if ans is not None:
            results.append({"perspective": p, "answer": ans})

    # Check agreement
    hashes = {}
    for r in results:
        h = _hash(r["answer"])
        hashes.setdefault(h, []).append(r["perspective"])

    best_hash = max(hashes, key=lambda k: len(hashes[k])) if hashes else ""
    agree = len(hashes.get(best_hash, [])) if best_hash else 0
    consensus = agree > len(results) / 2 if results else False

    return {
        "perspectives": results,
        "consensus": consensus,
        "agree_count": agree,
        "total": len(results),
    }


# ─────────────────────────────────────────
# Combined: robust answer
# ─────────────────────────────────────────
def robust_answer(question: str, timeout: int = 60) -> Dict:
    """
    Full pipeline:
      1. Get initial answer
      2. Self-critique
      3. If critique flags issue → get revised answer
      4. Adversarial check
      5. Return best answer + confidence
    """
    initial = _call(question, timeout=timeout)
    if initial is None:
        return {"error": "no AI available"}

    critique = self_critique(question, initial, timeout=timeout)

    final = initial
    if critique and critique.get("revised_answer"):
        final = critique["revised_answer"]

    # Adversarial test only if confidence is low
    conf = 50
    if critique:
        conf = int(critique.get("confidence_in_original", 50))

    adversarial = None
    if conf < 80:
        adversarial = adversarial_check(
            json.dumps(final)[:1000], timeout=timeout
        )

    # Determine final confidence
    final_conf = conf
    if adversarial:
        false_conf = int(adversarial.get("confidence_claim_is_false", 0))
        if false_conf > 70:
            final_conf = min(final_conf, 40)
        elif false_conf > 40:
            final_conf = min(final_conf, 65)

    return {
        "initial": initial,
        "critique": critique,
        "adversarial": adversarial,
        "final_answer": final,
        "final_confidence": final_conf,
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI self-critique")
    p.add_argument("--question", help="Run robust_answer")
    p.add_argument("--claim", help="Run adversarial check")
    p.add_argument("--multi", help="Run multi-perspective")
    args = p.parse_args()

    if args.question:
        r = robust_answer(args.question)
        print(json.dumps(r, indent=2, default=str))
    elif args.claim:
        r = adversarial_check(args.claim)
        print(json.dumps(r, indent=2, default=str))
    elif args.multi:
        r = multi_perspective(args.multi)
        print(json.dumps(r, indent=2, default=str))
    else:
        print("Use --question, --claim, or --multi")