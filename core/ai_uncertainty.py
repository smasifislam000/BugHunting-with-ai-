"""
core/ai_uncertainty.py
----------------------
Confidence calibration and threshold-based decisions.

Rules:
  - confidence >= 90 → auto-confirm
  - 70 <= confidence < 90 → flag for manual review
  - 40 <= confidence < 70 → mark uncertain, keep pending
  - confidence < 40 → drop as false positive

Also provides sampling-based confidence (ask AI N times).
"""

import json
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from statistics import mean, stdev

from core.logger import get_logger, info, ok, warn

log = get_logger("ai_uncertainty")


# ─────────────────────────────────────────
# Thresholds
# ─────────────────────────────────────────
THRESHOLD_AUTO_CONFIRM = 90
THRESHOLD_MANUAL_REVIEW = 70
THRESHOLD_UNCERTAIN = 40


# ─────────────────────────────────────────
# Decision
# ─────────────────────────────────────────
def decision_from_confidence(confidence: int) -> str:
    if confidence >= THRESHOLD_AUTO_CONFIRM:
        return "auto_confirm"
    if confidence >= THRESHOLD_MANUAL_REVIEW:
        return "manual_review"
    if confidence >= THRESHOLD_UNCERTAIN:
        return "uncertain"
    return "drop"


def severity_confidence_interval(samples: List[float]) -> Tuple[float, float, float]:
    """
    Return (mean, low, high) with 1-sigma range.
    """
    if not samples:
        return 0.0, 0.0, 0.0
    if len(samples) == 1:
        return samples[0], samples[0], samples[0]
    m = mean(samples)
    s = stdev(samples) if len(samples) > 1 else 0.0
    return m, max(0.0, m - s), min(100.0, m + s)


# ─────────────────────────────────────────
# Sampling-based confidence
# ─────────────────────────────────────────
def _hash(obj: Any) -> str:
    try:
        s = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    except Exception:
        s = str(obj)
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()


def sample_confidence(question: str, samples: int = 3,
                      timeout: int = 60) -> Optional[Dict]:
    """
    Ask the AI the same question N times and measure agreement.
    Higher agreement → higher confidence.
    """
    if samples < 2:
        samples = 2

    try:
        from core.ai_engine import ask_ai
    except Exception:
        return None

    answers: List[Any] = []
    confidences: List[int] = []

    for i in range(samples):
        # Slight wording variation to avoid cache
        prefix = f"[run {i+1}/{samples}] " if i > 0 else ""
        ans = ask_ai(prefix + question, json_mode=True, timeout=timeout)
        if ans is None:
            continue
        answers.append(ans)
        # Ask AI for its own confidence
        conf_prompt = (
            f"What is your confidence (0-100) in this answer?\n"
            f"Question: {question}\n"
            f"Answer: {json.dumps(ans)[:1000]}\n"
            f'Return JSON: {{"confidence": <int>}}'
        )
        c = ask_ai(conf_prompt, json_mode=True, timeout=timeout)
        if c and isinstance(c, dict) and "confidence" in c:
            try:
                confidences.append(int(c["confidence"]))
            except Exception:
                confidences.append(50)

    if not answers:
        return None

    # Agreement
    hashes = [_hash(a) for a in answers]
    unique = set(hashes)
    agreement = (len(hashes) - len(unique) + 1) / len(hashes)  # 0..1

    m, low, high = severity_confidence_interval([float(c) for c in confidences]) \
        if confidences else (50.0, 50.0, 50.0)

    # Blend: self-reported + agreement
    blended = (m * 0.5) + (agreement * 100 * 0.5)

    return {
        "samples": samples,
        "answers_received": len(answers),
        "agreement": round(agreement, 3),
        "self_confidence_mean": round(m, 1),
        "self_confidence_range": [round(low, 1), round(high, 1)],
        "blended_confidence": round(blended, 1),
        "decision": decision_from_confidence(int(blended)),
        "answers": answers,
    }


# ─────────────────────────────────────────
# Triage helper
# ─────────────────────────────────────────
def triage_with_uncertainty(finding: Dict, timeout: int = 60) -> Dict:
    """
    Ask AI to triage a finding, then apply uncertainty rules.
    """
    question = f"""
Analyze this finding and decide:

Finding:
{json.dumps(finding, indent=2)[:3000]}

Return JSON:
{{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "confidence": 0-100,
  "reasoning": "...",
  "next_step": "..."
}}
"""
    result = sample_confidence(question, samples=2, timeout=timeout)
    if not result or not result.get("answers"):
        return {"error": "no AI result"}

    # Take the first answer as base
    base = result["answers"][0]
    if not isinstance(base, dict):
        return {"error": "invalid answer format"}

    base["ai_confidence"] = base.get("confidence", 50)
    base["blended_confidence"] = result["blended_confidence"]
    base["agreement"] = result["agreement"]
    base["decision"] = result["decision"]

    return base


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI uncertainty quantification")
    p.add_argument("--question", help="Sample confidence on a question")
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--decision", type=int, help="Get decision from confidence")
    args = p.parse_args()

    if args.decision is not None:
        print(decision_from_confidence(args.decision))
    elif args.question:
        r = sample_confidence(args.question, samples=args.samples)
        print(json.dumps(r, indent=2, default=str) if r else "No result")
    else:
        print(json.dumps({
            "thresholds": {
                "auto_confirm": THRESHOLD_AUTO_CONFIRM,
                "manual_review": THRESHOLD_MANUAL_REVIEW,
                "uncertain": THRESHOLD_UNCERTAIN,
            }
        }, indent=2))