"""
core/feedback.py
----------------
Feedback loop for findings.

Stores user decisions (True Positive / False Positive) and lets the
framework learn patterns of what to prioritize or skip in future scans.
"""

import json
import re
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import Counter

from core.logger import get_logger, info, ok, warn
from core.utils import save_json, load_json, ensure_dir

log = get_logger("feedback")


# ─────────────────────────────────────────
# Storage
# ─────────────────────────────────────────
FEEDBACK_FILE = Path(".cache/feedback.json")


class FeedbackStore:
    def __init__(self, path: Path = FEEDBACK_FILE):
        self.path = path
        self._lock = threading.Lock()
        self._data: Dict = self._load()

    def _load(self) -> Dict:
        if not self.path.exists():
            return {
                "true_positives": [],   # list of finding signatures
                "false_positives": [],
                "stats": {"tp": 0, "fp": 0, "skipped": 0},
                "patterns": {
                    "tp_templates": {},
                    "fp_templates": {},
                },
            }
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"true_positives": [], "false_positives": [],
                    "stats": {"tp": 0, "fp": 0, "skipped": 0},
                    "patterns": {"tp_templates": {}, "fp_templates": {}}}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            log.debug(f"feedback save failed: {e}")

    # ── Signature ──
    @staticmethod
    def signature(finding: Dict) -> str:
        """
        A stable signature for a finding — template_id + url + param.
        """
        parts = [
            str(finding.get("vuln_type", "")).lower(),
            str(finding.get("template_id", "")).lower(),
            FeedbackStore._normalize_url(finding.get("url", "")),
            str(finding.get("param", "")).lower(),
        ]
        return "|".join(p for p in parts if p)

    @staticmethod
    def _normalize_url(url: str) -> str:
        u = url.lower()
        u = re.sub(r"https?://", "", u)
        u = re.sub(r"[?#].*$", "", u)  # strip query/fragment
        u = re.sub(r"\d+", "N", u)     # normalize numbers
        return u[:200]

    # ── Record decision ──
    def record_true_positive(self, finding: Dict) -> None:
        sig = self.signature(finding)
        with self._lock:
            if sig not in self._data["true_positives"]:
                self._data["true_positives"].append(sig)
            self._data["stats"]["tp"] = self._data["stats"].get("tp", 0) + 1

            # Track template pattern
            tid = str(finding.get("template_id", finding.get("vuln_type", ""))).lower()
            if tid:
                pats = self._data["patterns"]["tp_templates"]
                pats[tid] = pats.get(tid, 0) + 1
            self._save()

    def record_false_positive(self, finding: Dict) -> None:
        sig = self.signature(finding)
        with self._lock:
            if sig not in self._data["false_positives"]:
                self._data["false_positives"].append(sig)
            self._data["stats"]["fp"] = self._data["stats"].get("fp", 0) + 1

            tid = str(finding.get("template_id", finding.get("vuln_type", ""))).lower()
            if tid:
                pats = self._data["patterns"]["fp_templates"]
                pats[tid] = pats.get(tid, 0) + 1
            self._save()

    def record_skipped(self) -> None:
        with self._lock:
            self._data["stats"]["skipped"] = self._data["stats"].get("skipped", 0) + 1
            self._save()

    # ── Query ──
    def is_known_false_positive(self, finding: Dict) -> bool:
        sig = self.signature(finding)
        return sig in self._data["false_positives"]

    def is_known_true_positive(self, finding: Dict) -> bool:
        sig = self.signature(finding)
        return sig in self._data["true_positives"]

    def suggest_skip(self, finding: Dict, threshold: int = 5) -> bool:
        """
        If a template has produced many FPs and few TPs, suggest skipping.
        """
        tid = str(finding.get("template_id", finding.get("vuln_type", ""))).lower()
        if not tid:
            return False
        tp = self._data["patterns"]["tp_templates"].get(tid, 0)
        fp = self._data["patterns"]["fp_templates"].get(tid, 0)
        if fp >= threshold and (tp == 0 or fp / (tp + fp) > 0.9):
            return True
        return False

    def priority_score(self, finding: Dict) -> float:
        """
        Return 0.0 to 1.0 indicating likelihood of being a true positive.
        Based on past patterns.
        """
        tid = str(finding.get("template_id", finding.get("vuln_type", ""))).lower()
        if not tid:
            return 0.5
        tp = self._data["patterns"]["tp_templates"].get(tid, 0)
        fp = self._data["patterns"]["fp_templates"].get(tid, 0)
        total = tp + fp
        if total == 0:
            return 0.5
        return tp / total

    # ── Stats ──
    def stats(self) -> Dict:
        with self._lock:
            total = self._data["stats"].get("tp", 0) + self._data["stats"].get("fp", 0)
            return {
                "true_positives": self._data["stats"].get("tp", 0),
                "false_positives": self._data["stats"].get("fp", 0),
                "skipped": self._data["stats"].get("skipped", 0),
                "total_decisions": total,
                "accuracy_ratio": (
                    self._data["stats"].get("tp", 0) / total if total else 0.0
                ),
                "top_tp_templates": sorted(
                    self._data["patterns"]["tp_templates"].items(),
                    key=lambda x: -x[1]
                )[:10],
                "top_fp_templates": sorted(
                    self._data["patterns"]["fp_templates"].items(),
                    key=lambda x: -x[1]
                )[:10],
            }

    def reset(self) -> None:
        with self._lock:
            self._data = {
                "true_positives": [],
                "false_positives": [],
                "stats": {"tp": 0, "fp": 0, "skipped": 0},
                "patterns": {"tp_templates": {}, "fp_templates": {}},
            }
            self._save()


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_STORE: Optional[FeedbackStore] = None
_LOCK = threading.Lock()


def get_feedback() -> FeedbackStore:
    global _STORE
    with _LOCK:
        if _STORE is None:
            _STORE = FeedbackStore()
        return _STORE


# ─────────────────────────────────────────
# Batch triage helper
# ─────────────────────────────────────────
def auto_filter_findings(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Split a list of findings into buckets:
      - confirmed_known_tp
      - known_fp (should be dropped)
      - likely_fp (low priority)
      - priority (needs review)
    """
    store = get_feedback()
    result = {
        "known_tp": [],
        "known_fp": [],
        "likely_fp": [],
        "priority": [],
    }
    for f in findings:
        if store.is_known_true_positive(f):
            result["known_tp"].append(f)
        elif store.is_known_false_positive(f):
            result["known_fp"].append(f)
        elif store.suggest_skip(f):
            result["likely_fp"].append(f)
        else:
            result["priority"].append(f)
    return result


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Feedback store")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--reset", action="store_true")
    p.add_argument("--tp", help="URL to mark as true positive")
    p.add_argument("--fp", help="URL to mark as false positive")
    p.add_argument("--type", default="unknown", help="Vuln type for TP/FP")
    args = p.parse_args()

    store = get_feedback()
    if args.reset:
        store.reset()
        ok("Feedback reset")
    elif args.tp:
        store.record_true_positive({"url": args.tp, "vuln_type": args.type})
        ok(f"Marked TP: {args.tp}")
    elif args.fp:
        store.record_false_positive({"url": args.fp, "vuln_type": args.type})
        ok(f"Marked FP: {args.fp}")
    else:
        s = store.stats()
        print(json.dumps(s, indent=2))