"""
core/time_budget.py
-------------------
Time budget manager for scans.
Tracks elapsed time per phase, warns when approaching limit, aborts if exceeded.
"""

import time
import threading
from contextlib import contextmanager
from typing import Dict, List, Optional
from datetime import datetime, timedelta

from core.logger import get_logger, info, warn, skip

log = get_logger("time_budget")


# ─────────────────────────────────────────
# Default budgets (in seconds)
# ─────────────────────────────────────────
DEFAULT_BUDGET = {
    "recon":         900,    # 15 min
    "scanner":       1800,   # 30 min
    "modules":       2400,   # 40 min
    "intel":         600,    # 10 min
    "triage":        300,    # 5 min
    "reports":       300,    # 5 min
    "total":         7200,   # 2 hours overall
}


class BudgetExceeded(Exception):
    """Raised when a phase budget is exceeded."""
    pass


class TimeBudget:
    def __init__(self, budgets: Optional[Dict[str, int]] = None):
        self.budgets = dict(DEFAULT_BUDGET)
        if budgets:
            self.budgets.update(budgets)
        self.started: Dict[str, float] = {}
        self.elapsed: Dict[str, float] = {}
        self.finished: Dict[str, float] = {}
        self._scan_start = time.time()
        self._lock = threading.Lock()
        self._aborted = False

    # ── Phase tracking ──
    def start(self, phase: str) -> None:
        with self._lock:
            self.started[phase] = time.time()
            log.debug(f"Budget start: {phase}")

    def stop(self, phase: str) -> float:
        with self._lock:
            if phase not in self.started:
                return 0.0
            dur = time.time() - self.started[phase]
            self.elapsed[phase] = self.elapsed.get(phase, 0) + dur
            self.finished[phase] = time.time()
            log.debug(f"Budget stop: {phase} = {dur:.1f}s")
            return dur

    def remaining(self, phase: str) -> float:
        """Seconds remaining for a phase (may be negative)."""
        budget = self.budgets.get(phase, 3600)
        used = self.elapsed.get(phase, 0)
        # If currently running, add current session
        if phase in self.started and phase not in self.finished:
            used += time.time() - self.started[phase]
        return budget - used

    def is_exceeded(self, phase: str) -> bool:
        return self.remaining(phase) <= 0

    def check(self, phase: str) -> None:
        """Raise BudgetExceeded if phase is over budget."""
        if self.is_exceeded(phase):
            raise BudgetExceeded(f"Time budget exceeded for phase '{phase}'")

    def should_skip(self, phase: str, threshold: float = 0.2) -> bool:
        """
        Return True if remaining time is below threshold (default 20%) of budget.
        Useful to skip optional modules.
        """
        budget = self.budgets.get(phase, 3600)
        if budget <= 0:
            return True
        return self.remaining(phase) < (budget * threshold)

    # ── Total scan time ──
    def total_elapsed(self) -> float:
        return time.time() - self._scan_start

    def total_remaining(self) -> float:
        return self.budgets.get("total", 7200) - self.total_elapsed()

    def is_total_exceeded(self) -> bool:
        return self.total_remaining() <= 0

    def abort_scan(self) -> None:
        with self._lock:
            self._aborted = True

    def is_aborted(self) -> bool:
        return self._aborted

    # ── Report ──
    def summary(self) -> Dict:
        return {
            "total_elapsed_sec": round(self.total_elapsed(), 1),
            "total_budget_sec": self.budgets.get("total", 7200),
            "phases": {
                p: {
                    "elapsed_sec": round(self.elapsed.get(p, 0), 1),
                    "budget_sec": self.budgets.get(p, 0),
                    "remaining_sec": round(self.remaining(p), 1),
                }
                for p in self.budgets
                if p != "total"
            },
            "aborted": self._aborted,
        }

    def print_summary(self) -> None:
        s = self.summary()
        info(f"Total elapsed: {s['total_elapsed_sec']:.1f}s / {s['total_budget_sec']}s")
        for phase, data in s["phases"].items():
            status = "✓" if data["remaining_sec"] > 0 else "✗"
            log.info(f"  {status} {phase}: {data['elapsed_sec']:.1f}s / {data['budget_sec']}s")


# ─────────────────────────────────────────
# Context manager
# ─────────────────────────────────────────
@contextmanager
def budget_phase(budget: TimeBudget, phase: str, strict: bool = False):
    """
    Usage:
        with budget_phase(budget, "recon", strict=True):
            do_recon()
    If strict=True and time exceeded, raises BudgetExceeded.
    Otherwise just logs warning.
    """
    budget.start(phase)
    try:
        yield budget
    except BudgetExceeded:
        if strict:
            raise
        warn(f"Phase '{phase}' exceeded budget (soft)")
    finally:
        budget.stop(phase)


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_BUDGET: Optional[TimeBudget] = None


def get_budget() -> TimeBudget:
    global _BUDGET
    if _BUDGET is None:
        _BUDGET = TimeBudget()
    return _BUDGET


def reset_budget(budgets: Optional[Dict[str, int]] = None) -> TimeBudget:
    global _BUDGET
    _BUDGET = TimeBudget(budgets)
    return _BUDGET


# ─────────────────────────────────────────
# Adaptive time estimation
# ─────────────────────────────────────────
def estimate_phase_seconds(phase: str, target_count: int) -> int:
    """
    Rough estimate of how long a phase will take.
    target_count = number of URLs/hosts/etc.
    """
    per_unit = {
        "recon": 0.5,
        "scanner": 2.0,
        "modules": 5.0,
        "intel": 1.0,
        "triage": 3.0,
        "reports": 0.2,
    }.get(phase, 1.0)
    return int(target_count * per_unit)


def suggest_budget(num_hosts: int, num_urls: int, num_params: int) -> Dict[str, int]:
    """
    Given recon stats, suggest a per-phase budget.
    """
    return {
        "recon":    max(300, min(1800, num_hosts * 2)),
        "scanner":  max(600, min(3600, num_urls * 3)),
        "modules":  max(900, min(5400, num_params * 6)),
        "intel":    max(120, min(900, num_hosts * 5)),
        "triage":   max(60,  min(600, num_urls // 10)),
        "reports":  max(60,  min(600, num_urls // 20)),
        "total":    max(1800, num_urls * 8),
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse, json, time
    p = argparse.ArgumentParser(description="Time budget")
    p.add_argument("--test", action="store_true")
    p.add_argument("--suggest", help="Format: hosts,urls,params")
    args = p.parse_args()

    if args.suggest:
        try:
            h, u, pa = [int(x) for x in args.suggest.split(",")]
            print(json.dumps(suggest_budget(h, u, pa), indent=2))
        except Exception:
            print("Usage: --suggest HOSTS,URLS,PARAMS")

    elif args.test:
        b = TimeBudget({"recon": 3, "scanner": 2})
        with budget_phase(b, "recon", strict=False):
            time.sleep(1)
            print("recon phase done")
        with budget_phase(b, "recon", strict=False):
            time.sleep(3)
            print("recon phase exceeded? (should warn)")
        b.print_summary()
