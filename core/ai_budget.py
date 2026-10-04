"""
core/ai_budget.py
-----------------
Token budget manager for AI calls.

Tracks usage per day / per scan.
Refuses calls when budget is exhausted.
Estimates cost in USD.
"""

import json
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config

log = get_logger("ai_budget")
cfg = get_config()


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
BUDGET_FILE = Path(".cache/ai_budget.json")

# Default budgets
DEFAULT_DAILY_TOKENS = 500_000      # 500K tokens/day
DEFAULT_SCAN_TOKENS = 100_000       # 100K tokens/scan
DEFAULT_MONTHLY_TOKENS = 10_000_000 # 10M/month

# Cost estimates (USD per 1M tokens, aggregated)
COST_PER_M_TOKENS = {
    "commandcode": 0.30,
    "deepseek":    0.15,
    "openai":      2.50,
    "anthropic":   3.00,
    "default":     0.20,
}


# ─────────────────────────────────────────
# Budget manager
# ─────────────────────────────────────────
class AIBudget:
    def __init__(self, path: Path = BUDGET_FILE):
        self.path = path
        self._lock = threading.Lock()
        self.data = self._load()

    def _load(self) -> Dict:
        if not self.path.exists():
            return {
                "daily": {},
                "monthly": {},
                "current_scan": None,
                "limits": {
                    "daily_tokens": DEFAULT_DAILY_TOKENS,
                    "scan_tokens": DEFAULT_SCAN_TOKENS,
                    "monthly_tokens": DEFAULT_MONTHLY_TOKENS,
                },
            }
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("limits", {})
            data["limits"].setdefault("daily_tokens", DEFAULT_DAILY_TOKENS)
            data["limits"].setdefault("scan_tokens", DEFAULT_SCAN_TOKENS)
            data["limits"].setdefault("monthly_tokens", DEFAULT_MONTHLY_TOKENS)
            data.setdefault("daily", {})
            data.setdefault("monthly", {})
            data.setdefault("current_scan", None)
            return data
        except Exception:
            return {
                "daily": {}, "monthly": {}, "current_scan": None,
                "limits": {
                    "daily_tokens": DEFAULT_DAILY_TOKENS,
                    "scan_tokens": DEFAULT_SCAN_TOKENS,
                    "monthly_tokens": DEFAULT_MONTHLY_TOKENS,
                },
            }

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            log.debug(f"budget save failed: {e}")

    # ── Date keys ──
    def _today(self) -> str:
        return datetime.utcnow().strftime("%Y-%m-%d")

    def _month(self) -> str:
        return datetime.utcnow().strftime("%Y-%m")

    # ── Access ──
    def daily_used(self) -> int:
        return self.data["daily"].get(self._today(), {}).get("tokens", 0)

    def monthly_used(self) -> int:
        return self.data["monthly"].get(self._month(), {}).get("tokens", 0)

    def scan_used(self) -> int:
        scan = self.data.get("current_scan") or {}
        return scan.get("tokens", 0)

    # ── Limits ──
    def daily_limit(self) -> int:
        return self.data["limits"].get("daily_tokens", DEFAULT_DAILY_TOKENS)

    def scan_limit(self) -> int:
        return self.data["limits"].get("scan_tokens", DEFAULT_SCAN_TOKENS)

    def monthly_limit(self) -> int:
        return self.data["limits"].get("monthly_tokens", DEFAULT_MONTHLY_TOKENS)

    # ── Check ──
    def can_spend(self, tokens: int) -> bool:
        if self.daily_used() + tokens > self.daily_limit():
            return False
        if self.monthly_used() + tokens > self.monthly_limit():
            return False
        if self.scan_used() + tokens > self.scan_limit():
            return False
        return True

    def why_blocked(self) -> Optional[str]:
        if self.daily_used() >= self.daily_limit():
            return "daily_limit_reached"
        if self.monthly_used() >= self.monthly_limit():
            return "monthly_limit_reached"
        if self.scan_used() >= self.scan_limit():
            return "scan_limit_reached"
        return None

    # ── Spend ──
    def spend(self, tokens: int, provider: str = "default") -> bool:
        """
        Record token usage. Returns True if within budget.
        """
        if not self.can_spend(tokens):
            warn(f"AI budget exceeded ({self.why_blocked()})")
            return False

        with self._lock:
            today = self._today()
            month = self._month()

            # Daily
            day = self.data["daily"].setdefault(today, {"tokens": 0, "calls": 0, "cost": 0.0})
            day["tokens"] += tokens
            day["calls"] += 1
            day["cost"] += self._estimate_cost(tokens, provider)

            # Monthly
            mon = self.data["monthly"].setdefault(month, {"tokens": 0, "calls": 0, "cost": 0.0})
            mon["tokens"] += tokens
            mon["calls"] += 1
            mon["cost"] += self._estimate_cost(tokens, provider)

            # Current scan
            if self.data["current_scan"]:
                self.data["current_scan"]["tokens"] = self.data["current_scan"].get("tokens", 0) + tokens
                self.data["current_scan"]["calls"] = self.data["current_scan"].get("calls", 0) + 1

            # Prune old days (keep 30)
            self._prune_old()

            self._save()
        return True

    def _estimate_cost(self, tokens: int, provider: str) -> float:
        rate = COST_PER_M_TOKENS.get(provider, COST_PER_M_TOKENS["default"])
        return round((tokens / 1_000_000) * rate, 6)

    def _prune_old(self) -> None:
        # Keep last 30 days
        days = sorted(self.data["daily"].keys())
        if len(days) > 30:
            for d in days[:-30]:
                self.data["daily"].pop(d, None)
        # Keep last 12 months
        months = sorted(self.data["monthly"].keys())
        if len(months) > 12:
            for m in months[:-12]:
                self.data["monthly"].pop(m, None)

    # ── Scan lifecycle ──
    def start_scan(self, scan_name: str = "") -> None:
        with self._lock:
            self.data["current_scan"] = {
                "name": scan_name,
                "started_at": datetime.utcnow().isoformat(),
                "tokens": 0,
                "calls": 0,
            }
            self._save()

    def end_scan(self) -> Optional[Dict]:
        with self._lock:
            scan = self.data.get("current_scan")
            self.data["current_scan"] = None
            self._save()
        return scan

    # ── Stats ──
    def stats(self) -> Dict:
        today = self._today()
        month = self._month()
        day = self.data["daily"].get(today, {})
        mon = self.data["monthly"].get(month, {})
        scan = self.data.get("current_scan") or {}

        return {
            "today": {
                "tokens_used": day.get("tokens", 0),
                "tokens_limit": self.daily_limit(),
                "percent": round((day.get("tokens", 0) / self.daily_limit()) * 100, 1) if self.daily_limit() else 0,
                "calls": day.get("calls", 0),
                "cost_usd": round(day.get("cost", 0.0), 4),
            },
            "this_month": {
                "tokens_used": mon.get("tokens", 0),
                "tokens_limit": self.monthly_limit(),
                "percent": round((mon.get("tokens", 0) / self.monthly_limit()) * 100, 1) if self.monthly_limit() else 0,
                "calls": mon.get("calls", 0),
                "cost_usd": round(mon.get("cost", 0.0), 4),
            },
            "current_scan": {
                "name": scan.get("name", ""),
                "tokens_used": scan.get("tokens", 0),
                "tokens_limit": self.scan_limit(),
                "calls": scan.get("calls", 0),
            } if scan else None,
        }

    def print_report(self) -> None:
        s = self.stats()
        info("AI budget status:")
        t = s["today"]
        log.info(f"  Today:   {t['tokens_used']:>8} / {t['tokens_limit']:>8} tokens "
                 f"({t['percent']}%) — {t['calls']} calls — ${t['cost_usd']}")
        m = s["this_month"]
        log.info(f"  Month:   {m['tokens_used']:>8} / {m['tokens_limit']:>8} tokens "
                 f"({m['percent']}%) — {m['calls']} calls — ${m['cost_usd']}")
        if s["current_scan"]:
            cs = s["current_scan"]
            log.info(f"  Scan:    {cs['tokens_used']:>8} / {cs['tokens_limit']:>8} tokens "
                     f"({cs['calls']} calls)")


# ─────────────────────────────────────────
# Singleton + wrapper
# ─────────────────────────────────────────
_BUDGET: Optional[AIBudget] = None
_LOCK = threading.Lock()


def get_ai_budget() -> AIBudget:
    global _BUDGET
    with _LOCK:
        if _BUDGET is None:
            _BUDGET = AIBudget()
        return _BUDGET


def check_and_spend(tokens: int, provider: str = "default") -> bool:
    """Shortcut for budget checks before AI call."""
    return get_ai_budget().spend(tokens, provider)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI budget manager")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--reset-scan", action="store_true")
    p.add_argument("--test", action="store_true")
    args = p.parse_args()

    b = get_ai_budget()
    if args.stats:
        print(json.dumps(b.stats(), indent=2))
    elif args.reset_scan:
        b.end_scan()
        ok("Scan reset")
    elif args.test:
        b.print_report()
        b.spend(5000, "deepseek")
        b.print_report()
    else:
        b.print_report()