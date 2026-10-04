"""
core/ai_checkpoint.py
---------------------
Human-in-the-loop checkpoint for critical findings.

Rule (your setup):
  - Info/Low  → auto (no checkpoint)
  - Medium    → auto + notify
  - High      → auto + notify
  - Critical  → HARD STOP: requires manual approval
"""

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from core.logger import get_logger, banner, info, ok, warn, err
from core.utils import save_json, load_json, ensure_dir

log = get_logger("ai_checkpoint")


# ─────────────────────────────────────────
# Storage
# ─────────────────────────────────────────
PENDING_FILE = Path(".cache/pending_critical.json")
RESOLVED_FILE = Path(".cache/resolved_critical.json")


def _load_pending() -> List[Dict]:
    return load_json(PENDING_FILE, [])


def _save_pending(items: List[Dict]) -> None:
    ensure_dir(PENDING_FILE.parent)
    save_json(PENDING_FILE, items)


def _load_resolved() -> List[Dict]:
    return load_json(RESOLVED_FILE, [])


def _save_resolved(items: List[Dict]) -> None:
    ensure_dir(RESOLVED_FILE.parent)
    save_json(RESOLVED_FILE, items)


# ─────────────────────────────────────────
# Core actions
# ─────────────────────────────────────────
def queue_critical(finding: Dict, source: str = "auto") -> str:
    """
    Add a critical finding to the pending queue.
    Does NOT generate a report until approved.
    """
    cid = f"crit_{int(time.time() * 1000)}_{len(_load_pending())}"
    item = {
        "id": cid,
        "queued_at": datetime.utcnow().isoformat(),
        "source": source,
        "finding": finding,
        "status": "pending",
    }
    items = _load_pending()
    items.append(item)
    _save_pending(items)
    warn(f"Critical finding queued for manual review: {cid}")
    return cid


def list_pending() -> List[Dict]:
    return [i for i in _load_pending() if i.get("status") == "pending"]


def approve(cid: str, notes: str = "") -> bool:
    items = _load_pending()
    resolved = _load_resolved()
    for it in items:
        if it["id"] == cid:
            it["status"] = "approved"
            it["resolved_at"] = datetime.utcnow().isoformat()
            it["notes"] = notes
            resolved.append(it)
            break
    else:
        return False
    _save_pending([i for i in items if i["id"] != cid])
    _save_resolved(resolved)
    ok(f"Approved: {cid}")
    return True


def reject(cid: str, notes: str = "") -> bool:
    items = _load_pending()
    resolved = _load_resolved()
    for it in items:
        if it["id"] == cid:
            it["status"] = "rejected"
            it["resolved_at"] = datetime.utcnow().isoformat()
            it["notes"] = notes
            resolved.append(it)
            break
    else:
        return False
    _save_pending([i for i in items if i["id"] != cid])
    _save_resolved(resolved)
    ok(f"Rejected: {cid}")
    return True


def approve_all(notes: str = "bulk-approved") -> int:
    count = 0
    for it in list_pending():
        if approve(it["id"], notes):
            count += 1
    return count


def reject_all(notes: str = "bulk-rejected") -> int:
    count = 0
    for it in list_pending():
        if reject(it["id"], notes):
            count += 1
    return count


# ─────────────────────────────────────────
# Policy engine
# ─────────────────────────────────────────
POLICY = {
    "info":     {"action": "auto"},
    "low":      {"action": "auto"},
    "medium":   {"action": "auto_notify"},
    "high":     {"action": "auto_notify"},
    "critical": {"action": "manual_approval"},
}


def should_auto_process(severity: str) -> bool:
    """Return True if finding can proceed without manual approval."""
    sev = (severity or "info").lower()
    return POLICY.get(sev, {}).get("action") != "manual_approval"


def handle_finding(finding: Dict, source: str = "auto") -> Dict:
    """
    Main entry: decide what to do with a finding.
    Returns action taken.
    """
    severity = (finding.get("severity") or "info").lower()

    if should_auto_process(severity):
        # Notify for medium/high
        if severity in ("medium", "high"):
            try:
                from monitoring.alerts import alert_high_finding
                alert_high_finding(finding.get("host", "unknown"), finding)
            except Exception:
                pass
        return {
            "action": "auto",
            "severity": severity,
            "queued": False,
        }

    # Critical → queue for manual review
    cid = queue_critical(finding, source=source)
    try:
        from monitoring.alerts import alert_critical_finding
        alert_critical_finding(finding.get("host", "unknown"), finding)
    except Exception:
        pass
    return {
        "action": "manual_approval",
        "severity": severity,
        "queued": True,
        "checkpoint_id": cid,
    }


# ─────────────────────────────────────────
# Interactive CLI (for review)
# ─────────────────────────────────────────
def review_interactive() -> None:
    """
    Interactive loop to review pending critical findings.
    """
    pending = list_pending()
    if not pending:
        info("No pending critical findings")
        return

    banner(f"Review {len(pending)} pending critical finding(s)")
    for i, it in enumerate(pending, 1):
        f = it["finding"]
        print()
        print(f"─── [{i}/{len(pending)}] {it['id']} ───")
        print(f"  Queued:    {it['queued_at']}")
        print(f"  Severity:  {f.get('severity', '?')}")
        print(f"  Type:      {f.get('vuln_type', '?')}")
        print(f"  URL:       {f.get('url', '')[:200]}")
        print(f"  Param:     {f.get('param', '')}")
        print(f"  Payload:   {f.get('payload', '')[:200]}")
        print(f"  Evidence:  {(f.get('evidence') or '')[:400]}")
        print()

        while True:
            try:
                c = input("  [a]pprove / [r]eject / [s]kip / [q]uit > ").strip().lower()
            except EOFError:
                return
            if c in ("a", "approve"):
                approve(it["id"])
                break
            elif c in ("r", "reject"):
                reject(it["id"])
                break
            elif c in ("s", "skip", ""):
                break
            elif c in ("q", "quit"):
                return
            else:
                print("  Invalid. Use a/r/s/q.")

    ok("Review complete")


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Critical checkpoint")
    p.add_argument("--list", action="store_true")
    p.add_argument("--review", action="store_true")
    p.add_argument("--approve", metavar="ID")
    p.add_argument("--reject", metavar="ID")
    p.add_argument("--approve-all", action="store_true")
    p.add_argument("--reject-all", action="store_true")
    p.add_argument("--resolved", action="store_true")
    args = p.parse_args()

    if args.list:
        for it in list_pending():
            f = it["finding"]
            print(f"{it['id']}  {f.get('severity','?'):8} {f.get('vuln_type','?'):20} {f.get('url','')[:60]}")
    elif args.review:
        review_interactive()
    elif args.approve:
        approve(args.approve)
    elif args.reject:
        reject(args.reject)
    elif args.approve_all:
        n = approve_all()
        ok(f"Approved {n}")
    elif args.reject_all:
        n = reject_all()
        ok(f"Rejected {n}")
    elif args.resolved:
        for it in _load_resolved():
            print(f"{it['id']}  {it['status']:10} {it['finding'].get('url','')[:60]}")
    else:
        print(json.dumps({"pending": len(list_pending()),
                          "resolved": len(_load_resolved())}, indent=2))