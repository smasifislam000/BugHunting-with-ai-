"""
core/human_verification.py
--------------------------
Two-step human verification before report submission.

Rule: Even if AI says "PROVEN", YOU must review and approve.
This protects your HackerOne/Bugcrowd reputation.

Workflow:
  1. AI generates report draft
  2. You read it in terminal or markdown
  3. You type Y/N with a note
  4. If Y → report is marked "verified", ready to submit
  5. If N → report is discarded, feedback is recorded
"""

import json
import time
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from core.logger import get_logger, info, ok, warn, banner
from core.utils import save_json, load_json, ensure_dir

log = get_logger("human_verification")


# ─────────────────────────────────────────
# Storage
# ─────────────────────────────────────────
VERIFY_DIR = Path(".cache/verification")
PENDING_FILE = VERIFY_DIR / "pending.json"
VERIFIED_FILE = VERIFY_DIR / "verified.json"
REJECTED_FILE = VERIFY_DIR / "rejected.json"


def _load(path: Path, default=None):
    return load_json(path, default if default is not None else [])


def _save(path: Path, data):
    ensure_dir(path.parent)
    save_json(path, data)


# ─────────────────────────────────────────
# Queue a report for verification
# ─────────────────────────────────────────
def queue_for_verification(report_path: str, finding: Dict) -> str:
    """
    Queue a generated report for human verification.
    Returns verification ID.
    """
    vid = f"vf_{int(time.time() * 1000)}"
    report_path = Path(report_path)

    # Read report preview
    preview = ""
    try:
        preview = report_path.read_text(encoding="utf-8")[:3000]
    except Exception as e:
        log.debug(f"could not read report: {e}")

    entry = {
        "id": vid,
        "queued_at": datetime.utcnow().isoformat(),
        "report_path": str(report_path),
        "preview": preview,
        "finding": finding,
        "status": "pending",
    }

    pending = _load(PENDING_FILE, [])
    pending.append(entry)
    _save(PENDING_FILE, pending)

    info(f"Report queued for verification: {vid}")
    return vid


def list_pending() -> List[Dict]:
    return [e for e in _load(PENDING_FILE, []) if e.get("status") == "pending"]


def list_verified() -> List[Dict]:
    return _load(VERIFIED_FILE, [])


def list_rejected() -> List[Dict]:
    return _load(REJECTED_FILE, [])


# ─────────────────────────────────────────
# Verification actions
# ─────────────────────────────────────────
def approve(vid: str, notes: str = "") -> bool:
    """Mark a queued report as human-verified."""
    pending = _load(PENDING_FILE, [])
    verified = _load(VERIFIED_FILE, [])

    for e in pending:
        if e["id"] == vid:
            e["status"] = "verified"
            e["verified_at"] = datetime.utcnow().isoformat()
            e["verification_notes"] = notes
            verified.append(e)
            break
    else:
        warn(f"Not found: {vid}")
        return False

    _save(PENDING_FILE, [e for e in pending if e["id"] != vid])
    _save(VERIFIED_FILE, verified)
    ok(f"Approved: {vid}")
    return True


def reject(vid: str, reason: str = "") -> bool:
    """Mark a queued report as rejected by human."""
    pending = _load(PENDING_FILE, [])
    rejected = _load(REJECTED_FILE, [])

    for e in pending:
        if e["id"] == vid:
            e["status"] = "rejected"
            e["rejected_at"] = datetime.utcnow().isoformat()
            e["rejection_reason"] = reason
            rejected.append(e)
            break
    else:
        return False

    _save(PENDING_FILE, [e for e in pending if e["id"] != vid])
    _save(REJECTED_FILE, rejected)
    ok(f"Rejected: {vid}")
    return True


def is_verified(report_path: str) -> bool:
    """Check if a report has been human-verified."""
    path = str(report_path)
    for e in list_verified():
        if e.get("report_path") == path:
            return True
    return False


# ─────────────────────────────────────────
# Interactive review
# ─────────────────────────────────────────
def review_interactive() -> None:
    """
    Interactive loop to review pending reports.
    """
    pending = list_pending()
    if not pending:
        info("No pending reports for verification")
        return

    banner(f"Verify {len(pending)} pending report(s)")
    print()
    print("For each report:")
    print("  [a]pprove → report is ready to submit")
    print("  [r]eject  → report is discarded")
    print("  [s]kip    → review later")
    print("  [o]pen    → show full report preview")
    print("  [q]uit")
    print()

    for i, e in enumerate(pending, 1):
        print(f"\n═══ [{i}/{len(pending)}] {e['id']} ═══")
        print(f"  File:  {e['report_path']}")
        print(f"  Vuln:  {e['finding'].get('vuln_type', '?')}")
        print(f"  Sev:   {e['finding'].get('severity', '?')}")
        print(f"  URL:   {e['finding'].get('url', '')[:150]}")
        print()

        while True:
            try:
                c = input("  [a]pprove / [r]eject / [s]kip / [o]pen / [q]uit > ").strip().lower()
            except EOFError:
                return

            if c in ("a", "approve"):
                notes = input("  Notes (optional): ").strip()
                approve(e["id"], notes)
                break
            elif c in ("r", "reject"):
                reason = input("  Reason: ").strip()
                reject(e["id"], reason)
                break
            elif c in ("s", "skip", ""):
                break
            elif c in ("o", "open"):
                print()
                print("──── Report Preview ────")
                print(e.get("preview", "(no preview)"))
                print("──── End Preview ────")
                print()
            elif c in ("q", "quit"):
                return
            else:
                print("  Invalid. Use a/r/s/o/q.")

    ok("Review session complete")


# ─────────────────────────────────────────
# Report flow integration
# ─────────────────────────────────────────
def generate_report_with_verification(finding: Dict,
                                      output_root: str = "results",
                                      platform: str = "hackerone",
                                      require_approval: bool = True) -> Dict:
    """
    Generate a report, attach AI disclosure, and queue for verification.
    """
    result = {
        "generated": False,
        "verified": False,
        "report_path": None,
        "verification_id": None,
        "reason": "",
    }

    # 1) Generate report via reporting module
    try:
        from reporting.report import build_report_md
        md = build_report_md(finding, finding.get("host", "target"))
    except Exception as e:
        result["reason"] = f"report generation failed: {e}"
        return result

    # 2) Attach AI disclosure
    try:
        from core.ai_disclosure import attach_disclosure
        md = attach_disclosure(md, platform=platform)
    except Exception as e:
        log.debug(f"disclosure attach failed: {e}")

    # 3) Save to disk
    out_dir = Path(output_root) / finding.get("host", "target") / "reports_pending"
    ensure_dir(out_dir)
    path = out_dir / f"{finding.get('vuln_type', 'finding')}_{int(time.time())}.md"
    try:
        path.write_text(md, encoding="utf-8")
        result["generated"] = True
        result["report_path"] = str(path)
    except Exception as e:
        result["reason"] = f"write failed: {e}"
        return result

    # 4) Queue for verification
    if require_approval:
        vid = queue_for_verification(str(path), finding)
        result["verification_id"] = vid
        result["reason"] = "awaiting manual verification"
    else:
        result["verified"] = True
        result["reason"] = "auto-approved (require_approval=False)"

    return result


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Human verification before submit")
    p.add_argument("--list", action="store_true", help="List pending")
    p.add_argument("--review", action="store_true", help="Interactive review")
    p.add_argument("--approve", metavar="ID", help="Approve by ID")
    p.add_argument("--reject", metavar="ID", help="Reject by ID")
    p.add_argument("--verified", action="store_true", help="List verified")
    p.add_argument("--rejected", action="store_true", help="List rejected")
    args = p.parse_args()

    if args.list:
        for e in list_pending():
            print(f"{e['id']}  {e['finding'].get('vuln_type','?'):15} "
                  f"{e['finding'].get('severity','?'):8} "
                  f"{e['report_path']}")
    elif args.review:
        review_interactive()
    elif args.approve:
        approve(args.approve)
    elif args.reject:
        reason = input("Reason: ").strip()
        reject(args.reject, reason)
    elif args.verified:
        for e in list_verified():
            print(f"{e['id']}  {e['report_path']}")
    elif args.rejected:
        for e in list_rejected():
            print(f"{e['id']}  {e.get('rejection_reason', '')}  {e['report_path']}")
    else:
        print(json.dumps({
            "pending": len(list_pending()),
            "verified": len(list_verified()),
            "rejected": len(list_rejected()),
        }, indent=2))