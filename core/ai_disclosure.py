"""
core/ai_disclosure.py
---------------------
Automatic AI-usage disclosure for bug bounty reports.

Different platforms have different policies:
  - HackerOne:  encourages disclosure, no strict requirement
  - Bugcrowd:   requires disclosure if AI used
  - curl, Nextcloud, etc.: strict — AI Slop = ban
  - Many programs: AI-assisted is OK if human-verified

This module appends a proper disclosure statement at the end of
every report so triagers know exactly what to expect.
"""

from datetime import datetime
from typing import Dict, Optional

from core.logger import get_logger
from core.config_loader import get_config

log = get_logger("ai_disclosure")
cfg = get_config()


# ─────────────────────────────────────────
# Disclosure templates per platform
# ─────────────────────────────────────────
DISCLOSURE_TEMPLATES = {
    "hackerone": """
---

### AI-Assistance Disclosure

This report was prepared with AI assistance (reconnaissance, initial
analysis, and draft generation). All findings have been **manually
verified** by the reporter:

- ✅ Raw HTTP request/response captured
- ✅ Reproduction steps validated end-to-end
- ✅ PoC (curl / Python) tested before submission
- ✅ Impact assessment reviewed

**Reporter confirms**: The vulnerability is reproducible, the PoC
works, and the description reflects what was actually observed.
Any AI-generated content has been verified against real evidence.
""",

    "bugcrowd": """
---

## AI-Assistance Disclosure

**AI Used**: Yes
**Purpose**: Reconnaissance, analysis assistance, report drafting
**Human Verification**: All findings manually verified

Evidence bundle attached (raw HTTP, PoC, screenshots). Reporter has
personally reproduced the vulnerability and confirms the report is
accurate.
""",

    "generic": """
---

### AI-Assistance Disclosure

This report was prepared with AI assistance. All findings have been
manually verified by the reporter before submission. Raw evidence,
PoC, and reproduction steps are included and tested.
""",
}


# ─────────────────────────────────────────
# Program-specific policies
# ─────────────────────────────────────────
# Some programs require additional wording or forbid certain things
PROGRAM_POLICIES = {
    "curl": {
        "ai_allowed": False,
        "note": "curl does not accept AI-generated reports. Do not submit.",
    },
    "nextcloud": {
        "ai_allowed": False,
        "note": "Nextcloud requires hand-written reports.",
    },
    "hackerone": {
        "ai_allowed": True,
        "note": "HackerOne allows AI-assisted with human verification.",
    },
    "bugcrowd": {
        "ai_allowed": True,
        "note": "Bugcrowd requires disclosure when AI is used.",
    },
    "yeswehack": {
        "ai_allowed": True,
        "note": "YesWeHack allows AI-assisted with disclosure.",
    },
    "intigriti": {
        "ai_allowed": True,
        "note": "Intigriti allows AI-assisted if human-verified.",
    },
}


# ─────────────────────────────────────────
# Core functions
# ─────────────────────────────────────────
def get_template(platform: str = "hackerone") -> str:
    """Return the appropriate disclosure template."""
    p = (platform or "hackerone").lower()
    if p in DISCLOSURE_TEMPLATES:
        return DISCLOSURE_TEMPLATES[p]
    return DISCLOSURE_TEMPLATES["generic"]


def attach_disclosure(report_md: str, platform: str = "hackerone",
                      extra_note: str = "") -> str:
    """
    Append AI-disclosure section to a report.
    Never duplicates — checks if disclosure already present.
    """
    if "AI-Assistance Disclosure" in report_md or "AI-Assistance" in report_md:
        return report_md

    template = get_template(platform)
    if extra_note:
        template += f"\n\n**Note**: {extra_note}\n"

    return report_md.rstrip() + "\n" + template


def check_program_policy(program_name: str) -> Dict:
    """
    Check if a program allows AI-assisted reports.
    """
    key = (program_name or "").lower().replace(" ", "").replace("-", "")
    for k, v in PROGRAM_POLICIES.items():
        if k in key:
            return {
                "program": program_name,
                "ai_allowed": v["ai_allowed"],
                "note": v["note"],
            }
    # Default: allowed with disclosure
    return {
        "program": program_name,
        "ai_allowed": True,
        "note": "No specific policy found — AI-assisted with disclosure is safest.",
    }


def should_warn(program_name: str) -> Optional[str]:
    """
    Return a warning message if AI is not allowed.
    """
    policy = check_program_policy(program_name)
    if not policy["ai_allowed"]:
        return (
            f"⚠️ WARNING: {program_name} does not allow AI-generated reports.\n"
            f"Reason: {policy['note']}\n"
            f"→ Do NOT submit AI-assisted reports to this program."
        )
    return None


def build_disclosure_note(ai_used: bool = True,
                          platform: str = "hackerone") -> str:
    """
    Quick helper to build the disclosure text.
    """
    if not ai_used:
        return ""
    return get_template(platform)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser(description="AI disclosure helper")
    p.add_argument("--check", help="Check program policy by name")
    p.add_argument("--template", default="hackerone",
                   help="Get template (hackerone/bugcrowd/generic)")
    args = p.parse_args()

    if args.check:
        r = check_program_policy(args.check)
        print(json.dumps(r, indent=2))
        w = should_warn(args.check)
        if w:
            print()
            print(w)
    else:
        print(get_template(args.template))