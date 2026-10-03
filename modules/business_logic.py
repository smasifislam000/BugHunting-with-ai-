"""
modules/business_logic.py
-------------------------
Business Logic Helper (AI-assisted).
Does NOT auto-exploit. Instead:
  - Identifies business-flow endpoints (cart, price, coupon, order, transfer)
  - Asks AI to suggest logic tests
  - Saves suggestions for manual execution
"""

import json
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs

from core.logger import get_logger, info, ok, warn, skip
from core.utils import safe_request, write_lines, save_json
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("business_logic")


LOGIC_HINTS = {
    "price": ["price", "amount", "cost", "total", "subtotal"],
    "quantity": ["qty", "quantity", "count", "num"],
    "discount": ["discount", "coupon", "promo", "voucher", "code"],
    "cart": ["cart", "basket", "checkout", "order"],
    "user": ["user", "account", "member", "customer"],
    "role": ["role", "permission", "admin", "level", "type"],
    "amount": ["amount", "value", "credit", "balance", "wallet"],
}


def find_logic_endpoints(urls: List[str]) -> List[Dict]:
    out = []
    for u in urls:
        low = u.lower()
        for cat, hints in LOGIC_HINTS.items():
            for h in hints:
                if h in low:
                    out.append({"url": u, "category": cat, "hint": h})
                    break
            else:
                continue
            break
    return out


def ask_ai_for_tests(endpoints: List[Dict]) -> Optional[Dict]:
    """Ask AI to suggest business logic tests."""
    try:
        from core.ai_engine import ask_ai, is_ai_available
    except Exception:
        return None
    if not is_ai_available():
        return None

    prompt = f"""
You are a bug bounty hunter specialized in Business Logic vulnerabilities.

Candidate endpoints:
{json.dumps(endpoints[:20], indent=2)}

For each endpoint, suggest specific business logic tests. Focus on:
- Negative values / zero values
- Integer overflow
- Discount/coupon abuse
- Price manipulation
- Race conditions on checkout
- Role/privilege abuse

Return JSON:
{{
  "tests": [
    {{
      "url": "...",
      "category": "...",
      "test": "manual test description",
      "payload": "example request",
      "expected_impact": "..."
    }}
  ]
}}
"""
    return ask_ai(prompt)


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "business_logic", output_root)
    urls = load_urls(domain, output_root)
    endpoints = find_logic_endpoints(urls)
    if not endpoints:
        info("No business logic candidates found")
        return {"count": 0, "findings": []}

    info(f"Found {len(endpoints)} business logic candidates")

    ai_result = ask_ai_for_tests(endpoints)
    findings: List[Dict] = []

    if ai_result and "tests" in ai_result:
        for t in ai_result["tests"]:
            findings.append(t)
            save_finding(
                domain, "business_logic", "business_logic_suggestion",
                "info", t.get("url", ""),
                payload=t.get("payload", ""),
                evidence=f"{t.get('category')}: {t.get('test')}",
                confidence=0,
                scan_id=scan_id, output_root=output_root,
            )
        save_json(mdir / "ai_suggestions.json", ai_result)
        info(f"AI suggested {len(findings)} tests")
    else:
        # Fallback: basic suggestions
        for ep in endpoints[:30]:
            hint = ep["category"]
            suggestion = {
                "url": ep["url"],
                "category": hint,
                "test": f"Try manipulating '{ep['hint']}' value (negative, zero, huge, negative currency)",
                "payload": f"{ep['hint']}=-1",
            }
            findings.append(suggestion)
            save_finding(
                domain, "business_logic", "business_logic_suggestion",
                "info", ep["url"],
                payload=suggestion["payload"],
                evidence=suggestion["test"],
                confidence=0,
                scan_id=scan_id, output_root=output_root,
            )

    write_lines(mdir / "business_logic_suggestions.txt",
                [f"[{f['category']}] {f['url']} — {f['test']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "business_logic", run, args.output)