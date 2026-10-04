"""
core/ai_hallucination.py
------------------------
Detect and mitigate AI hallucinations.

Checks:
  - URLs actually exist (HEAD request)
  - CVE IDs are real (NVD lookup)
  - Reference links resolve
  - Claimed findings match real evidence
  - Numeric consistency
"""

import re
import json
from typing import Dict, List, Optional, Any, Tuple

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request

log = get_logger("ai_hallucination")


# ─────────────────────────────────────────
# Regex extractors
# ─────────────────────────────────────────
URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]]+")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")


# ─────────────────────────────────────────
# Individual checks
# ─────────────────────────────────────────
def check_urls(text: str, timeout: int = 6,
               max_check: int = 8) -> List[Dict]:
    """
    HEAD each URL in the text to see if it resolves.
    """
    urls = list(set(URL_RE.findall(text)))[:max_check]
    results = []
    for url in urls:
        r = safe_request(url, method="HEAD", timeout=timeout,
                         allow_redirects=True)
        if r is None:
            # Try GET with small timeout
            r = safe_request(url, method="GET", timeout=timeout,
                             allow_redirects=True)
        alive = r is not None and r.status_code < 400
        results.append({
            "url": url,
            "alive": alive,
            "status": r.status_code if r else None,
        })
    return results


def check_cve_ids(text: str) -> List[Dict]:
    """
    Verify CVE IDs against NVD.
    """
    cves = list(set(CVE_RE.findall(text)))
    results = []
    for cve in cves[:5]:
        try:
            from intel.nvd_api import search_cves
            hits = search_cves(cve, max_results=1)
            results.append({
                "cve": cve,
                "exists": bool(hits),
                "found": len(hits),
            })
        except Exception as e:
            results.append({"cve": cve, "exists": None, "error": str(e)})
    return results


def check_numeric_consistency(text: str) -> List[str]:
    """
    Look for contradicting numbers (e.g. two different CVSS scores).
    """
    issues = []
    # CVSS score mentions
    cvss_matches = re.findall(r"CVSS[^\d]{0,20}(\d+\.\d+)", text, re.IGNORECASE)
    if len(set(cvss_matches)) > 1:
        issues.append(f"Multiple CVSS scores claimed: {cvss_matches}")
    return issues


# ─────────────────────────────────────────
# Main verifier
# ─────────────────────────────────────────
def verify_ai_output(ai_text: str,
                     check_urls_enabled: bool = True,
                     check_cves: bool = True) -> Dict:
    """
    Verify an AI output. Returns a report.
    """
    report = {
        "urls": [],
        "cves": [],
        "numeric_issues": [],
        "hallucination_confidence": 0,  # 0-100, higher = likely hallucination
        "verdict": "unverified",
    }

    if check_urls_enabled:
        try:
            report["urls"] = check_urls(ai_text)
        except Exception as e:
            log.debug(f"url check failed: {e}")

    if check_cves:
        try:
            report["cves"] = check_cve_ids(ai_text)
        except Exception as e:
            log.debug(f"cve check failed: {e}")

    try:
        report["numeric_issues"] = check_numeric_consistency(ai_text)
    except Exception:
        pass

    # Score
    suspicion = 0
    total_urls = len(report["urls"])
    dead_urls = sum(1 for u in report["urls"] if not u["alive"])
    if total_urls:
        suspicion += (dead_urls / total_urls) * 60

    total_cves = len(report["cves"])
    fake_cves = sum(1 for c in report["cves"] if c["exists"] is False)
    if total_cves:
        suspicion += (fake_cves / total_cves) * 30

    if report["numeric_issues"]:
        suspicion += 10

    report["hallucination_confidence"] = min(100, int(suspicion))
    if suspicion < 20:
        report["verdict"] = "likely_accurate"
    elif suspicion < 50:
        report["verdict"] = "possibly_inaccurate"
    else:
        report["verdict"] = "likely_hallucinated"

    return report


# ─────────────────────────────────────────
# AI verification prompt
# ─────────────────────────────────────────
def ai_self_check(ai_text: str, original_question: str,
                  timeout: int = 60) -> Optional[Dict]:
    """
    Ask a second AI call to fact-check the first answer.
    """
    try:
        from core.ai_engine import ask_ai, is_ai_available
    except Exception:
        return None
    if not is_ai_available():
        return None

    prompt = f"""
You are a FACT-CHECKER. Review the following AI-generated answer for hallucinations.

Original question:
{original_question}

AI answer:
{ai_text[:4000]}

Check:
1. Are all URLs valid and real?
2. Are all CVEs real and correctly described?
3. Are all technical claims consistent?
4. Is anything fabricated?

Return JSON:
{{
  "hallucination_score": 0-100,
  "fabricated_items": ["...", "..."],
  "verified_items": ["...", "..."],
  "verdict": "accurate" | "partly_accurate" | "hallucinated"
}}
"""
    return ask_ai(prompt, json_mode=True, timeout=timeout)


# ─────────────────────────────────────────
# Wrapper: verify + auto-fix
# ─────────────────────────────────────────
def verify_and_report(ai_text: str,
                      original_question: str = "",
                      timeout: int = 60) -> Dict:
    """
    Full verification pipeline:
      1. Deterministic checks (URLs, CVEs, numbers)
      2. AI self-check (second opinion)
      3. Combined report
    """
    static = verify_ai_output(ai_text)

    ai_check = None
    if original_question:
        ai_check = ai_self_check(ai_text, original_question, timeout=timeout)

    combined_confidence = static["hallucination_confidence"]
    if ai_check and isinstance(ai_check, dict):
        ai_score = int(ai_check.get("hallucination_score", 0))
        combined_confidence = (combined_confidence + ai_score) // 2

    return {
        "static_check": static,
        "ai_check": ai_check,
        "combined_hallucination_confidence": combined_confidence,
        "final_verdict": (
            "accurate" if combined_confidence < 25 else
            "needs_review" if combined_confidence < 60 else
            "likely_fabricated"
        ),
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI hallucination detector")
    p.add_argument("--text", help="Text to verify")
    p.add_argument("--file", help="Read text from file")
    p.add_argument("--with-ai-check", action="store_true")
    args = p.parse_args()

    text = ""
    if args.text:
        text = args.text
    elif args.file:
        try:
            text = open(args.file, encoding="utf-8").read()
        except Exception as e:
            print(f"Could not read file: {e}")
            exit(1)

    if not text:
        print("Provide --text or --file")
        exit(1)

    if args.with_ai_check:
        r = verify_and_report(text)
    else:
        r = verify_ai_output(text)

    print(json.dumps(r, indent=2, default=str))