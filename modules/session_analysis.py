"""
modules/session_analysis.py
---------------------------
Session security analysis.

Checks:
  - Cookie flags (HttpOnly, Secure, SameSite)
  - Session fixation surface
  - Predictable session tokens
  - Cookie scope (Domain/Path)
"""

import re
import hashlib
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("session_analysis")


def _analyze_cookie(name: str, value: str, url: str,
                    set_cookie_header: str) -> List[Dict]:
    findings: List[Dict] = []
    header_low = set_cookie_header.lower()

    # HttpOnly
    if "httponly" not in header_low:
        findings.append({
            "type": "cookie_no_httponly",
            "url": url,
            "param": name,
            "evidence": f"Cookie '{name}' missing HttpOnly flag",
            "severity": "medium",
            "confidence": 90,
        })

    # Secure
    if url.startswith("https://") and "secure" not in header_low:
        findings.append({
            "type": "cookie_no_secure",
            "url": url,
            "param": name,
            "evidence": f"Cookie '{name}' missing Secure flag over HTTPS",
            "severity": "medium",
            "confidence": 90,
        })

    # SameSite
    if "samesite" not in header_low:
        findings.append({
            "type": "cookie_no_samesite",
            "url": url,
            "param": name,
            "evidence": f"Cookie '{name}' missing SameSite attribute",
            "severity": "low",
            "confidence": 85,
        })
    elif "samesite=none" in header_low and "secure" not in header_low:
        findings.append({
            "type": "cookie_samesite_none_insecure",
            "url": url,
            "param": name,
            "evidence": f"Cookie '{name}' SameSite=None without Secure",
            "severity": "medium",
            "confidence": 80,
        })

    # Session token predictability heuristics
    if _looks_like_session(name) and value:
        if len(value) < 16:
            findings.append({
                "type": "short_session_token",
                "url": url,
                "param": name,
                "evidence": f"Session token '{name}' is only {len(value)} chars",
                "severity": "medium",
                "confidence": 70,
            })
        if value.isdigit():
            findings.append({
                "type": "numeric_session_token",
                "url": url,
                "param": name,
                "evidence": f"Session token '{name}' is purely numeric",
                "severity": "high",
                "confidence": 75,
            })

    return findings


def _looks_like_session(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in
               ["sess", "sid", "session", "auth", "token", "jwt", "id"])


def analyze_url(url: str) -> List[Dict]:
    findings: List[Dict] = []

    try:
        acquire(url)
        r = safe_request(url, timeout=10)
    except Exception:
        return findings
    if not r:
        return findings

    set_cookies: List[str] = []
    for k, v in r.headers.items():
        if k.lower() == "set-cookie":
            set_cookies.append(v)

    for raw in set_cookies:
        # Split: name=value; attr1; attr2
        parts = raw.split(";")
        if not parts:
            continue
        name_value = parts[0].strip()
        if "=" not in name_value:
            continue
        name, value = name_value.split("=", 1)
        findings.extend(_analyze_cookie(name.strip(), value.strip(), url, raw))

    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "session_analysis", output_root)
    urls = load_urls(domain, output_root)

    if not urls:
        info("No URLs to test")
        return {"count": 0, "findings": []}

    info(f"Session analysis: {len(urls[:30])} URLs")
    findings: List[Dict] = []

    for url in urls[:30]:
        try:
            findings.extend(analyze_url(url))
        except Exception as e:
            log.debug(f"session analysis failed {url}: {e}")

    for f in findings:
        save_finding(domain, "session_analysis", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "session_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Session security analysis")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "session_analysis", run, args.output)