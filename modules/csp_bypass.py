"""
modules/csp_bypass.py
---------------------
CSP bypass analysis.
Parses CSP header, identifies weak directives (unsafe-inline,
wildcards, JSONP endpoints, data:, angular, etc.)
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("csp_bypass")


WEAK_PATTERNS = [
    (r"unsafe-inline", "unsafe-inline allows inline scripts", "high"),
    (r"unsafe-eval", "unsafe-eval allows eval()", "high"),
    (r"\*", "wildcard source allows any host", "high"),
    (r"data:", "data: URIs allow script injection", "medium"),
    (r"http:", "http: allows MITM injection", "medium"),
    (r"'self' 'unsafe", "self + unsafe combination", "high"),
]

KNOWN_BYPASS_DOMAINS = [
    "ajax.googleapis.com", "cdn.jsdelivr.net", "unpkg.com",
    "cdnjs.cloudflare.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
]


def analyze_csp(url: str) -> Optional[Dict]:
    r = safe_request(url, timeout=10)
    if not r:
        return None
    csp = r.headers.get("Content-Security-Policy") or \
          r.headers.get("content-security-policy")
    if not csp:
        return None

    weak: List[str] = []
    for pattern, desc, severity in WEAK_PATTERNS:
        if re.search(pattern, csp):
            weak.append(f"{severity}: {desc}")

    # Check for known bypass hosts
    for host in KNOWN_BYPASS_DOMAINS:
        if host in csp:
            weak.append(f"medium: known JSONP host allowed: {host}")

    # Missing directives
    for directive in ["script-src", "object-src", "base-uri", "frame-ancestors"]:
        if directive not in csp.lower():
            weak.append(f"medium: missing {directive}")

    if weak:
        return {
            "type": "weak_csp",
            "url": url,
            "csp": csp[:500],
            "weaknesses": weak[:10],
            "severity": "medium",
            "confidence": 70,
        }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "csp_bypass", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    info(f"Analyzing CSP on {len(urls[:40])} URLs")
    findings: List[Dict] = []

    for url in urls[:40]:
        try:
            res = analyze_csp(url)
            if res:
                findings.append(res)
                save_finding(domain, "csp_bypass", res["type"], res["severity"],
                             res["url"], evidence="; ".join(res["weaknesses"]),
                             confidence=res["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"csp check failed {url}: {e}")

    if findings:
        write_lines(mdir / "csp_findings.txt",
                    [f"[{f['severity']}] {f['url']} — {'; '.join(f['weaknesses'][:3])}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "csp_bypass", run, args.output)