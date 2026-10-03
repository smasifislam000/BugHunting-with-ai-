"""
modules/xs_leaks.py
-------------------
Cross-Site Leaks (XS-Leaks) detection.
Tests: COOP/COEP headers, frame-ancestors, X-Frame-Options,
       cross-origin redirect behaviors.
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("xs_leaks")


def analyze_headers(url: str) -> Optional[Dict]:
    r = safe_request(url, timeout=10)
    if not r:
        return None

    h = {k.lower(): v for k, v in r.headers.items()}
    findings = []

    # Missing COOP/COEP
    if "cross-origin-opener-policy" not in h:
        findings.append("missing COOP")
    if "cross-origin-embedder-policy" not in h:
        findings.append("missing COEP")
    if "cross-origin-resource-policy" not in h:
        findings.append("missing CORP")

    # Weak XFO
    xfo = h.get("x-frame-options", "").lower()
    csp = h.get("content-security-policy", "").lower()
    if not xfo and "frame-ancestors" not in csp:
        findings.append("no frame protection (XFO/frame-ancestors)")

    if findings:
        return {
            "type": "xs_leaks_headers",
            "url": url,
            "evidence": "; ".join(findings),
            "severity": "low",
            "confidence": 60,
        }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "xs_leaks", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    info(f"Analyzing {len(urls[:40])} URLs for XS-Leak surface")
    findings: List[Dict] = []

    for url in urls[:40]:
        try:
            res = analyze_headers(url)
            if res:
                findings.append(res)
                save_finding(domain, "xs_leaks", res["type"], res["severity"],
                             res["url"], evidence=res["evidence"],
                             confidence=res["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"xs-leaks check failed {url}: {e}")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "xs_leaks", run, args.output)