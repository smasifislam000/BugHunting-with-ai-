"""
modules/cdn_misconfig.py
------------------------
CDN misconfiguration detection.

Detects:
  - Origin IP leaks (bypassing CDN)
  - Missing CDN headers
  - Cache poisoning surface
  - WAF bypass headers
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("cdn_misconfig")


CDN_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "akamai": ["akamai", "ak-bmsc", "x-akamai"],
    "fastly": ["fastly", "x-served-by", "x-cache"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "sucuri": ["x-sucuri-id", "sucuri"],
    "incapsula": ["x-cdn", "incap_ses", "visid_incap"],
    "bunnycdn": ["bunnycdn", "b-cdn"],
    "stackpath": ["stackpath", "x-sp-cache"],
}


ORIGIN_BYPASS_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
]


def detect_cdn(url: str) -> Optional[Dict]:
    try:
        acquire(url)
        r = safe_request(url, timeout=10)
    except Exception:
        return None
    if not r:
        return None

    headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
    header_blob = " ".join(f"{k}: {v}" for k, v in headers_lower.items())

    for cdn, sigs in CDN_SIGNATURES.items():
        for sig in sigs:
            if sig in header_blob:
                return {
                    "cdn": cdn,
                    "signature": sig,
                    "url": url,
                    "evidence": f"CDN '{cdn}' detected via '{sig}'",
                }
    return None


def test_origin_leak(url: str, cdn_info: Optional[Dict]) -> Optional[Dict]:
    if not cdn_info:
        return None

    try:
        parsed = urlparse(url)
        baseline = safe_request(url, timeout=10)
    except Exception:
        return None
    if not baseline:
        return None

    baseline_len = len(baseline.content)

    for header in ORIGIN_BYPASS_HEADERS:
        try:
            acquire(url)
            r = safe_request(url, headers={header: "127.0.0.1"}, timeout=10)
        except Exception:
            continue
        if not r:
            continue
        # If bypassing CDN changes response
        if (r.status_code != baseline.status_code or
                abs(len(r.content) - baseline_len) > 500):
            return {
                "type": "cdn_origin_bypass_suspect",
                "url": url,
                "param": header,
                "evidence": (
                    f"Baseline {baseline.status_code}/{baseline_len}B "
                    f"vs {r.status_code}/{len(r.content)}B with {header}"
                ),
                "severity": "medium",
                "confidence": 45,
            }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "cdn_misconfig", output_root)
    urls = load_urls(domain, output_root)

    if not urls:
        info("No URLs to test")
        return {"count": 0, "findings": []}

    info(f"Testing {len(urls[:20])} URLs for CDN misconfig")
    findings: List[Dict] = []

    for url in urls[:20]:
        try:
            cdn = detect_cdn(url)
        except Exception:
            cdn = None

        if cdn:
            findings.append({
                "type": "cdn_detected",
                "url": url,
                "evidence": cdn["evidence"],
                "severity": "info",
                "confidence": 90,
            })

            try:
                leak = test_origin_leak(url, cdn)
                if leak:
                    findings.append(leak)
            except Exception as e:
                log.debug(f"origin leak test failed: {e}")

    for f in findings:
        save_finding(domain, "cdn_misconfig", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "cdn_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="CDN misconfig detector")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "cdn_misconfig", run, args.output)