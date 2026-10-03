"""
modules/crlf_injection.py
-------------------------
CRLF / HTTP Header Injection detection.
Payloads: %0d%0a, %0a%0d, unicode variants.
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("crlf")


PAYLOADS = [
    "%0d%0aInjected-Header:crlf",
    "%0aInjected-Header:crlf",
    "%0d%0a%0d%0a<html>crlf</html>",
    "\r\nInjected-Header:crlf",
    "%E5%98%8A%E5%98%8DInjected-Header:crlf",  # unicode
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
            r = safe_request(new_url, timeout=10, allow_redirects=False)
            if not r:
                continue
            if any(h.lower() == "injected-header" for h in r.headers):
                findings.append({
                    "type": "crlf_injection",
                    "url": new_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Injected-Header present in response",
                    "severity": "high",
                    "confidence": 90,
                })
                break
            # Check Location header
            loc = r.headers.get("Location", "")
            if "Injected-Header" in loc:
                findings.append({
                    "type": "crlf_injection_redirect",
                    "url": new_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Injected via Location: {loc[:100]}",
                    "severity": "high",
                    "confidence": 85,
                })
                break
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "crlf_injection", output_root)
    urls = load_urls(domain, output_root)
    params_urls = [u for u in urls if "?" in u and "=" in u]
    if not params_urls:
        return {"count": 0, "findings": []}

    info(f"Testing {len(params_urls)} URLs for CRLF")
    findings: List[Dict] = []

    for url in params_urls[:100]:
        try:
            for f in test_url(url):
                findings.append(f)
                save_finding(domain, "crlf_injection", f["type"], f["severity"],
                             f["url"], param=f["param"], payload=f["payload"],
                             evidence=f["evidence"], confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"crlf test failed: {e}")

    if findings:
        write_lines(mdir / "crlf_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "crlf_injection", run, args.output)