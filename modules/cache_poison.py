"""
modules/cache_poison.py
-----------------------
Web cache poisoning via unkeyed headers.
Techniques: X-Forwarded-Host, X-Host, X-Original-URL reflection.
"""

import hashlib
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("cache_poison")


UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Scheme",
    "Forwarded",
]

POISON_MARKER = "cp-marker-{r}".format


def cache_buster() -> str:
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    p = urlparse(url)
    base = f"{p.scheme}://{p.netloc}{p.path}"

    for header in UNKEYED_HEADERS:
        marker = POISON_MARKER(r=cache_buster())
        test_url_q = f"{base}?cb={marker}"

        # Send request with malicious header
        r = safe_request(test_url_q, headers={header: marker}, timeout=10)
        if not r:
            continue
        if marker in (r.text or "") or marker in str(r.headers):
            # Now request without the header to see if cached
            time.sleep(1)
            r2 = safe_request(test_url_q, timeout=10)
            if r2 and marker in (r2.text or ""):
                findings.append({
                    "type": "cache_poisoning",
                    "url": test_url_q,
                    "param": header,
                    "payload": marker,
                    "evidence": f"Marker persisted after removing '{header}' header",
                    "severity": "high",
                    "confidence": 75,
                })
                return findings
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "cache_poison", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    info(f"Testing {len(urls[:60])} URLs for cache poisoning")
    findings: List[Dict] = []

    for url in urls[:60]:
        try:
            for f in test_url(url):
                findings.append(f)
                save_finding(domain, "cache_poison", f["type"], f["severity"],
                             f["url"], param=f["param"], payload=f["payload"],
                             evidence=f["evidence"], confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
                warn(f"CACHE POISON: {f['url']}")
        except Exception as e:
            log.debug(f"cache poison test failed {url}: {e}")

    if findings:
        write_lines(mdir / "cache_poison_findings.txt",
                    [f"[{f['severity']}] {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "cache_poison", run, args.output)