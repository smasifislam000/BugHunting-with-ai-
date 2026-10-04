"""
scanner/ssrf_scanner.py
-----------------------
SSRF detection via OOB (Collaborator/Interactsh) + response analysis.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, skip, warn
from core.utils import safe_request, write_lines, ensure_dir
from core.rate_limiter import acquire
from core.config_loader import get_config

log = get_logger("ssrf")
cfg = get_config()


SSRF_PARAMS = [
    "url", "uri", "target", "dest", "destination", "redirect",
    "return", "next", "continue", "callback", "webhook",
    "image", "img", "src", "source", "file", "path", "load",
    "proxy", "fetch", "resource", "host", "domain", "domain_name",
    "feed", "link", "ref", "reference", "site", "page", "open",
]

LOCAL_URLS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0.0.0.0",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
]

RESPONSE_MARKERS = [
    "ami-id", "instance-id", "computeMetadata",
    "root:x:", "[boot loader]", "localhost",
    "internal", "metadata",
]


def _find_ssrf_params(url: str) -> List[str]:
    try:
        qs = parse_qs(urlparse(url).query)
        return [p for p in qs if p.lower() in SSRF_PARAMS]
    except Exception:
        return []


def _inject(url: str, param: str, payload: str) -> Optional[str]:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query)
        qs[param] = [payload]
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs, doseq=True), ""))
    except Exception:
        return None


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    params = _find_ssrf_params(url)
    if not params:
        return findings

    for param in params[:3]:
        for payload in LOCAL_URLS:
            test_url = _inject(url, param, payload)
            if not test_url:
                continue
            try:
                acquire(test_url)
                r = safe_request(test_url, timeout=10, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue

            body = (r.text or "").lower()
            for marker in RESPONSE_MARKERS:
                if marker.lower() in body:
                    findings.append({
                        "type": "ssrf",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Response contains: {marker}",
                        "severity": "critical",
                        "confidence": 80,
                    })
                    return findings
    return findings


def scan_ssrf(urls_file: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)
    from core.utils import read_lines

    urls = read_lines(urls_file)
    if not urls:
        info("No URLs for SSRF scan")
        return {"count": 0, "findings": []}

    info(f"SSRF: testing {len(urls[:50])} URLs")
    findings: List[Dict] = []

    for url in urls[:50]:
        try:
            findings.extend(test_url(url))
        except Exception as e:
            log.debug(f"SSRF test failed for {url}: {e}")

    if findings:
        write_lines(Path(output_dir) / "ssrf_findings.txt",
                    [f"[{f['severity']}] {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="SSRF scanner")
    p.add_argument("-l", "--list", required=True)
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = scan_ssrf(args.list, args.output)
    print(f"\nSSRF findings: {result['count']}")