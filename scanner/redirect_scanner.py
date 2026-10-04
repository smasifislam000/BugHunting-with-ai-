"""
scanner/redirect_scanner.py
---------------------------
Open redirect detection via Location header analysis.
Tests common redirect parameters with attacker-controlled domains.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, skip, warn
from core.utils import safe_request, write_lines, ensure_dir, read_lines
from core.rate_limiter import acquire
from core.config_loader import get_config

log = get_logger("redirect")
cfg = get_config()


REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "uri",
    "next", "return", "return_to", "return_url", "continue",
    "dest", "destination", "target", "to", "goto", "out",
    "link", "callback", "callback_url", "success", "failure",
    "redir", "r", "u", "view",
]


def _find_redirect_params(url: str) -> List[str]:
    try:
        qs = parse_qs(urlparse(url).query)
        return [p for p in qs if p.lower() in REDIRECT_PARAMS]
    except Exception:
        return []


def _inject(url: str, param: str, value: str) -> Optional[str]:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query)
        qs[param] = [value]
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs, doseq=True), ""))
    except Exception:
        return None


def _marker() -> str:
    import time
    return f"evil{int(time.time())}.com"


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    params = _find_redirect_params(url)
    if not params:
        return findings

    marker = _marker()
    payloads = [
        f"https://{marker}",
        f"//{marker}",
        f"http://{marker}",
        f"https://trusted.com@{marker}",
        f"https://trusted.com.{marker}",
        f"https:{marker}",
        f"\\/\\/{marker}",
    ]

    for param in params[:3]:
        for payload in payloads:
            test_url = _inject(url, param, payload)
            if not test_url:
                continue
            try:
                acquire(test_url)
                r = safe_request(test_url, timeout=8, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue

            if r.status_code not in (301, 302, 303, 307, 308):
                continue

            location = r.headers.get("Location", "")
            if marker in location:
                findings.append({
                    "type": "open_redirect",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Location header: {location[:200]}",
                    "severity": "medium",
                    "confidence": 90,
                })
                return findings
    return findings


def scan_redirect(urls_file: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)
    urls = read_lines(urls_file)
    if not urls:
        info("No URLs for redirect scan")
        return {"count": 0, "findings": []}

    info(f"Redirect: testing {len(urls[:60])} URLs")
    findings: List[Dict] = []

    for url in urls[:60]:
        try:
            findings.extend(test_url(url))
        except Exception as e:
            log.debug(f"redirect test failed for {url}: {e}")

    if findings:
        write_lines(Path(output_dir) / "redirect_findings.txt",
                    [f"[{f['severity']}] {f['url']} -> {f['evidence']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Open redirect scanner")
    p.add_argument("-l", "--list", required=True)
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = scan_redirect(args.list, args.output)
    print(f"\nRedirect findings: {result['count']}")