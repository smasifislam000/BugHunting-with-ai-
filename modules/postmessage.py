"""
modules/postmessage.py
----------------------
postMessage vulnerabilities: wildcard origin, no origin check,
message handlers in JS files.
"""

import re
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("postmessage")


PATTERNS = [
    (re.compile(r'postMessage\s*\([^,]+,\s*["\']\*["\']'), "wildcard origin", "high"),
    (re.compile(r'\.addEventListener\s*\(\s*["\']message["\']'), "message listener", "info"),
    (re.compile(r'event\.origin'), "origin check", "info"),
    (re.compile(r'onmessage\s*='), "inline onmessage", "info"),
]


def scan_js(js_url: str) -> List[Dict]:
    findings: List[Dict] = []
    r = safe_request(js_url, timeout=10)
    if not r or r.status_code != 200:
        return []
    text = r.text or ""
    for pat, desc, severity in PATTERNS:
        for m in pat.finditer(text):
            if severity == "info":
                continue
            findings.append({
                "type": "postmessage_vuln",
                "url": js_url,
                "evidence": f"{desc}: {m.group(0)[:100]}",
                "severity": severity,
                "confidence": 60,
            })
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "postmessage", output_root)
    urls = load_urls(domain, output_root)
    js_urls = [u for u in urls if ".js" in u.lower().split("?")[0]]

    info(f"Scanning {len(js_urls[:50])} JS files for postMessage issues")
    findings: List[Dict] = []

    for js in js_urls[:50]:
        try:
            for f in scan_js(js):
                findings.append(f)
                save_finding(domain, "postmessage", f["type"], f["severity"],
                             f["url"], evidence=f["evidence"],
                             confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"postmessage scan failed {js}: {e}")

    if findings:
        write_lines(mdir / "postmessage_findings.txt",
                    [f"[{f['severity']}] {f['url']} — {f['evidence']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "postmessage", run, args.output)