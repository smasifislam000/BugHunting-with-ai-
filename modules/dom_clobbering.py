"""
modules/dom_clobbering.py
-------------------------
DOM Clobbering detection via JS analysis.
Looks for patterns where global variables are used without declaration,
suggesting they can be clobbered via injected HTML.
"""

import re
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("dom_clobbering")


CLOBBER_PATTERNS = [
    re.compile(r'window\.(\w+)\s*[\.\[]'),
    re.compile(r'document\.(\w+)\s*[\.\[]'),
    re.compile(r'typeof\s+(\w+)\s*===?\s*["\']undefined'),
]


def scan_js(js_url: str) -> List[Dict]:
    findings: List[Dict] = []
    r = safe_request(js_url, timeout=10)
    if not r or r.status_code != 200:
        return []
    text = r.text or ""

    # Detect patterns like: if (window.someVar) { ... }
    if re.search(r'window\.\w+', text) and "innerHTML" in text:
        # Weak signal — worth flagging
        findings.append({
            "type": "dom_clobbering_suspect",
            "url": js_url,
            "evidence": "window.* usage with innerHTML suggests possible clobbering",
            "severity": "low",
            "confidence": 30,
        })
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "dom_clobbering", output_root)
    urls = load_urls(domain, output_root)
    js_urls = [u for u in urls if ".js" in u.lower().split("?")[0]]

    info(f"Scanning {len(js_urls[:50])} JS files for DOM clobbering patterns")
    findings: List[Dict] = []

    for js in js_urls[:50]:
        try:
            for f in scan_js(js):
                findings.append(f)
                save_finding(domain, "dom_clobbering", f["type"], f["severity"],
                             f["url"], evidence=f["evidence"],
                             confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"clobbering scan failed {js}: {e}")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "dom_clobbering", run, args.output)