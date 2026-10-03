"""
modules/web_cache_deception.py
------------------------------
Web Cache Deception (Omer Gil technique).
Appends static-extension paths to auth'd endpoints to force caching
of sensitive responses.
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("web_cache_deception")


EXTENSIONS = [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", "%2F", "%00", ";"]

SENSITIVE_HINTS = ["/profile", "/account", "/dashboard", "/api/user",
                   "/api/me", "/settings", "/admin", "/user", "/my"]


def test_url(url: str) -> Optional[Dict]:
    p = urlparse(url)
    # Only test URLs that look sensitive
    if not any(h in p.path.lower() for h in SENSITIVE_HINTS):
        return None

    for ext in EXTENSIONS:
        target = urlunparse((p.scheme, p.netloc, p.path + ext,
                             p.params, p.query, ""))
        r = safe_request(target, timeout=10)
        if not r:
            continue
        if r.status_code == 200:
            # Check if response looks like the original (not a 404-page)
            # Look for cache headers
            cache_hdrs = {k.lower(): v for k, v in r.headers.items()}
            has_cache = any(h in cache_hdrs for h in
                            ["x-cache", "cf-cache-status", "age", "cache-control"])
            if has_cache or len(r.content) > 1000:
                return {
                    "type": "web_cache_deception",
                    "url": target,
                    "payload": ext,
                    "evidence": f"Status {r.status_code}, cache headers: "
                                f"{[k for k in cache_hdrs if 'cache' in k]}",
                    "severity": "high",
                    "confidence": 50,
                }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "web_cache_deception", output_root)
    urls = load_urls(domain, output_root)
    sensitive = [u for u in urls if any(h in u.lower() for h in SENSITIVE_HINTS)]
    if not sensitive:
        info("No sensitive URLs to test")
        return {"count": 0, "findings": []}

    info(f"Testing {len(sensitive)} sensitive URLs for cache deception")
    findings: List[Dict] = []

    for url in sensitive[:40]:
        try:
            res = test_url(url)
            if res:
                findings.append(res)
                save_finding(domain, "web_cache_deception", res["type"],
                             res["severity"], res["url"], payload=res["payload"],
                             evidence=res["evidence"], confidence=res["confidence"],
                             scan_id=scan_id, output_root=output_root)
                warn(f"CACHE DECEPTION: {res['url']}")
        except Exception as e:
            log.debug(f"cache deception failed {url}: {e}")

    if findings:
        write_lines(mdir / "web_cache_deception_findings.txt",
                    [f"[{f['severity']}] {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "web_cache_deception", run, args.output)