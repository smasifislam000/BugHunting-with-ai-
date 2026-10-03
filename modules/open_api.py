"""
modules/open_api.py
-------------------
OpenAPI / Swagger discovery:
- Probe common spec paths
- Parse endpoints
- Flag unauthenticated spec exposure
"""

import json
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, dedupe, save_json
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("open_api")


SPEC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/api/openapi.json",
    "/.well-known/openapi.json", "/docs/openapi.json",
]


def probe_spec(base: str) -> Optional[Dict]:
    for path in SPEC_PATHS:
        url = base.rstrip("/") + path
        r = safe_request(url, timeout=8)
        if not r or r.status_code != 200:
            continue
        text = r.text or ""
        # Heuristic: JSON with "openapi" or "swagger"
        looks_like = False
        if '"openapi"' in text or '"swagger"' in text:
            looks_like = True
        elif path.endswith(".yaml") and ("openapi:" in text or "swagger:" in text):
            looks_like = True
        if not looks_like:
            continue
        endpoints = []
        try:
            spec = json.loads(text)
            paths = spec.get("paths", {})
            endpoints = list(paths.keys())[:200]
        except Exception:
            pass
        return {
            "url": url,
            "endpoints": endpoints,
            "endpoint_count": len(endpoints),
            "raw_preview": text[:500],
        }
    return None


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "open_api", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs to probe")
        return {"count": 0, "findings": []}

    hosts = set()
    for u in urls[:100]:
        p = urlparse(u)
        hosts.add(f"{p.scheme}://{p.netloc}")

    info(f"Probing {len(hosts)} hosts for OpenAPI specs")
    findings: List[Dict] = []

    for host in sorted(hosts)[:40]:
        try:
            res = probe_spec(host)
            if res:
                findings.append(res)
                save_finding(
                    domain, "open_api", "openapi_spec_exposed",
                    "medium", res["url"],
                    evidence=f"{res['endpoint_count']} endpoints exposed",
                    confidence=90,
                    scan_id=scan_id, output_root=output_root,
                )
                # Save spec endpoints
                if res["endpoints"]:
                    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)
                    write_lines(mdir / f"spec_endpoints_{safe_name}.txt",
                                res["endpoints"])
        except Exception as e:
            log.debug(f"openapi probe failed {host}: {e}")

    if findings:
        save_json(mdir / "openapi_findings.json", findings)

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "open_api", run, args.output)