"""
scanner/api_fuzzing.py
----------------------
API endpoint fuzzing (Kiterunner-style).
Discovers hidden API endpoints and methods.
"""

import re
from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, skip, warn
from core.utils import safe_request, read_lines, write_lines, ensure_dir
from core.rate_limiter import acquire
from core.config_loader import get_config

log = get_logger("api_fuzzing")
cfg = get_config()


API_COMMON = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/admin",
    "/api/login", "/api/logout", "/api/register",
    "/api/profile", "/api/me", "/api/account",
    "/api/orders", "/api/products", "/api/items",
    "/api/search", "/api/upload", "/api/download",
    "/api/config", "/api/settings", "/api/health",
    "/api/status", "/api/version", "/api/info",
    "/api/graphql", "/api/rest", "/api/v1/graphql",
    "/api/internal", "/api/private", "/api/debug",
    "/api/test", "/api/dev", "/api/staging",
]


METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


def test_api_endpoint(base_url: str, endpoint: str) -> List[Dict]:
    findings: List[Dict] = []
    url = base_url.rstrip("/") + endpoint

    try:
        acquire(url)
        r = safe_request(url, timeout=8, allow_redirects=False)
    except Exception:
        return findings
    if not r:
        return findings

    if r.status_code in (200, 201, 202, 401, 403, 405):
        findings.append({
            "type": "api_endpoint",
            "url": url,
            "status": r.status_code,
            "method": "GET",
            "severity": "info",
            "confidence": 60,
        })

        if r.status_code == 405:
            for method in METHODS:
                if method == "GET":
                    continue
                try:
                    acquire(url)
                    r2 = safe_request(url, method=method, timeout=8,
                                      allow_redirects=False)
                    if r2 and r2.status_code not in (404, 405):
                        findings.append({
                            "type": "api_method_allowed",
                            "url": url,
                            "status": r2.status_code,
                            "method": method,
                            "severity": "info",
                            "confidence": 70,
                        })
                except Exception:
                    continue

    return findings


def scan_api(target_url: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)

    findings: List[Dict] = []
    info(f"API fuzzing: {target_url}")

    for endpoint in API_COMMON:
        try:
            findings.extend(test_api_endpoint(target_url, endpoint))
        except Exception as e:
            log.debug(f"api probe failed {endpoint}: {e}")

    if findings:
        write_lines(Path(output_dir) / "api_endpoints.txt",
                    sorted({f"{f['method']} {f['url']}" for f in findings}))
        ok(f"API fuzzing: {len(findings)} endpoints found")
    else:
        info("API fuzzing: no new endpoints")

    return {"count": len(findings), "findings": findings}


def scan_api_from_file(urls_file: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)
    urls = read_lines(urls_file)
    if not urls:
        return {"count": 0, "findings": []}

    hosts = sorted({f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in urls})
    findings: List[Dict] = []

    for host in hosts[:10]:
        try:
            r = scan_api(host, output_dir)
            findings.extend(r.get("findings", []))
        except Exception as e:
            log.debug(f"api scan failed for {host}: {e}")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="API fuzzing scanner")
    p.add_argument("-t", "--target")
    p.add_argument("-l", "--list")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()

    if args.target:
        result = scan_api(args.target, args.output)
    elif args.list:
        result = scan_api_from_file(args.list, args.output)
    else:
        print("Provide --target or --list")
        raise SystemExit(1)

    print(f"\nAPI endpoints: {result['count']}")