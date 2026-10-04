"""
modules/api_versioning.py
-------------------------
API version enumeration & downgrade detection.

Finds:
  - /v1/, /v2/, /v3/ endpoints
  - /beta/, /alpha/, /dev/ versions
  - Deprecated versions with weaker auth
  - Version header manipulation (Accept-Version, X-API-Version)
"""

import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urlunparse, urljoin

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, dedupe
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("api_versioning")


# ─────────────────────────────────────────
# Version patterns to probe
# ─────────────────────────────────────────
VERSION_PATTERNS = [
    "v1", "v2", "v3", "v4", "v5",
    "v0", "v0.1", "v1.0", "v2.0",
    "beta", "alpha", "dev", "test", "staging", "internal",
    "legacy", "old", "deprecated", "latest", "current",
    "2020", "2021", "2022", "2023", "2024",
]

VERSION_HEADERS = [
    "Accept-Version",
    "X-API-Version",
    "X-API-Version-Override",
    "Api-Version",
    "X-Version",
]

VERSION_HEADER_VALUES = ["1", "2", "3", "v1", "v2", "v3", "0", "beta", "legacy"]


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def _find_api_prefixes(urls: List[str]) -> Set[str]:
    """
    Extract unique /api/... prefixes from URLs.
    Example: https://x.com/api/v2/users → https://x.com/api
    """
    prefixes: Set[str] = set()
    for u in urls:
        try:
            p = urlparse(u)
            parts = p.path.strip("/").split("/")
            if not parts:
                continue
            # Look for /api/ style segments
            for i, seg in enumerate(parts):
                if seg.lower() in ("api", "rest", "graphql"):
                    prefix = "/" + "/".join(parts[:i + 1])
                    prefixes.add(f"{p.scheme}://{p.netloc}{prefix}")
        except Exception:
            continue
    return prefixes


def _probe_url(url: str) -> Optional[Dict]:
    acquire(url)
    r = safe_request(url, timeout=8, allow_redirects=False)
    if not r:
        return None
    return {
        "status": r.status_code,
        "length": len(r.content),
        "content_type": r.headers.get("Content-Type", ""),
    }


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────
def discover_versions(api_prefix: str) -> List[Dict]:
    """
    Probe common version paths under an /api/ prefix.
    """
    findings: List[Dict] = []

    # Baseline (the prefix itself)
    base_resp = _probe_url(api_prefix)
    base_status = base_resp["status"] if base_resp else 0

    for version in VERSION_PATTERNS:
        for path in [f"/{version}", f"/{version}/", f"/{version}/users",
                     f"/{version}/user/1", f"/{version}/status"]:
            test_url = api_prefix + path
            try:
                resp = _probe_url(test_url)
            except Exception:
                continue
            if not resp:
                continue
            # Interesting: not 404
            if resp["status"] not in (404, 0):
                findings.append({
                    "type": "api_version_found",
                    "url": test_url,
                    "evidence": f"Status {resp['status']}, len={resp['length']}",
                    "severity": "info",
                    "confidence": 70,
                })
    return findings


def test_version_header_bypass(url: str) -> List[Dict]:
    """
    Send X-API-Version header with different values to see if behavior changes.
    """
    findings: List[Dict] = []

    # Baseline without header
    base = _probe_url(url)
    if not base:
        return findings

    for header in VERSION_HEADERS:
        for value in VERSION_HEADER_VALUES:
            try:
                acquire(url)
                r = safe_request(url, headers={header: value}, timeout=8,
                                 allow_redirects=False)
                if not r:
                    continue
                # Behavior change?
                if (r.status_code != base["status"] and
                        abs(len(r.content) - base["length"]) > 200):
                    findings.append({
                        "type": "api_version_header_downgrade",
                        "url": url,
                        "param": header,
                        "payload": value,
                        "evidence": (
                            f"Baseline: {base['status']}/{base['length']}B → "
                            f"With {header}:{value}: {r.status_code}/{len(r.content)}B"
                        ),
                        "severity": "medium",
                        "confidence": 45,
                    })
                    break
            except Exception:
                continue
    return findings


def test_deprecated_versions(api_prefix: str, current_version: str = "v3") -> List[Dict]:
    """
    Compare current version with older versions to see if auth differs.
    """
    findings: List[Dict] = []

    # Try to find a protected endpoint on current version
    test_endpoint = "/users/1"
    current_url = api_prefix + f"/{current_version}{test_endpoint}"
    current = _probe_url(current_url)
    if not current:
        return findings

    current_auth = current["status"] in (401, 403)

    # Test older versions
    for old_ver in ["v1", "v2", "v0", "beta", "legacy"]:
        if old_ver == current_version:
            continue
        old_url = api_prefix + f"/{old_ver}{test_endpoint}"
        old = _probe_url(old_url)
        if not old:
            continue
        # If old returns 200 but current requires auth → downgrade works
        if old["status"] == 200 and current_auth:
            findings.append({
                "type": "api_version_auth_downgrade",
                "url": old_url,
                "evidence": (
                    f"{old_ver} returns 200 (unauth) but {current_version} "
                    f"returns {current['status']}"
                ),
                "severity": "high",
                "confidence": 70,
            })
    return findings


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "api_versioning", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs to test")
        return {"count": 0, "findings": []}

    api_prefixes = _find_api_prefixes(urls)
    if not api_prefixes:
        info("No API prefixes detected")
        return {"count": 0, "findings": []}

    info(f"Found {len(api_prefixes)} API prefixes — probing versions")
    findings: List[Dict] = []

    for prefix in list(api_prefixes)[:10]:
        try:
            findings.extend(discover_versions(prefix))
        except Exception as e:
            log.debug(f"version discovery failed {prefix}: {e}")

        try:
            findings.extend(test_deprecated_versions(prefix))
        except Exception as e:
            log.debug(f"deprecated test failed {prefix}: {e}")

    # Header manipulation on sample API URLs
    api_urls = [u for u in urls if "/api/" in u.lower()][:15]
    for url in api_urls:
        try:
            findings.extend(test_version_header_bypass(url))
        except Exception as e:
            log.debug(f"header bypass failed {url}: {e}")

    # Save
    for f in findings:
        save_finding(domain, "api_versioning", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     payload=f.get("payload", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "api_versioning_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="API versioning scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "api_versioning", run, args.output)