"""
modules/bypass_403.py
---------------------
403 Forbidden bypass techniques.

Vectors:
  - Header injection (X-Forwarded-For, X-Original-URL)
  - Path confusion (//, /./, /../)
  - URL encoding (%2e, %2f)
  - HTTP verb tampering
  - Case manipulation
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("bypass_403")


# ─────────────────────────────────────────
# Bypass techniques
# ─────────────────────────────────────────
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Server": "localhost"},
]

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
           "HEAD", "TRACE", "CONNECT"]


# ─────────────────────────────────────────
# Path mutations
# ─────────────────────────────────────────
def path_mutations(path: str) -> List[str]:
    """
    Generate path variants that may bypass 403.
    """
    if not path:
        path = "/"
    variants = set()
    variants.add(path)
    variants.add(path + "/")
    variants.add(path + "/.")
    variants.add(path + "//")
    variants.add(path + "/..;/")
    variants.add("//" + path.lstrip("/"))
    variants.add("/." + path)
    variants.add(path + "%20")
    variants.add(path + "%09")
    variants.add(path + "?")
    variants.add(path + "%23")
    variants.add(path + "%2e")
    variants.add(path + "%2f")
    variants.add(path.upper())
    variants.add(path.lower())
    # Case manipulation
    parts = path.split("/")
    for i in range(1, len(parts)):
        parts[i] = parts[i].capitalize() if parts[i].islower() else parts[i].lower()
    variants.add("/".join(parts))
    return sorted(variants)


# ─────────────────────────────────────────
# Test URLs
# ─────────────────────────────────────────
def test_header_bypass(url: str) -> List[Dict]:
    findings: List[Dict] = []
    acquire(url)
    baseline = safe_request(url, timeout=8, allow_redirects=False)
    if not baseline or baseline.status_code != 403:
        return findings

    for headers in BYPASS_HEADERS:
        try:
            acquire(url)
            r = safe_request(url, headers=headers, timeout=8,
                             allow_redirects=False)
            if r and r.status_code not in (403, 401):
                findings.append({
                    "type": "403_bypass_header",
                    "url": url,
                    "param": list(headers.keys())[0],
                    "payload": list(headers.values())[0],
                    "evidence": f"403 → {r.status_code} with header {headers}",
                    "severity": "high",
                    "confidence": 75,
                })
                return findings  # one is enough
        except Exception:
            continue
    return findings


def test_path_bypass(url: str) -> List[Dict]:
    findings: List[Dict] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return findings

    acquire(url)
    baseline = safe_request(url, timeout=8, allow_redirects=False)
    if not baseline or baseline.status_code != 403:
        return findings

    for variant in path_mutations(parsed.path):
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, variant,
            parsed.params, parsed.query, ""
        ))
        try:
            acquire(new_url)
            r = safe_request(new_url, timeout=8, allow_redirects=False)
            if r and r.status_code not in (403, 401):
                findings.append({
                    "type": "403_bypass_path",
                    "url": new_url,
                    "payload": variant,
                    "evidence": f"403 → {r.status_code} with path '{variant}'",
                    "severity": "high",
                    "confidence": 70,
                })
                return findings
        except Exception:
            continue
    return findings


def test_method_bypass(url: str) -> List[Dict]:
    findings: List[Dict] = []
    acquire(url)
    baseline = safe_request(url, timeout=8, allow_redirects=False)
    if not baseline or baseline.status_code != 403:
        return findings

    for method in METHODS:
        try:
            acquire(url)
            r = safe_request(url, method=method, timeout=8,
                             allow_redirects=False)
            if r and r.status_code not in (403, 401, 405, 501):
                findings.append({
                    "type": "403_bypass_method",
                    "url": url,
                    "payload": method,
                    "evidence": f"403 → {r.status_code} with method {method}",
                    "severity": "medium",
                    "confidence": 60,
                })
                return findings
        except Exception:
            continue
    return findings


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def _find_403_urls(urls: List[str], max_check: int = 50) -> List[str]:
    """
    Sample URLs and keep those returning 403.
    """
    forbidden: List[str] = []
    for url in urls[:max_check]:
        try:
            acquire(url)
            r = safe_request(url, timeout=6, allow_redirects=False)
            if r and r.status_code == 403:
                forbidden.append(url)
        except Exception:
            continue
    return forbidden


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "bypass_403", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs to test")
        return {"count": 0, "findings": []}

    info("Scanning for 403-protected URLs...")
    forbidden = _find_403_urls(urls, max_check=80)
    if not forbidden:
        info("No 403-protected URLs found")
        return {"count": 0, "findings": []}

    info(f"Attempting bypass on {len(forbidden)} forbidden URLs")
    findings: List[Dict] = []

    for url in forbidden:
        for tester in (test_header_bypass, test_path_bypass, test_method_bypass):
            try:
                findings.extend(tester(url))
            except Exception as e:
                log.debug(f"bypass test failed {url}: {e}")

    # Save
    for f in findings:
        save_finding(domain, "bypass_403", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     payload=f.get("payload", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "bypass_403_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])
        ok(f"Found {len(findings)} 403 bypass(es)")

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="403 bypass scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "bypass_403", run, args.output)