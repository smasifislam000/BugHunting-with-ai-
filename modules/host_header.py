"""
modules/host_header.py
----------------------
Host Header Injection testing.

Vectors:
  - Password reset poisoning (via reset password email link)
  - Cache poisoning (via X-Forwarded-Host, X-Host)
  - Routing-based SSRF
  - Virtual host brute force
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("host_header")


# ─────────────────────────────────────────
# Payloads
# ─────────────────────────────────────────
HOST_PAYLOADS = [
    "evil.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "internal.target.local",
    "target.com.evil.com",
    "evil.com#target.com",
    "target.com@evil.com",
    "169.254.169.254",
    "localhost:8080",
    "[::1]",
]

INJECT_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Forwarded",
    "X-Host",
    "X-Forwarded-For",
]

# Sensitive endpoints where Host injection is dangerous
SENSITIVE_PATHS = [
    "/password/reset", "/password/forgot", "/forgot",
    "/reset", "/account/recover", "/user/forgot",
    "/api/password/reset", "/auth/reset",
]

MARKER = "hhinject-{token}.evil.com"


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def _new_marker() -> str:
    import time
    return MARKER.format(token=int(time.time()))


def _fetch(url: str, headers: Dict[str, str]) -> Optional[object]:
    acquire(url)
    return safe_request(url, headers=headers, timeout=10,
                        allow_redirects=False)


def _detect_reflection(response, marker: str) -> bool:
    if response is None:
        return False
    body = response.text or ""
    if marker in body:
        return True
    # Check Location header
    loc = ""
    if hasattr(response, "headers"):
        loc = response.headers.get("Location", "")
    if marker in loc:
        return True
    return False


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────
def test_host_reflection(url: str) -> List[Dict]:
    """
    Send requests with injected Host/XFH headers; detect reflection.
    """
    findings: List[Dict] = []

    for header in INJECT_HEADERS:
        marker = _new_marker()
        try:
            r = _fetch(url, {header: marker})
        except Exception:
            continue
        if _detect_reflection(r, marker):
            findings.append({
                "type": "host_header_reflection",
                "url": url,
                "param": header,
                "payload": marker,
                "evidence": f"'{marker}' reflected via {header} header",
                "severity": "medium",
                "confidence": 70,
            })
    return findings


def test_password_reset_poisoning(url: str) -> List[Dict]:
    """
    Look for password reset endpoints and check if reset link uses Host.
    """
    findings: List[Dict] = []
    if not any(p in url.lower() for p in ["reset", "forgot", "recover"]):
        return findings

    marker = _new_marker()
    for header in ["Host", "X-Forwarded-Host"]:
        try:
            r = _fetch(url, {header: marker, "Content-Type": "application/x-www-form-urlencoded"})
        except Exception:
            continue
        # Even if response doesn't reflect, look for potential email trigger message
        if r and r.status_code in (200, 201, 202, 302):
            body = (r.text or "").lower()
            if any(k in body for k in ["email", "sent", "check your inbox",
                                       "reset link", "we have sent"]):
                findings.append({
                    "type": "host_header_reset_poisoning_suspect",
                    "url": url,
                    "param": header,
                    "payload": marker,
                    "evidence": f"Reset endpoint accepts {header} — check email for {marker}",
                    "severity": "high",
                    "confidence": 45,
                })
    return findings


def test_cache_poisoning_simple(url: str) -> List[Dict]:
    """
    Quick cache poisoning check with X-Forwarded-Host.
    (Full cache poisoning is in cache_poison.py — this is a stub.)
    """
    findings: List[Dict] = []
    marker = _new_marker()
    for header in ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server"]:
        try:
            r = _fetch(url, {header: marker})
        except Exception:
            continue
        if _detect_reflection(r, marker):
            findings.append({
                "type": "host_header_cache_poison_suspect",
                "url": url,
                "param": header,
                "payload": marker,
                "evidence": f"Reflected via {header}; may be cacheable",
                "severity": "high",
                "confidence": 50,
            })
    return findings


def test_vhost_bruteforce(url: str) -> List[Dict]:
    """
    Try common internal Host values to see if routing changes.
    """
    findings: List[Dict] = []
    parsed = urlparse(url)
    base_path = parsed.path or "/"

    # Baseline
    try:
        baseline = _fetch(url, {})
        base_len = len(baseline.content) if baseline else 0
        base_status = baseline.status_code if baseline else 0
    except Exception:
        return findings

    for payload in ["localhost", "127.0.0.1", "internal", "admin.local",
                    "dev.local", "test.local"]:
        try:
            r = _fetch(url, {"Host": payload})
        except Exception:
            continue
        if not r:
            continue
        # If status or size differs significantly → potential vhost
        if r.status_code != base_status or abs(len(r.content) - base_len) > 500:
            findings.append({
                "type": "host_header_vhost_diff",
                "url": url,
                "param": "Host",
                "payload": payload,
                "evidence": (
                    f"Baseline: {base_status}/{base_len}B → "
                    f"Injected: {r.status_code}/{len(r.content)}B"
                ),
                "severity": "low",
                "confidence": 40,
            })
    return findings


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "host_header", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs to test")
        return {"count": 0, "findings": []}

    # Sample URLs — heavy tests are expensive
    sample = urls[:20]
    info(f"Testing {len(sample)} URLs for Host Header Injection")

    all_findings: List[Dict] = []

    for url in sample:
        try:
            all_findings.extend(test_host_reflection(url))
        except Exception as e:
            log.debug(f"host reflection failed {url}: {e}")

        try:
            all_findings.extend(test_vhost_bruteforce(url))
        except Exception as e:
            log.debug(f"vhost bruteforce failed {url}: {e}")

        try:
            all_findings.extend(test_cache_poisoning_simple(url))
        except Exception as e:
            log.debug(f"cache poison check failed {url}: {e}")

    # Dedicated password-reset tests
    reset_urls = [u for u in urls if any(k in u.lower()
                  for k in ["reset", "forgot", "recover"])]
    for url in reset_urls[:10]:
        try:
            all_findings.extend(test_password_reset_poisoning(url))
        except Exception as e:
            log.debug(f"reset test failed {url}: {e}")

    # Save
    for f in all_findings:
        save_finding(domain, "host_header", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     payload=f.get("payload", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if all_findings:
        write_lines(mdir / "host_header_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']} ({f['param']})"
                     for f in all_findings])
        ok(f"Found {len(all_findings)} host-header finding(s)")
    else:
        info("No host-header issues detected")

    return {"count": len(all_findings), "findings": all_findings}


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Host header injection scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "host_header", run, args.output)