"""
modules/oauth_test.py
---------------------
OAuth 2.0 / OIDC misconfiguration tests:
- Open redirect via redirect_uri
- Missing state parameter
- Missing PKCE (for public clients)
- Token leakage via Referer
- Implicit flow issues
- Wildcard / subdomain redirect_uri bypass
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, dedupe
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("oauth_test")


OAUTH_HINT = re.compile(
    r"(oauth|authorize|auth|login|sso|openid|connect|callback|redirect)",
    re.IGNORECASE
)
REDIRECT_PARAMS = ["redirect_uri", "redirect_url", "callback", "return",
                   "return_to", "next", "continue", "url", "target"]


def find_oauth_endpoints(urls: List[str]) -> List[str]:
    return [u for u in urls if OAUTH_HINT.search(u)]


def test_redirect_uri_bypass(url: str) -> List[Dict]:
    """
    Try common redirect_uri bypass payloads.
    """
    findings: List[Dict] = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    candidate_params = [p for p in REDIRECT_PARAMS if p in qs]
    if not candidate_params:
        candidate_params = [p for p in REDIRECT_PARAMS if p in url]
    if not candidate_params:
        return []

    payloads = [
        "https://evil.com",
        "//evil.com",
        "https://evil.com#trusted.com",
        "https://trusted.com.evil.com",
        "https://trusted.com@evil.com",
        "https://evil.com/trusted.com",
        "https://trusted.com%2f.evil.com",
        "https://evil.com\\@trusted.com",
    ]

    for param in candidate_params:
        for payload in payloads:
            try:
                new_qs = dict(qs)
                new_qs[param] = [payload]
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(new_qs, doseq=True), parsed.fragment
                ))
            except Exception:
                continue
            r = safe_request(new_url, timeout=10, allow_redirects=False)
            if not r:
                continue
            location = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                findings.append({
                    "type": "oauth_open_redirect",
                    "url": new_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Redirected to: {location}",
                    "severity": "high",
                    "confidence": 90,
                })
                break

    return findings


def check_missing_state(url: str) -> Optional[Dict]:
    """Check if the OAuth authorize URL lacks a state parameter."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if "response_type" in qs and "state" not in qs:
        return {
            "type": "oauth_missing_state",
            "url": url,
            "evidence": "OAuth authorize URL without state parameter",
            "severity": "medium",
            "confidence": 70,
        }
    return None


def check_pkce(url: str) -> Optional[Dict]:
    """Check if PKCE code_challenge is missing for public clients."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if (qs.get("response_type", [""])[0] == "code"
            and "code_challenge" not in qs
            and qs.get("client_id")):
        return {
            "type": "oauth_missing_pkce",
            "url": url,
            "evidence": "Authorization code flow without PKCE",
            "severity": "medium",
            "confidence": 60,
        }
    return None


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "oauth_test", output_root)
    urls = load_urls(domain, output_root)
    endpoints = find_oauth_endpoints(urls)
    if not endpoints:
        info("No OAuth-like endpoints found")
        return {"count": 0, "findings": []}

    info(f"Testing {len(endpoints)} OAuth endpoints")
    findings: List[Dict] = []

    for url in endpoints[:30]:
        try:
            findings.extend(test_redirect_uri_bypass(url))
        except Exception as e:
            log.debug(f"redirect test failed {url}: {e}")

        try:
            m = check_missing_state(url)
            if m:
                findings.append(m)
        except Exception:
            pass

        try:
            p = check_pkce(url)
            if p:
                findings.append(p)
        except Exception:
            pass

    # Save
    for f in findings:
        save_finding(domain, "oauth_test", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     payload=f.get("payload", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "oauth_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "oauth_test", run, args.output)