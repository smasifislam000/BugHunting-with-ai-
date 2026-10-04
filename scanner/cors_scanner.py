"""
scanner/cors_scanner.py
-----------------------
CORS misconfiguration scanner.
Tests multiple Origin payloads and analyzes response headers.
"""

from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, skip, warn
from core.utils import safe_request, write_lines, ensure_dir, read_lines
from core.rate_limiter import acquire
from core.config_loader import get_config

log = get_logger("cors")
cfg = get_config()


ORIGIN_PAYLOADS = [
    "https://evil.com",
    "https://evil.com.attacker.net",
    "http://evil.com",
    "null",
    "https://attacker.example.com",
    "https://sub.example.com.evil.com",
]


def _build_test_origin(target_url: str) -> str:
    try:
        p = urlparse(target_url)
        return f"https://evil-{p.netloc}"
    except Exception:
        return "https://evil.com"


def test_url(url: str) -> List[Dict]:
    findings: List[Dict] = []

    origin_payloads = list(ORIGIN_PAYLOADS)
    origin_payloads.append(_build_test_origin(url))

    for origin in origin_payloads:
        try:
            acquire(url)
            r = safe_request(
                url, method="GET",
                headers={"Origin": origin},
                timeout=8, allow_redirects=False
            )
        except Exception:
            continue
        if not r:
            continue

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = r.headers.get("Access-Control-Allow-Methods", "")

        if not acao:
            continue

        # Case 1: reflection of attacker origin
        if origin in acao and origin not in ("null",):
            severity = "high" if acac == "true" else "medium"
            findings.append({
                "type": "cors_misconfiguration",
                "url": url,
                "payload": origin,
                "evidence": (
                    f"ACAO reflects '{acao}'; "
                    f"ACAC={acac or 'none'}; "
                    f"ACAM={acam}"
                ),
                "severity": severity,
                "confidence": 90,
            })
            break

        # Case 2: wildcard with credentials
        if acao == "*" and acac == "true":
            findings.append({
                "type": "cors_wildcard_with_credentials",
                "url": url,
                "payload": origin,
                "evidence": "ACAO=* AND ACAC=true (invalid but dangerous)",
                "severity": "high",
                "confidence": 85,
            })
            break

        # Case 3: null origin accepted
        if origin == "null" and acao == "null":
            findings.append({
                "type": "cors_null_origin_allowed",
                "url": url,
                "payload": "null",
                "evidence": "Server accepts 'null' Origin",
                "severity": "medium",
                "confidence": 80,
            })
            break

    return findings


def scan_cors(urls_file: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)
    urls = read_lines(urls_file)
    if not urls:
        info("No URLs for CORS scan")
        return {"count": 0, "findings": []}

    info(f"CORS: testing {len(urls[:50])} URLs")
    findings: List[Dict] = []

    for url in urls[:50]:
        try:
            findings.extend(test_url(url))
        except Exception as e:
            log.debug(f"CORS test failed for {url}: {e}")

    if findings:
        write_lines(Path(output_dir) / "cors_findings.txt",
                    [f"[{f['severity']}] {f['url']} - {f['evidence']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="CORS scanner")
    p.add_argument("-l", "--list", required=True)
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = scan_cors(args.list, args.output)
    print(f"\nCORS findings: {result['count']}")