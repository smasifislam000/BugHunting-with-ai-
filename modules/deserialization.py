"""
modules/deserialization.py
--------------------------
Detects deserialization attack surface.
Looks for cookies/headers/bodies with serialized markers.
Does NOT auto-exploit (needs manual PoC), but flags opportunities.
"""

import re
import base64
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("deserialization")


# Serialization markers per language
MARKERS = {
    "java":       [re.compile(r"^rO0AB"),                # base64 of \xac\xed\x00\x05
                   re.compile(r"\xac\xed\x00\x05")],
    "php":        [re.compile(r'^a:\d+:\{'), re.compile(r'^O:\d+:"')],
    "python":     [re.compile(r"^gASV"), re.compile(r"^gAJ")],  # pickle base64 prefixes
    "dotnet":     [re.compile(r"^AAEAAAD/////")],  # .NET BinaryFormatter base64
    "ruby":       [re.compile(r"^BAh7")],  # Marshal base64
    "node":       [re.compile(r"^eyJ")],  # could be JWT, common
}


def detect_serialized(text: str) -> List[str]:
    hits = []
    if not text:
        return hits
    for lang, pats in MARKERS.items():
        for pat in pats:
            if pat.search(text):
                hits.append(lang)
                break
    return hits


def inspect_url(url: str) -> List[Dict]:
    findings: List[Dict] = []
    r = safe_request(url, timeout=10)
    if not r:
        return findings

    # Cookies
    for c in r.cookies:
        langs = detect_serialized(c.value)
        if langs:
            findings.append({
                "type": "deserialization_cookie",
                "url": url,
                "param": c.name,
                "payload": c.value[:100],
                "evidence": f"Serialized data detected: {langs}",
                "severity": "high",
                "confidence": 45,
            })

    # Headers
    for h in ["X-Data", "X-Session", "X-Auth", "Set-Cookie"]:
        v = r.headers.get(h)
        if v:
            langs = detect_serialized(v)
            if langs:
                findings.append({
                    "type": "deserialization_header",
                    "url": url,
                    "param": h,
                    "payload": v[:100],
                    "evidence": f"Serialized data in header: {langs}",
                    "severity": "high",
                    "confidence": 40,
                })

    # Body
    langs = detect_serialized(r.text[:5000])
    if langs:
        findings.append({
            "type": "deserialization_body",
            "url": url,
            "evidence": f"Serialized data in body: {langs}",
            "severity": "medium",
            "confidence": 35,
        })

    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "deserialization", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    info(f"Inspecting {len(urls[:80])} URLs for serialized data")
    findings: List[Dict] = []

    for url in urls[:80]:
        try:
            for f in inspect_url(url):
                findings.append(f)
                save_finding(domain, "deserialization", f["type"], f["severity"],
                             f["url"], param=f.get("param", ""),
                             payload=f.get("payload", ""),
                             evidence=f["evidence"], confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"deser inspect failed: {e}")

    if findings:
        write_lines(mdir / "deserialization_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "deserialization", run, args.output)