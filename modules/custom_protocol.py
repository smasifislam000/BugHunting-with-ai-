"""
modules/custom_protocol.py
--------------------------
Custom protocol detection: WebSocket, gRPC, MQTT, Socket.io.
Detects endpoints and suggests tests.
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines, has_tool
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("custom_protocol")


def find_ws_endpoints(urls: List[str]) -> List[str]:
    """Detect WebSocket endpoints in URL list and JS files."""
    ws = set()
    for u in urls:
        low = u.lower()
        if any(k in low for k in ["/ws", "/socket", "/websocket", "socket.io"]):
            ws.add(u)
    return sorted(ws)


def scan_js_for_protocols(js_url: str) -> List[Dict]:
    findings: List[Dict] = []
    r = safe_request(js_url, timeout=10)
    if not r or r.status_code != 200:
        return []

    text = r.text or ""

    patterns = [
        (re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)'), "websocket", "info"),
        (re.compile(r'socket\.io'), "socket.io", "info"),
        (re.compile(r'grpc://[^"\']+'), "grpc", "info"),
        (re.compile(r'wss?://[^"\']+'), "wss", "info"),
        (re.compile(r'mqtt://[^"\']+'), "mqtt", "info"),
    ]

    for pat, kind, severity in patterns:
        for m in pat.finditer(text):
            findings.append({
                "type": f"custom_protocol_{kind}",
                "url": js_url,
                "evidence": f"{kind}: {m.group(0)[:120]}",
                "severity": severity,
                "confidence": 40,
            })
    return findings


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "custom_protocol", output_root)
    urls = load_urls(domain, output_root)

    # Direct endpoints
    ws_endpoints = find_ws_endpoints(urls)
    js_urls = [u for u in urls if ".js" in u.lower().split("?")[0]]

    info(f"Found {len(ws_endpoints)} WS candidates, scanning {len(js_urls[:40])} JS files")
    findings: List[Dict] = []

    for ep in ws_endpoints:
        findings.append({
            "type": "websocket_endpoint",
            "url": ep,
            "evidence": "WebSocket-like endpoint detected",
            "severity": "info",
            "confidence": 50,
        })
        save_finding(domain, "custom_protocol", "websocket_endpoint", "info",
                     ep, evidence="WebSocket-like endpoint detected",
                     confidence=50, scan_id=scan_id, output_root=output_root)

    for js in js_urls[:40]:
        try:
            for f in scan_js_for_protocols(js):
                findings.append(f)
                save_finding(domain, "custom_protocol", f["type"], f["severity"],
                             f["url"], evidence=f["evidence"],
                             confidence=f["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"custom protocol scan failed {js}: {e}")

    if findings:
        write_lines(mdir / "custom_protocol_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "custom_protocol", run, args.output)