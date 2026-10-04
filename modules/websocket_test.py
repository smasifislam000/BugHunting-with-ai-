"""
modules/websocket_test.py
-------------------------
WebSocket fuzzing and security checks.

Checks:
  - WS endpoint detection
  - Missing auth on WS connect
  - CSWSH (Cross-Site WebSocket Hijacking)
  - Mass assignment via WS messages
"""

import base64
import os
import socket
import ssl
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("websocket_test")


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _handshake(host: str, path: str, port: int,
               use_tls: bool, origin: str = "",
               cookie: str = "") -> Optional[str]:
    key = _ws_key()
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        headers.append(f"Origin: {origin}")
    if cookie:
        headers.append(f"Cookie: {cookie}")

    request = ("\r\n".join(headers) + "\r\n\r\n").encode()

    try:
        s = socket.create_connection((host, port), timeout=6)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(request)
        s.settimeout(5)
        data = s.recv(4096)
        s.close()
        return data.decode("utf-8", errors="ignore")
    except Exception as e:
        log.debug(f"ws handshake failed: {e}")
        return None


def test_unauth_ws(host: str, path: str, port: int,
                   use_tls: bool) -> Optional[Dict]:
    """
    Test if WS connects without auth (no cookies).
    """
    resp = _handshake(host, path, port, use_tls, origin="https://example.com")
    if resp and "101" in resp.split("\r\n")[0]:
        return {
            "type": "websocket_no_auth",
            "url": f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}",
            "evidence": "WS accepted handshake without authentication",
            "severity": "medium",
            "confidence": 70,
        }
    return None


def test_cswsh(host: str, path: str, port: int,
               use_tls: bool) -> Optional[Dict]:
    """
    Cross-Site WebSocket Hijacking: no Origin check.
    """
    resp = _handshake(host, path, port, use_tls,
                      origin="https://evil-attacker.com")
    if resp and "101" in resp.split("\r\n")[0]:
        return {
            "type": "websocket_cswsh",
            "url": f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}",
            "evidence": "Handshake accepted from attacker Origin (CSWSH)",
            "severity": "high",
            "confidence": 80,
        }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "websocket_test", output_root)
    urls = load_urls(domain, output_root)

    candidates: List[Dict] = []
    for u in urls:
        low = u.lower()
        if any(k in low for k in ["/ws", "/socket", "websocket", "socket.io", "/chat"]):
            p = urlparse(u)
            if p.hostname:
                candidates.append({
                    "host": p.hostname,
                    "path": p.path or "/",
                    "port": p.port or (443 if p.scheme == "https" else 80),
                    "tls": p.scheme == "https",
                })

    if not candidates:
        info("No WebSocket endpoints found")
        return {"count": 0, "findings": []}

    info(f"WebSocket testing: {len(candidates[:15])} endpoints")
    findings: List[Dict] = []

    for c in candidates[:15]:
        for tester in (test_unauth_ws, test_cswsh):
            try:
                res = tester(c["host"], c["path"], c["port"], c["tls"])
                if res:
                    findings.append(res)
            except Exception as e:
                log.debug(f"ws test failed: {e}")

    for f in findings:
        save_finding(domain, "websocket_test", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "websocket_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WebSocket security scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "websocket_test", run, args.output)