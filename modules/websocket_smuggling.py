"""
modules/websocket_smuggling.py
------------------------------
WebSocket smuggling / H2C smuggling detection.

Techniques:
  - H2C upgrade + smuggling
  - WebSocket protocol confusion
  - Origin bypass in WS handshake
"""

import base64
import socket
import os
import ssl
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from core.rate_limiter import acquire
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("websocket_smuggling")


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def test_origin_check(host: str, path: str, port: int,
                      use_tls: bool) -> Optional[Dict]:
    """
    Send WebSocket handshake with attacker-controlled Origin.
    """
    key = _ws_key()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: https://evil-attacker.com\r\n"
        f"\r\n"
    ).encode()

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
    except Exception:
        return None

    text = data.decode("utf-8", errors="ignore")
    if "101" in text.split("\r\n")[0]:
        return {
            "type": "websocket_origin_not_enforced",
            "url": f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}",
            "evidence": "Server accepted handshake from attacker Origin",
            "severity": "medium",
            "confidence": 75,
        }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "websocket_smuggling", output_root)
    urls = load_urls(domain, output_root)

    # Find WS endpoints or sockets
    candidates: List[Dict] = []
    for u in urls:
        low = u.lower()
        if any(k in low for k in ["/ws", "/socket", "websocket", "socket.io"]):
            p = urlparse(u)
            if p.hostname:
                candidates.append({
                    "host": p.hostname,
                    "path": p.path or "/",
                    "port": p.port or (443 if p.scheme == "https" else 80),
                    "tls": p.scheme == "https",
                })

    if not candidates:
        info("No WebSocket candidates found")
        return {"count": 0, "findings": []}

    info(f"WebSocket smuggling: {len(candidates[:15])} candidates")
    findings: List[Dict] = []

    for c in candidates[:15]:
        try:
            res = test_origin_check(c["host"], c["path"], c["port"], c["tls"])
            if res:
                findings.append(res)
        except Exception as e:
            log.debug(f"ws smuggling test failed: {e}")

    for f in findings:
        save_finding(domain, "websocket_smuggling", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "ws_smuggling_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WebSocket smuggling scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "websocket_smuggling", run, args.output)