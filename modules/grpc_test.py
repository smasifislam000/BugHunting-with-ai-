"""
modules/grpc_test.py
--------------------
gRPC endpoint detection and basic testing.

Detects gRPC services via:
  - HTTP/2 cleartext (h2c) on common ports
  - gRPC reflection API
  - Common gRPC health check
"""

import socket
import ssl
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("grpc_test")


GRPC_PORTS = [50051, 443, 8080, 9090, 8443]
GRPC_PATHS = [
    "/grpc.health.v1.Health/Check",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
]


def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def test_grpc_reflection(host: str, port: int,
                         use_tls: bool = False) -> Optional[Dict]:
    """
    Probe gRPC reflection over HTTP/2.
    """
    scheme = "https" if use_tls else "http"
    for path in GRPC_PATHS:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            r = safe_request(url, method="POST",
                             headers={
                                 "Content-Type": "application/grpc",
                                 "TE": "trailers",
                             },
                             data=b"\x00\x00\x00\x00\x00",
                             timeout=8)
        except Exception:
            continue
        if r and r.status_code in (200, 400, 415):
            # gRPC responses often have 200 with grpc-status trailer
            return {
                "type": "grpc_service_detected",
                "url": url,
                "evidence": f"gRPC service on {host}:{port} - status {r.status_code}",
                "severity": "info",
                "confidence": 70,
            }
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "grpc_test", output_root)
    urls = load_urls(domain, output_root)

    hosts = set()
    for u in urls:
        try:
            p = urlparse(u)
            if p.hostname:
                hosts.add(p.hostname)
        except Exception:
            continue

    if not hosts:
        info("No hosts to test for gRPC")
        return {"count": 0, "findings": []}

    info(f"gRPC: checking {len(hosts[:5])} hosts on {len(GRPC_PORTS)} ports")
    findings: List[Dict] = []

    for host in list(hosts)[:5]:
        for port in GRPC_PORTS:
            if not _port_open(host, port):
                continue

            for use_tls in (True, False):
                try:
                    res = test_grpc_reflection(host, port, use_tls=use_tls)
                    if res:
                        findings.append(res)
                        break
                except Exception as e:
                    log.debug(f"grpc test failed: {e}")

    for f in findings:
        save_finding(domain, "grpc_test", f["type"], f["severity"],
                     f["url"], evidence=f.get("evidence", ""),
                     confidence=f.get("confidence", 0),
                     scan_id=scan_id, output_root=output_root)

    if findings:
        write_lines(mdir / "grpc_findings.txt",
                    [f"[{f['severity']}] {f['type']} -> {f['url']}"
                     for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="gRPC scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "grpc_test", run, args.output)