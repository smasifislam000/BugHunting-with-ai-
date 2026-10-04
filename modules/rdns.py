"""
modules/rdns.py
---------------
Reverse DNS (PTR) analysis.
Discovers:
  - PTR records for IPs
  - Other domains sharing the same IP
  - Internal hostnames leaked via PTR
"""

import socket
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn
from core.utils import (
    safe_request, write_lines, run_command, has_tool, dedupe
)
from modules._common import load_urls, recon_dir, module_dir, save_finding, cli_main

log = get_logger("rdns")


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def _extract_ips(urls: List[str]) -> Set[str]:
    """
    Extract unique IPs from URL list.
    """
    ips: Set[str] = set()
    for u in urls:
        try:
            p = urlparse(u)
            host = p.hostname or ""
            # Only add if it's already an IP
            if _is_ip(host):
                ips.add(host)
        except Exception:
            continue
    return ips


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except Exception:
        return False


def _resolve(host: str) -> List[str]:
    """
    Resolve a hostname to IPs.
    """
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return ips
    except Exception:
        return []


def _reverse_lookup(ip: str) -> Optional[str]:
    """
    PTR lookup for an IP.
    """
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


# ─────────────────────────────────────────
# Analysis
# ─────────────────────────────────────────
def lookup_ips(ips: Set[str]) -> List[Dict]:
    """
    PTR lookup for a set of IPs.
    """
    findings: List[Dict] = []
    for ip in sorted(ips)[:50]:
        host = _reverse_lookup(ip)
        if not host:
            continue
        findings.append({
            "ip": ip,
            "ptr": host,
        })
    return findings


def shared_hosting(ip_to_hosts: Dict[str, Set[str]]) -> List[Dict]:
    """
    Find IPs that serve multiple hosts.
    """
    results: List[Dict] = []
    for ip, hosts in ip_to_hosts.items():
        if len(hosts) > 1:
            results.append({
                "ip": ip,
                "host_count": len(hosts),
                "hosts": sorted(hosts)[:20],
            })
    return sorted(results, key=lambda x: -x["host_count"])


def detect_internal_leaks(ptr_results: List[Dict]) -> List[Dict]:
    """
    PTR records leaking internal naming conventions.
    """
    internal_markers = [
        "internal", "intranet", "corp", "lan", "local",
        "dev", "staging", "test", "backend", "db", "admin",
    ]
    findings: List[Dict] = []
    for r in ptr_results:
        host_low = r["ptr"].lower()
        for m in internal_markers:
            if m in host_low:
                findings.append({
                    "type": "rdns_internal_leak",
                    "ip": r["ip"],
                    "ptr": r["ptr"],
                    "marker": m,
                })
                break
    return findings


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None) -> Dict:
    mdir = module_dir(domain, "rdns", output_root)
    recon = recon_dir(domain, output_root)

    # Collect candidate hostnames
    hostnames: Set[str] = set()
    for fname in ("subdomains.txt", "live_hosts.txt"):
        path = recon / fname
        if path.exists():
            for line in path.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    p = urlparse(line if "://" in line else "https://" + line)
                    if p.hostname:
                        hostnames.add(p.hostname)
                except Exception:
                    continue

    if not hostnames:
        info("No hostnames available for rDNS")
        return {"count": 0, "findings": []}

    info(f"Resolving {len(hostnames)} hostnames to IPs")
    ip_to_hosts: Dict[str, Set[str]] = {}
    for h in list(hostnames)[:100]:
        ips = _resolve(h)
        for ip in ips:
            ip_to_hosts.setdefault(ip, set()).add(h)

    all_ips: Set[str] = set(ip_to_hosts.keys())
    info(f"Found {len(all_ips)} unique IPs")

    # PTR lookups
    info("Performing PTR lookups")
    ptr_results = lookup_ips(all_ips)

    # Save results
    ptr_file = mdir / "rdns_records.txt"
    write_lines(ptr_file,
                [f"{r['ip']} -> {r['ptr']}" for r in ptr_results])

    # Shared hosting
    shared = shared_hosting(ip_to_hosts)
    if shared:
        shared_file = mdir / "shared_hosting.txt"
        lines = []
        for item in shared:
            lines.append(f"\nIP: {item['ip']} ({item['host_count']} hosts)")
            for h in item["hosts"]:
                lines.append(f"  - {h}")
        shared_file.write_text("\n".join(lines), encoding="utf-8")

    # Internal leaks
    leaks = detect_internal_leaks(ptr_results)
    for lk in leaks:
        save_finding(
            domain, "rdns", lk["type"], "low",
            f"https://{lk['ptr']}",
            evidence=f"PTR record exposes internal marker '{lk['marker']}'",
            confidence=50, scan_id=scan_id, output_root=output_root
        )

    ok(f"rDNS: {len(ptr_results)} PTR records, {len(shared)} shared-hosting IPs, {len(leaks)} internal leaks")

    return {
        "count": len(ptr_results),
        "findings": ptr_results,
        "shared_hosting": shared,
        "internal_leaks": leaks,
    }


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Reverse DNS analysis")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    args = p.parse_args()
    cli_main(args.target, "rdns", run, args.output)