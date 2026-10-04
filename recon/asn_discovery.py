"""
recon/asn_discovery.py
----------------------
ASN discovery from IP addresses via whois.
Finds ASN, then enumerates all IP ranges belonging to that ASN.
"""

import re
from pathlib import Path
from typing import List, Dict, Set

from core.logger import get_logger, info, ok, skip, warn
from core.utils import (
    read_lines, write_lines, ensure_dir, run_command, has_tool
)

log = get_logger("asn_discovery")


def extract_asn_from_whois(ip: str) -> List[str]:
    if not has_tool("whois"):
        return []
    out = run_command(f"whois {ip}", timeout=15)
    if not out:
        return []
    asns: Set[str] = set()
    for line in out.splitlines():
        m = re.search(r"origin\s*:\s*(AS\d+)", line, re.IGNORECASE)
        if m:
            asns.add(m.group(1).upper())
        m2 = re.search(r"^(AS\d+)\s", line)
        if m2:
            asns.add(m2.group(1).upper())
    return sorted(asns)


def asn_to_prefixes(asn: str) -> List[str]:
    if not has_tool("whois"):
        return []
    out = run_command(f"whois -h whois.radb.net -- '-i origin {asn}'", timeout=30)
    if not out:
        return []
    prefixes: Set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("route:") or line.startswith("route6:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                prefixes.add(parts[1].strip())
    return sorted(prefixes)


def discover_asns(ips_file: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)

    ips = read_lines(ips_file)
    if not ips:
        info("No IPs for ASN discovery")
        return {"asns": [], "prefixes": []}

    info(f"ASN discovery: {len(ips[:50])} IPs")
    all_asns: Set[str] = set()

    for ip in ips[:50]:
        try:
            for asn in extract_asn_from_whois(ip):
                all_asns.add(asn)
        except Exception as e:
            log.debug(f"whois failed for {ip}: {e}")

    asn_list = sorted(all_asns)
    write_lines(Path(output_dir) / "asns.txt", asn_list)

    all_prefixes: Set[str] = set()
    for asn in asn_list[:10]:
        try:
            for p in asn_to_prefixes(asn):
                all_prefixes.add(p)
        except Exception as e:
            log.debug(f"prefix lookup failed for {asn}: {e}")

    prefixes_list = sorted(all_prefixes)
    write_lines(Path(output_dir) / "asn_prefixes.txt", prefixes_list)

    ok(f"ASN: {len(asn_list)} ASNs, {len(prefixes_list)} prefixes")
    return {"asns": asn_list, "prefixes": prefixes_list}


if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser(description="ASN discovery")
    p.add_argument("-i", "--ips", required=True, help="File with IPs")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = discover_asns(args.ips, args.output)
    print(json.dumps(result, indent=2))