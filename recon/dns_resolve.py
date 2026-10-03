"""
recon/dns_resolve.py
--------------------
DNS resolution, CNAME discovery, permutation.
Uses: dnsx, puredns, dnsgen (all optional).
"""

from pathlib import Path
from typing import List, Dict

from core.logger import get_logger, info, ok, skip
from core.utils import (
    has_tool, read_lines, write_lines, ensure_dir,
    run_command, dedupe
)

log = get_logger("dns_resolve")


def resolve_hosts(input_file: str, output_dir: str) -> List[str]:
    """
    Resolve a list of hostnames via dnsx.
    """
    ensure_dir(output_dir)
    if not has_tool("dnsx"):
        skip("dnsx not installed")
        return []

    subs = read_lines(input_file)
    if not subs:
        return []

    info(f"Resolving {len(subs)} hostnames via dnsx")
    cmd = f"dnsx -l {input_file} -silent -a -resp-only"
    out = run_command(cmd, timeout=600)
    resolved = [ln.strip() for ln in out.splitlines() if ln.strip()]
    resolved = dedupe(resolved)

    out_file = Path(output_dir) / "resolved_ips.txt"
    write_lines(out_file, resolved)
    ok(f"Resolved: {len(resolved)}")
    return resolved


def get_cnames(input_file: str, output_dir: str) -> List[Dict]:
    """
    Get CNAME records for each hostname. Returns list of dicts.
    """
    ensure_dir(output_dir)
    if not has_tool("dnsx"):
        skip("dnsx not installed")
        return []

    info("Fetching CNAME records")
    cmd = f"dnsx -l {input_file} -silent -cname -resp"
    out = run_command(cmd, timeout=600)

    results: List[Dict] = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        # Format: "hostname [CNAME] target"
        parts = ln.split()
        if len(parts) >= 3 and parts[1] == "[CNAME]":
            results.append({"host": parts[0], "cname": parts[2]})
        elif "->" in ln:
            h, c = ln.split("->", 1)
            results.append({"host": h.strip(), "cname": c.strip()})

    out_file = Path(output_dir) / "cname_records.txt"
    lines = [f"{r['host']} -> {r['cname']}" for r in results]
    write_lines(out_file, lines)
    ok(f"CNAME records: {len(results)}")
    return results


def generate_permutations(input_file: str, output_dir: str) -> List[str]:
    """
    Generate DNS permutations via dnsgen (or fallback).
    """
    ensure_dir(output_dir)
    out_file = Path(output_dir) / "permutations.txt"
    subs = read_lines(input_file)

    if has_tool("dnsgen"):
        info("Generating permutations via dnsgen")
        cmd = f"dnsgen {input_file}"
        out = run_command(cmd, timeout=300)
        perm = [ln.strip() for ln in out.splitlines() if ln.strip()]
        perm = dedupe(perm)
        write_lines(out_file, perm)
        ok(f"Permutations: {len(perm)}")
        return perm

    # Fallback: simple permutation
    skip("dnsgen not installed — using fallback permutation")
    words = ["dev", "staging", "test", "api", "admin", "app", "m", "mobile",
             "beta", "demo", "internal", "vpn", "mail", "ftp", "cdn", "static"]
    perm = []
    for s in subs:
        base = s.split(".")[0]
        for w in words:
            perm.append(f"{w}-{base}.{'.'.join(s.split('.')[1:])}")
            perm.append(f"{base}-{w}.{'.'.join(s.split('.')[1:])}")
    perm = dedupe(perm)
    write_lines(out_file, perm)
    ok(f"Fallback permutations: {len(perm)}")
    return perm


def resolve_permutations(perm_file: str, output_dir: str) -> List[str]:
    """
    Resolve permutations via puredns (or dnsx fallback).
    """
    ensure_dir(output_dir)
    if not has_tool("puredns") and not has_tool("dnsx"):
        skip("Neither puredns nor dnsx installed")
        return []

    out_file = Path(output_dir) / "resolved_permutations.txt"

    if has_tool("puredns"):
        info("Resolving permutations via puredns")
        # puredns needs a resolvers file
        resolver = Path(output_dir) / "resolvers.txt"
        if not resolver.exists():
            # Use public resolvers
            write_lines(resolver, [
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "9.9.9.9", "208.67.222.222", "208.67.220.220",
            ])
        cmd = f"puredns resolve {perm_file} -r {resolver} -q --write {out_file}"
        run_command(cmd, timeout=900)
    else:
        info("Resolving permutations via dnsx")
        cmd = f"dnsx -l {perm_file} -silent -a -resp-only"
        out = run_command(cmd, timeout=900)
        resolved = [ln.strip() for ln in out.splitlines() if ln.strip()]
        write_lines(out_file, resolved)

    resolved = read_lines(out_file)
    ok(f"Resolved permutations: {len(resolved)}")
    return resolved


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DNS resolution")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--cname", action="store_true")
    parser.add_argument("--permute", action="store_true")
    args = parser.parse_args()

    if args.cname:
        get_cnames(args.input, args.output)
    elif args.permute:
        generate_permutations(args.input, args.output)
    else:
        resolve_hosts(args.input, args.output)