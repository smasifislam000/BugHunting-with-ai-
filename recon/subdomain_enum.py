"""
recon/subdomain_enum.py
-----------------------
Multi-source subdomain enumeration with concurrency.
Sources: subfinder, amass, assetfinder, findomain, chaos, github.
Graceful: skips missing tools, merges all results.
"""

import os
import json
import asyncio
from pathlib import Path
from typing import List, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import get_logger, ok, info, warn, skip
from core.utils import (
    run_command, has_tool, read_lines, write_lines,
    dedupe, ensure_dir, timestamp
)
from core.config_loader import get_config

log = get_logger("subdomain_enum")
cfg = get_config()


# ─────────────────────────────────────────
# Individual Sources
# ─────────────────────────────────────────
def run_subfinder(domain: str, timeout: int = 180) -> List[str]:
    if not has_tool("subfinder"):
        skip("subfinder not installed")
        return []
    info(f"subfinder: enumerating {domain}")
    out = run_command(f"subfinder -d {domain} -all -silent", timeout=timeout)
    subs = [s.strip() for s in out.splitlines() if s.strip()]
    ok(f"subfinder: {len(subs)} subdomains")
    return subs


def run_amass(domain: str, timeout: int = 300) -> List[str]:
    if not has_tool("amass"):
        skip("amass not installed")
        return []
    info(f"amass: passive enum {domain}")
    out = run_command(
        f"amass enum -passive -d {domain} -timeout 5",
        timeout=timeout
    )
    subs = [s.strip() for s in out.splitlines() if s.strip() and "." in s]
    ok(f"amass: {len(subs)} subdomains")
    return subs


def run_assetfinder(domain: str, timeout: int = 120) -> List[str]:
    if not has_tool("assetfinder"):
        skip("assetfinder not installed")
        return []
    info(f"assetfinder: {domain}")
    out = run_command(f"assetfinder --subs-only {domain}", timeout=timeout)
    subs = [s.strip() for s in out.splitlines() if s.strip()]
    ok(f"assetfinder: {len(subs)} subdomains")
    return subs


def run_findomain(domain: str, timeout: int = 180) -> List[str]:
    if not has_tool("findomain"):
        skip("findomain not installed")
        return []
    info(f"findomain: {domain}")
    out = run_command(f"findomain -t {domain} -q", timeout=timeout)
    subs = [s.strip() for s in out.splitlines() if s.strip()]
    ok(f"findomain: {len(subs)} subdomains")
    return subs


def run_chaos(domain: str, timeout: int = 120) -> List[str]:
    """Chaos API - requires chaos key in config."""
    if not has_tool("chaos"):
        skip("chaos client not installed")
        return []
    key = cfg.get("api_keys.chaos", "")
    if not key:
        skip("chaos API key missing")
        return []
    info(f"chaos: {domain}")
    out = run_command(
        f"chaos -d {domain} -key {key} -silent -d {domain}",
        timeout=timeout
    )
    subs = [s.strip() for s in out.splitlines() if s.strip()]
    ok(f"chaos: {len(subs)} subdomains")
    return subs


def run_github_subdomains(domain: str, timeout: int = 180) -> List[str]:
    """GitHub-based subdomain discovery via subfinder's github source."""
    if not has_tool("subfinder"):
        return []
    token = cfg.get("api_keys.github_token", "")
    if not token:
        skip("github token missing (subfinder github source)")
        return []
    info(f"github-subdomains: {domain}")
    env = f"GITHUB_TOKEN={token}"
    out = run_command(
        f"{env} subfinder -d {domain} -sources github -silent",
        timeout=timeout
    )
    subs = [s.strip() for s in out.splitlines() if s.strip()]
    ok(f"github: {len(subs)} subdomains")
    return subs


def run_crtsh(domain: str, timeout: int = 60) -> List[str]:
    """crt.sh certificate transparency (no tool needed)."""
    info(f"crt.sh: {domain}")
    try:
        import requests
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=timeout
        )
        if r.status_code != 200:
            return []
        data = r.json()
        subs: Set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower()
                if n and "*" not in n and domain in n:
                    subs.add(n)
        result = sorted(subs)
        ok(f"crt.sh: {len(result)} subdomains")
        return result
    except Exception as e:
        log.debug(f"crt.sh failed: {e}")
        return []


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def enumerate_subdomains(domain: str, output_dir: str,
                         deep: bool = False,
                         max_workers: int = 6) -> List[str]:
    """
    Run all sources concurrently, merge results.
    Returns deduped sorted list of subdomains.
    """
    info(f"Starting subdomain enumeration for {domain}")
    ensure_dir(output_dir)

    sources = [
        ("subfinder",   run_subfinder),
        ("assetfinder", run_assetfinder),
        ("crtsh",       run_crtsh),
        ("github",      run_github_subdomains),
    ]

    if deep:
        sources += [
            ("amass",     run_amass),
            ("findomain", run_findomain),
            ("chaos",     run_chaos),
        ]

    all_subs: Set[str] = set()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in sources}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results = fut.result(timeout=600)
                all_subs.update(results)
            except Exception as e:
                log.debug(f"source {name} failed: {e}")

    # Normalize + dedupe
    cleaned = []
    for s in all_subs:
        s = s.strip().lower()
        if not s or " " in s:
            continue
        if s.startswith("*."):
            s = s[2:]
        if s.endswith("."):
            s = s[:-1]
        if domain in s:
            cleaned.append(s)

    final = dedupe(cleaned)
    final.sort()

    out_file = Path(output_dir) / "subdomains.txt"
    write_lines(out_file, final)
    ok(f"Total unique subdomains: {len(final)} → {out_file}")

    return final


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Subdomain enumeration")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--deep", action="store_true")
    args = parser.parse_args()

    out = args.output or f"results/{args.domain}/recon"
    subs = enumerate_subdomains(args.domain, out, deep=args.deep)
    print(f"\nTotal: {len(subs)} subdomains → {out}/subdomains.txt")