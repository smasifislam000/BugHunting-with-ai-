"""
scanner/sqli_scanner.py
-----------------------
SQL injection scanning via sqlmap.
IMPORTANT: Only runs on filtered, high-confidence targets.
Uses --batch mode, no interactive prompts.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, skip, warn
from core.utils import (
    has_tool, read_lines, write_lines, ensure_dir, run_command
)
from core.config_loader import get_config

log = get_logger("sqli")
cfg = get_config()


SQLI_HINTS = re.compile(
    r"(id|uid|pid|cid|user|account|profile|item|product|order|"
    r"cat|category|page|post|article|news|view|file|doc|"
    r"sel|select|query|search|q|kw|keyword)=",
    re.IGNORECASE
)


def filter_sqli_candidates(urls: List[str], max_urls: int = 150) -> List[str]:
    candidates = [u for u in urls if SQLI_HINTS.search(u)]
    seen = set()
    out = []
    for u in candidates:
        sig = u.split("?")[0]
        if sig not in seen:
            seen.add(sig)
            out.append(u)
        if len(out) >= max_urls:
            break
    return out


def run_sqlmap(urls_file: str, output_dir: str,
               level: int = 2, risk: int = 1,
               threads: int = 5,
               max_urls: int = 150,
               timeout_per_url: int = 300) -> List[Dict]:
    ensure_dir(output_dir)

    if not has_tool("sqlmap"):
        skip("sqlmap not installed")
        return []

    all_urls = read_lines(urls_file)
    if not all_urls:
        info("No URLs for SQLi scan")
        return []

    candidates = filter_sqli_candidates(all_urls, max_urls=max_urls)
    if not candidates:
        info("No SQLi-suspicious URLs after filtering")
        return []

    info(f"SQLi: filtered {len(all_urls)} -> {len(candidates)} candidates")

    filtered_file = Path(output_dir) / "sqli_candidates.txt"
    write_lines(filtered_file, candidates)

    sqlmap_out = Path(output_dir) / "sqlmap_output"
    ensure_dir(sqlmap_out)

    findings: List[Dict] = []

    cmd = (
        f"sqlmap -m {filtered_file} "
        f"--batch "
        f"--random-agent "
        f"--level={level} "
        f"--risk={risk} "
        f"--threads={threads} "
        f"--timeout=10 "
        f"--retries=1 "
        f"--output-dir={sqlmap_out} "
        f"--flush-session "
        f"--disable-coloring"
    )

    info("Running sqlmap (this can take a while)...")
    out = run_command(cmd, timeout=timeout_per_url * len(candidates))

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            findings.append({
                "type": "sqli",
                "raw": line,
                "url": _extract_url(line),
                "dbms": _extract_dbms(line),
            })

    log_file = Path(output_dir) / "sqli_results.txt"
    write_lines(log_file, [f["raw"] for f in findings])

    if findings:
        warn(f"SQLi: {len(findings)} potential injection points found")
    else:
        ok("SQLi: no confirmed injections")
    return findings


def _extract_url(line: str) -> str:
    m = re.search(r"(https?://[^\s]+)", line)
    return m.group(1) if m else ""


def _extract_dbms(line: str) -> str:
    m = re.search(r"(MySQL|PostgreSQL|Microsoft SQL Server|Oracle|SQLite|MariaDB)",
                  line, re.IGNORECASE)
    return m.group(1) if m else ""


def scan_sqli(urls_file: str, output_dir: str) -> Dict:
    findings = run_sqlmap(urls_file, output_dir)
    return {"findings": findings, "count": len(findings)}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="SQLi scanner")
    p.add_argument("-l", "--list", required=True)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--level", type=int, default=2)
    p.add_argument("--risk", type=int, default=1)
    args = p.parse_args()

    findings = run_sqlmap(args.list, args.output,
                          level=args.level, risk=args.risk)
    print(f"\nSQLi findings: {len(findings)}")