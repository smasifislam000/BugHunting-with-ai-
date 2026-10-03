"""
recon/live_hosts.py
-------------------
Detect live hosts + HTTP metadata via httpx.
Outputs: live_hosts.txt (urls), live_hosts.json (full metadata).
"""

import json
from pathlib import Path
from typing import List, Dict

from core.logger import get_logger, info, ok, skip
from core.utils import (
    run_command, has_tool, read_lines, write_lines,
    ensure_dir, save_json, run_command_stream
)
from core.config_loader import get_config

log = get_logger("live_hosts")
cfg = get_config()


def detect_live_hosts(subdomains_file: str, output_dir: str,
                      threads: int = None,
                      timeout: int = None) -> Dict:
    """
    Run httpx on subdomain list.
    Returns dict with 'urls' (list) and 'meta' (list of dicts).
    """
    ensure_dir(output_dir)

    if not has_tool("httpx"):
        skip("httpx not installed — live host detection skipped")
        return {"urls": [], "meta": []}

    subs = read_lines(subdomains_file)
    if not subs:
        info("No subdomains to scan")
        return {"urls": [], "meta": []}

    threads = threads or cfg.get("scan_settings.httpx_threads", 50)
    timeout = timeout or cfg.get("scan_settings.request_timeout", 10)
    ua = cfg.get("scan_settings.user_agent", "")

    info(f"Running httpx on {len(subs)} subdomains")

    # Build command
    input_file = Path(output_dir) / "_httpx_input.txt"
    write_lines(input_file, subs)

    cmd = (
        f"httpx -l {input_file} "
        f"-threads {threads} "
        f"-timeout {timeout} "
        f"-json "
        f"-silent "
        f"-no-color "
        f"-status-code "
        f"-title "
        f"-tech-detect "
        f"-follow-redirects "
        f"-random-agent"
    )
    if ua:
        cmd += f' -H "User-Agent: {ua}"'

    urls: List[str] = []
    meta: List[Dict] = []

    for line in run_command_stream(cmd, timeout=1800):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # Sometimes httpx emits plain urls
            if line.startswith(("http://", "https://")):
                urls.append(line)
            continue

        url = data.get("url") or data.get("input", "")
        if not url:
            continue

        urls.append(url)
        meta.append({
            "url": url,
            "host": data.get("host", ""),
            "status_code": data.get("status_code", 0),
            "title": data.get("title", ""),
            "tech": data.get("tech", []),
            "content_length": data.get("content_length", 0),
            "webserver": data.get("webserver", ""),
            "cname": data.get("cname", []),
            "cdn": data.get("cdn", False),
            "cdn_name": data.get("cdn_name", ""),
            "tls": data.get("tls", {}),
        })

    urls = sorted(set(urls))

    # Write outputs
    urls_file = Path(output_dir) / "live_hosts.txt"
    write_lines(urls_file, urls)
    save_json(Path(output_dir) / "live_hosts.json", meta)

    ok(f"Live hosts: {len(urls)} → {urls_file}")
    return {"urls": urls, "meta": meta}


def filter_by_status(meta: List[Dict], statuses: List[int]) -> List[Dict]:
    """Keep only hosts with given status codes."""
    return [m for m in meta if m.get("status_code") in statuses]


def filter_by_tech(meta: List[Dict], keyword: str) -> List[Dict]:
    """Keep only hosts with tech matching keyword (case-insensitive)."""
    kw = keyword.lower()
    return [m for m in meta if any(kw in str(t).lower() for t in m.get("tech", []))]


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Live host detection")
    parser.add_argument("-i", "--input", required=True, help="subdomains.txt")
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    result = detect_live_hosts(args.input, args.output)
    print(f"\nLive: {len(result['urls'])}")