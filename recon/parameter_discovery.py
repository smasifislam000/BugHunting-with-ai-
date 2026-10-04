"""
recon/parameter_discovery.py
----------------------------
Hidden parameter discovery via arjun and pattern matching.
"""

from pathlib import Path
from typing import List, Dict

from core.logger import get_logger, info, ok, skip, warn
from core.utils import (
    has_tool, read_lines, write_lines, ensure_dir, run_command
)

log = get_logger("parameter_discovery")


def run_arjun(urls_file: str, output_dir: str,
              threads: int = 10,
              timeout_per_url: int = 120) -> List[Dict]:
    ensure_dir(output_dir)

    if not has_tool("arjun"):
        skip("arjun not installed")
        return []

    urls = read_lines(urls_file)
    if not urls:
        info("No URLs for parameter discovery")
        return []

    info(f"arjun: {len(urls[:30])} URLs")

    out_file = Path(output_dir) / "arjun_params.txt"

    cmd = (
        f"arjun -i {urls_file} "
        f"-t {threads} "
        f"-oT {out_file} "
        f"--stable "
    )

    run_command(cmd, timeout=timeout_per_url * min(len(urls), 30))

    findings: List[Dict] = []
    if out_file.exists():
        for line in out_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            # arjun format: URL\n  param1\n  param2
            if line.startswith("http"):
                current_url = line
                continue
            findings.append({
                "type": "hidden_parameter",
                "url": current_url if 'current_url' in dir() else line,
                "param": line.strip(),
                "severity": "info",
                "confidence": 70,
            })

    ok(f"arjun: {len(findings)} hidden parameters found")
    return findings


def grep_params_from_urls(urls_file: str) -> List[str]:
    from urllib.parse import urlparse, parse_qs
    urls = read_lines(urls_file)
    params = set()
    for u in urls:
        try:
            qs = parse_qs(urlparse(u).query)
            for p in qs:
                params.add(p)
        except Exception:
            continue
    return sorted(params)


def scan_parameters(urls_file: str, output_dir: str) -> Dict:
    ensure_dir(output_dir)

    findings: List[Dict] = []

    try:
        findings.extend(run_arjun(urls_file, output_dir))
    except Exception as e:
        log.debug(f"arjun failed: {e}")

    # Always gather known params from URLs
    known = grep_params_from_urls(urls_file)
    if known:
        write_lines(Path(output_dir) / "known_params.txt", known)

    if findings:
        write_lines(Path(output_dir) / "arjun_findings.txt",
                    [f"{f['url']} :: {f['param']}" for f in findings])

    return {"count": len(findings), "findings": findings,
            "known_params": known}


if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser(description="Parameter discovery")
    p.add_argument("-l", "--list", required=True)
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = scan_parameters(args.list, args.output)
    print(json.dumps({"count": result["count"]}, indent=2))