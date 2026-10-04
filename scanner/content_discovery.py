"""
scanner/content_discovery.py
----------------------------
Directory/file brute force via ffuf or dirsearch.
Uses wordlists from wordlists/ directory.
"""

from pathlib import Path
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, skip, warn
from core.utils import (
    has_tool, read_lines, write_lines, ensure_dir, run_command, run_command_stream
)
from core.config_loader import get_config

log = get_logger("content_discovery")
cfg = get_config()


DEFAULT_WORDLISTS = [
    "wordlists/common.txt",
    "wordlists/api_endpoints.txt",
    "wordlists/sensitive_paths.txt",
]


def _pick_wordlist() -> Optional[str]:
    for wl in DEFAULT_WORDLISTS:
        p = Path(wl)
        if p.exists() and p.stat().st_size > 0:
            return str(p)
    return None


def run_ffuf(target_url: str, output_dir: str,
             wordlist: Optional[str] = None,
             extensions: str = "php,html,txt,json,xml,bak",
             timeout: int = 900) -> List[Dict]:
    ensure_dir(output_dir)

    if not has_tool("ffuf"):
        skip("ffuf not installed")
        return []

    wl = wordlist or _pick_wordlist()
    if not wl:
        warn("No wordlist found in wordlists/")
        return []

    url = target_url.rstrip("/") + "/FUZZ"

    info(f"ffuf: {url} with {wl}")

    output_file = Path(output_dir) / "ffuf_results.json"

    cmd = (
        f"ffuf -u \"{url}\" "
        f"-w {wl} "
        f"-mc 200,204,301,302,307,401,403 "
        f"-fc 404 "
        f"-t 40 "
        f"-timeout 10 "
        f"-of json "
        f"-o {output_file} "
        f"-s "
    )
    if extensions:
        cmd += f"-e .{extensions.replace(',', ',.')} "

    run_command(cmd, timeout=timeout)

    findings: List[Dict] = []
    if output_file.exists():
        try:
            import json
            data = json.loads(output_file.read_text(encoding="utf-8"))
            results = data.get("results", [])
            for r in results:
                findings.append({
                    "type": "content_discovery",
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "severity": "info",
                    "confidence": 60,
                })
        except Exception as e:
            log.debug(f"ffuf parse failed: {e}")

    ok(f"ffuf: {len(findings)} paths found")
    return findings


def run_dirsearch(target_url: str, output_dir: str,
                  wordlist: Optional[str] = None,
                  timeout: int = 900) -> List[Dict]:
    ensure_dir(output_dir)

    if not has_tool("dirsearch"):
        skip("dirsearch not installed")
        return []

    wl = wordlist or _pick_wordlist()
    if not wl:
        return []

    info(f"dirsearch: {target_url}")

    report_dir = Path(output_dir) / "dirsearch_report"
    ensure_dir(report_dir)

    cmd = (
        f"dirsearch -u {target_url} "
        f"-w {wl} "
        f"-e php,html,txt,json,xml,bak "
        f"-t 30 "
        f"-q "
        f"--format=simple "
        f"--output={report_dir}/report.txt "
    )
    run_command(cmd, timeout=timeout)

    findings: List[Dict] = []
    report = report_dir / "report.txt"
    if report.exists():
        for line in report.read_text(errors="ignore").splitlines():
            line = line.strip()
            if "200" in line or "301" in line or "302" in line:
                findings.append({
                    "type": "content_discovery",
                    "url": line.split()[0] if line.split() else line,
                    "severity": "info",
                    "confidence": 50,
                })

    ok(f"dirsearch: {len(findings)} paths found")
    return findings


def scan_content(target_url: str, output_dir: str) -> Dict:
    findings: List[Dict] = []

    try:
        findings.extend(run_ffuf(target_url, output_dir))
    except Exception as e:
        log.debug(f"ffuf failed: {e}")

    if not findings:
        try:
            findings.extend(run_dirsearch(target_url, output_dir))
        except Exception as e:
            log.debug(f"dirsearch failed: {e}")

    if findings:
        write_lines(Path(output_dir) / "content_discovery_findings.txt",
                    [f"{f['url']}" for f in findings])

    return {"count": len(findings), "findings": findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Content discovery scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    result = scan_content(args.target, args.output)
    print(f"\nContent discovery findings: {result['count']}")