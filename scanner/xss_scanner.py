"""
scanner/xss_scanner.py
----------------------
XSS scanning via dalfox (primary) + kxss (reflection check).
Supports: reflected, stored, DOM-based, blind.
"""

from pathlib import Path
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, skip
from core.utils import (
    has_tool, read_lines, write_lines, ensure_dir, run_command_stream
)
from core.config_loader import get_config

log = get_logger("xss")
cfg = get_config()


def run_dalfox(urls_file: str, output_dir: str,
               mode: str = "reflected",
               extra_args: str = "") -> List[Dict]:
    """
    Run dalfox on URL list.
    Modes: reflected | stored | dom | blind
    """
    ensure_dir(output_dir)

    if not has_tool("dalfox"):
        skip("dalfox not installed")
        return []

    urls = read_lines(urls_file)
    if not urls:
        info("No URLs for XSS scan")
        return []

    info(f"Dalfox [{mode}]: {len(urls)} URLs")

    output_file = Path(output_dir) / f"xss_{mode}_results.txt"

    cmd = f"dalfox file {urls_file} --silence --no-color"
    if mode == "reflected":
        cmd += " --mass"
    elif mode == "stored":
        cmd += " --stored"
    elif mode == "dom":
        cmd += " --mining-dom"
    elif mode == "blind":
        cmd += " --blind"
    if extra_args:
        cmd += f" {extra_args}"

    findings: List[Dict] = []
    lines: List[str] = []

    for line in run_command_stream(cmd, timeout=3600):
        line = line.strip()
        if not line or line.startswith("[") and "INFO" in line:
            continue
        lines.append(line)

        # Dalfox output format: [POC][METHOD] or [VULN] ...
        if "POC" in line or "VULN" in line or "XSS" in line.upper():
            findings.append({
                "type": "xss",
                "mode": mode,
                "raw": line,
                "url": _extract_url(line),
                "payload": _extract_payload(line),
            })

    write_lines(output_file, lines)
    ok(f"Dalfox [{mode}]: {len(findings)} potential XSS → {output_file}")
    return findings


def run_kxss(urls_file: str, output_dir: str) -> List[Dict]:
    """
    Kxss reflection check.
    """
    ensure_dir(output_dir)

    if not has_tool("kxss"):
        skip("kxss not installed")
        return []

    urls = read_lines(urls_file)
    if not urls:
        return []

    info(f"Kxss: {len(urls)} URLs")

    cmd = f"cat {urls_file} | kxss"
    out = "".join(run_command_stream(cmd, timeout=900))

    reflections: List[Dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        reflections.append({
            "type": "xss_reflection",
            "raw": line,
            "url": _extract_url(line),
            "params": _extract_kxss_params(line),
        })

    output_file = Path(output_dir) / "kxss_reflections.txt"
    write_lines(output_file, [r["raw"] for r in reflections])
    ok(f"Kxss: {len(reflections)} reflections → {output_file}")
    return reflections


def _extract_url(line: str) -> str:
    """Best-effort URL extraction from dalfox/kxss output."""
    for token in line.split():
        if token.startswith(("http://", "https://")):
            return token
    return ""


def _extract_payload(line: str) -> str:
    """Extract quoted payload if present."""
    import re
    m = re.search(r"\[(?:POC|VULN)\]\s*(.+)", line, re.IGNORECASE)
    if m:
        return m.group(1).strip()[:300]
    return ""


def _extract_kxss_params(line: str) -> List[str]:
    """Kxss format: URL param: ..."""
    import re
    return re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)=", line)


def scan_xss(urls_file: str, output_dir: str,
             modes: Optional[List[str]] = None) -> Dict:
    """
    Run all requested XSS modes.
    """
    modes = modes or ["reflected"]
    all_findings: List[Dict] = []

    for mode in modes:
        try:
            all_findings.extend(run_dalfox(urls_file, output_dir, mode=mode))
        except Exception as e:
            log.debug(f"dalfox {mode} failed: {e}")

    try:
        all_findings.extend(run_kxss(urls_file, output_dir))
    except Exception as e:
        log.debug(f"kxss failed: {e}")

    return {
        "findings": all_findings,
        "count": len(all_findings),
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="XSS scanner")
    parser.add_argument("-l", "--list", required=True, help="URLs file")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-m", "--modes", default="reflected",
                        help="comma-separated: reflected,stored,dom,blind")
    args = parser.parse_args()

    modes = [m.strip() for m in args.modes.split(",")]
    result = scan_xss(args.list, args.output, modes=modes)
    print(f"\nXSS findings: {result['count']}")