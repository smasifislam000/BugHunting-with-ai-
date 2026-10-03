"""
scanner/nuclei_runner.py
------------------------
Nuclei wrapper with severity filter, rate limit, deduplication.
Outputs JSONL for structured parsing.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, skip, warn
from core.utils import (
    has_tool, read_lines, write_lines, ensure_dir,
    run_command_stream, save_json
)
from core.config_loader import get_config

log = get_logger("nuclei")
cfg = get_config()


SEVERITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5, "unknown": 6}


def run_nuclei(targets_file: str, output_dir: str,
               severity: Optional[List[str]] = None,
               tags: Optional[List[str]] = None,
               exclude_tags: Optional[List[str]] = None,
               templates: Optional[str] = None,
               rate_limit: Optional[int] = None,
               extra_args: str = "") -> List[Dict]:
    """
    Run nuclei against a file of URLs.
    Returns list of parsed JSON findings.
    """
    ensure_dir(output_dir)

    if not has_tool("nuclei"):
        skip("nuclei not installed")
        return []

    targets = read_lines(targets_file)
    if not targets:
        info("No targets for nuclei")
        return []

    severity = severity or cfg.get("scan_settings.nuclei_severity",
                                   ["critical", "high", "medium"])
    exclude_tags = exclude_tags or cfg.get("scan_settings.nuclei_exclude_tags",
                                           ["fuzz", "dos", "brute-force"])
    rate_limit = rate_limit or cfg.get("scan_settings.nuclei_rate_limit", 70)

    sev_str = ",".join(severity)
    excl_str = ",".join(exclude_tags)

    info(f"Nuclei: {len(targets)} targets, severity={sev_str}, rate={rate_limit}")

    output_jsonl = Path(output_dir) / "nuclei_results.jsonl"
    output_txt = Path(output_dir) / "nuclei_results.txt"

    cmd = (
        f"nuclei -l {targets_file} "
        f"-severity {sev_str} "
        f"-exclude-tags {excl_str} "
        f"-rl {rate_limit} "
        f"-c 25 "
        f"-timeout 5 "
        f"-retries 1 "
        f"-jsonl "
        f"-silent "
        f"-no-color "
        f"-stats "
        f"-stats-interval 30"
    )
    if tags:
        cmd += f" -tags {','.join(tags)}"
    if templates:
        cmd += f" -t {templates}"
    if extra_args:
        cmd += f" {extra_args}"

    findings: List[Dict] = []
    seen = set()
    line_count = 0

    for line in run_command_stream(cmd, timeout=7200):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Dedupe
        key = (
            data.get("template-id", ""),
            data.get("matched-at", ""),
            data.get("matcher-name", ""),
        )
        if key in seen:
            continue
        seen.add(key)

        findings.append({
            "template_id": data.get("template-id", ""),
            "name": data.get("info", {}).get("name", ""),
            "severity": data.get("info", {}).get("severity", "unknown"),
            "url": data.get("matched-at", data.get("host", "")),
            "host": data.get("host", ""),
            "type": data.get("type", ""),
            "matcher": data.get("matcher-name", ""),
            "extracted": data.get("extracted-results", []),
            "description": data.get("info", {}).get("description", ""),
            "reference": data.get("info", {}).get("reference", []),
            "tags": data.get("info", {}).get("tags", []),
            "timestamp": data.get("timestamp", ""),
        })
        line_count += 1

    # Write outputs
    with open(output_jsonl, "w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(json.dumps(fnd) + "\n")

    txt_lines = []
    for fnd in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
        txt_lines.append(f"[{fnd['severity'].upper()}] {fnd['template_id']} → {fnd['url']}")
    write_lines(output_txt, txt_lines)

    ok(f"Nuclei: {len(findings)} findings → {output_txt}")
    return findings


def summarize(findings: List[Dict]) -> Dict[str, int]:
    """Severity summary."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        summary[sev] = summary.get(sev, 0) + 1
    summary["total"] = sum(summary.values())
    return summary


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Nuclei runner")
    parser.add_argument("-l", "--list", required=True, help="targets file")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-s", "--severity", default=None,
                        help="comma-separated severities")
    parser.add_argument("-t", "--tags", default=None)
    args = parser.parse_args()

    sev = args.severity.split(",") if args.severity else None
    tags = args.tags.split(",") if args.tags else None

    findings = run_nuclei(args.list, args.output, severity=sev, tags=tags)
    print(f"\nSummary: {summarize(findings)}")