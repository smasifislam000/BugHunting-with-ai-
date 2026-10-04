"""
core/poc_enhancer.py
--------------------
Enhances PoC for triager acceptance.

Adds:
  - Before/After diff visualization
  - Impact sequence diagram (text)
  - CVSS score breakdown
  - Suggested fix snippet
  - Video recording (Playwright)
  - Timeline of reproduction
  - Cross-reference with public CVEs
"""

import json
import time
import difflib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from core.logger import get_logger, info, ok, warn, skip
from core.utils import save_json, ensure_dir
from core.platform_detect import is_low_resource

log = get_logger("poc_enhancer")


# ─────────────────────────────────────────
# Diff visualizer
# ─────────────────────────────────────────
def visualize_diff(baseline: str, attack: str, max_lines: int = 60) -> str:
    bl = baseline.splitlines()[:max_lines]
    al = attack.splitlines()[:max_lines]
    out = []
    out.append("```diff")
    out.append("--- BASELINE (safe request)")
    out.append("+++ ATTACK (with payload)")
    out.append("")
    for line in difflib.unified_diff(bl, al, lineterm="",
                                     fromfile="baseline", tofile="attack"):
        out.append(line)
    out.append("```")
    return "\n".join(out)


# ─────────────────────────────────────────
# CVSS breakdown
# ─────────────────────────────────────────
def cvss_breakdown(vuln_type: str) -> Dict:
    try:
        from reporting.cvss_calculator import cvss_for
        cvss = cvss_for(vuln_type)
    except Exception:
        return {}

    vector = cvss.get("vector", "")
    parts = {}
    if vector:
        for segment in vector.replace("CVSS:3.1/", "").split("/"):
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k] = v

    explain = {
        "AV": {"N": "Network (remotely exploitable)",
               "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low (easy to exploit)", "H": "High (complex)"},
        "PR": {"N": "No privileges required",
               "L": "Low privileges", "H": "High privileges"},
        "UI": {"N": "No user interaction",
               "R": "User interaction required"},
        "S":  {"U": "Unchanged scope", "C": "Changed scope"},
        "C":  {"H": "High confidentiality impact",
               "L": "Low", "N": "None"},
        "I":  {"H": "High integrity impact",
               "L": "Low", "N": "None"},
        "A":  {"H": "High availability impact",
               "L": "Low", "N": "None"},
    }

    breakdown = []
    for k, v in parts.items():
        text = explain.get(k, {}).get(v, v)
        breakdown.append(f"- **{k}**: {v} — {text}")

    return {
        "score": cvss.get("score", 0),
        "severity": cvss.get("severity", "unknown"),
        "vector": vector,
        "breakdown": breakdown,
    }


# ─────────────────────────────────────────
# Sequence diagram
# ─────────────────────────────────────────
def sequence_diagram(finding: Dict) -> str:
    url = finding.get("url", "")
    param = finding.get("param", "")
    payload = finding.get("payload", "")
    vuln = finding.get("vuln_type", "")

    diagram = [
        "```",
        "  ATTACKER                  SERVER                  VICTIM",
        "     |                         |                       |",
        "     |--- 1. Craft payload --> |                       |",
        f"     |     (param={param})     |                       |",
        "     |                         |                       |",
        "     |--- 2. Send request ---> |                       |",
        f"     |     {payload[:30]:30s} |                       |",
        "     |                         |                       |",
        f"     |                         |--- 3. {vuln} ----->   |",
        "     |                         |                       |",
        "     | <--- 4. Response with ---|                       |",
        "     |      reflected impact   |                       |",
        "     |                         |                       |",
        "     |--- 5. Exploit --------  |---- 6. Impact ------> |",
        "     |                         |                       |",
        "```",
    ]
    return "\n".join(diagram)


# ─────────────────────────────────────────
# Fix snippets
# ─────────────────────────────────────────
FIX_SNIPPETS = {
    "xss": """```python
# Python (Jinja2) — use autoescape
from markupsafe import escape
return render_template("page.html", user_input=escape(user_input))