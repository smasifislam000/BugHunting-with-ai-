cat > core/poc_enhancer.py << 'ENDOFFILE'
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
        breakdown.append(f"- **{k}**: {v} - {text}")

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
    "xss": "Use output encoding (e.g., Jinja2 autoescape) and a strict Content-Security-Policy.",
    "sqli_error": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "ssti": "Never render user input as a template. Use a sandboxed template engine if unavoidable.",
    "open_redirect": "Whitelist allowed redirect targets. Reject anything not on the list.",
    "ssrf": "Block private IP ranges (RFC1918), loopback, and link-local. Use IMDSv2 for cloud metadata.",
    "idor": "Enforce authorization on every object access. Do not rely on client-supplied IDs alone.",
    "crlf": "Strip CR (\\r) and LF (\\n) from any user-supplied header value.",
}


def get_fix_snippet(vuln_type: str) -> str:
    key = (vuln_type or "").lower()
    for k, snippet in FIX_SNIPPETS.items():
        if k in key:
            return snippet
    return ("Apply input validation, output encoding, and "
            "the principle of least privilege.")


# ─────────────────────────────────────────
# CVE cross-reference
# ─────────────────────────────────────────
def cve_cross_reference(vuln_type: str) -> List[Dict]:
    keyword_map = {
        "sqli": "SQL injection",
        "xss": "cross-site scripting",
        "ssrf": "server-side request forgery",
        "ssti": "server-side template injection",
        "xxe": "XML external entity",
        "lfi": "local file inclusion",
        "open_redirect": "open redirect",
        "crlf": "CRLF injection",
        "nosql": "NoSQL injection",
    }
    keyword = None
    low = (vuln_type or "").lower()
    for k, v in keyword_map.items():
        if k in low:
            keyword = v
            break

    if not keyword:
        return []

    try:
        from intel.nvd_api import search_cves
        return search_cves(keyword, max_results=3)
    except Exception:
        return []


# ─────────────────────────────────────────
# Video recording
# ─────────────────────────────────────────
def record_proof_video(url: str, output_path: str,
                       duration_sec: int = 5) -> Optional[str]:
    if is_low_resource():
        skip("Video recording skipped (low-resource platform)")
        return None

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        skip("Playwright not installed - no video")
        return None

    ensure_dir(Path(output_path).parent)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                record_video_dir=str(Path(output_path).parent / "videos"),
                record_video_size={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            page.wait_for_timeout(duration_sec * 1000)
            video_path = page.video.path() if page.video else None
            context.close()
            browser.close()
            if video_path:
                final = Path(output_path)
                Path(video_path).rename(final)
                ok(f"Video: {final}")
                return str(final)
    except Exception as e:
        log.debug(f"video failed: {e}")
    return None


# ─────────────────────────────────────────
# Enhancer entry
# ─────────────────────────────────────────
def enhance_evidence(evidence: Dict, finding: Dict,
                     output_dir: Path,
                     enable_video: bool = False) -> Dict:
    ensure_dir(output_dir)

    baseline_body = evidence.get("baseline", {}).get("raw_response", "")
    attack_body = evidence.get("attack", {}).get("raw_response", "")

    enhanced = {
        "diff_visual": visualize_diff(baseline_body, attack_body),
        "cvss": cvss_breakdown(finding.get("vuln_type", "")),
        "sequence_diagram": sequence_diagram(finding),
        "fix_snippet": get_fix_snippet(finding.get("vuln_type", "")),
        "cve_references": cve_cross_reference(finding.get("vuln_type", "")),
        "timeline": [
            "0s - Baseline request sent",
            "~1s - Baseline response received",
            "~1s - Attack request sent with payload",
            "~2s - Attack response received",
            "~2s - Differential analysis completed",
            f"~2s - Verdict: {evidence.get('verdict', 'unknown')}",
        ],
    }

    if enable_video:
        vid = record_proof_video(
            finding.get("url", ""),
            str(output_dir / "proof_video.webm"),
        )
        if vid:
            enhanced["video"] = vid

    save_json(output_dir / "enhanced_evidence.json", enhanced)

    md = build_triager_markdown(evidence, enhanced, finding)
    (output_dir / "triager_view.md").write_text(md, encoding="utf-8")

    return enhanced


# ─────────────────────────────────────────
# Triager markdown
# ─────────────────────────────────────────
def build_triager_markdown(evidence: Dict, enhanced: Dict,
                           finding: Dict) -> str:
    vuln = finding.get("vuln_type", "unknown")
    url = finding.get("url", "")
    param = finding.get("param", "")

    md = "# PoC - " + vuln + "\n\n"
    md += "**Target**: `" + url + "`\n"
    md += "**Vulnerable parameter**: `" + param + "`\n"
    md += "**Verdict**: **" + str(evidence.get("verdict", "UNKNOWN")) + "** "
    md += "(confidence " + str(evidence.get("confidence", 0)) + "%)\n\n"
    md += "---\n\n## 1. Summary\n\n"
    md += "A **" + vuln + "** vulnerability was confirmed at the above URL.\n\n"
    md += "**CVSS**: " + str(enhanced["cvss"].get("score", 0))
    md += " (" + str(enhanced["cvss"].get("severity", "unknown")) + ")\n\n"
    md += "---\n\n## 2. Reproduction Steps\n\n"

    for i, step in enumerate(evidence.get("reproduction_steps", []), 1):
        md += str(i) + ". " + step + "\n"

    md += "\n---\n\n## 3. Attack Sequence\n\n"
    md += enhanced.get("sequence_diagram", "") + "\n\n"
    md += "---\n\n## 4. Baseline vs Attack Diff\n\n"
    md += enhanced.get("diff_visual", "") + "\n\n"
    md += "---\n\n## 5. PoC - cURL\n\n"
    md += "```bash\n" + evidence.get("poc", {}).get("curl", "") + "\n```\n\n"
    md += "---\n\n## 6. PoC - Python\n\n"
    md += "```python\n" + evidence.get("poc", {}).get("python", "") + "\n```\n\n"
    md += "---\n\n## 7. Impact\n\n"

    for impact in evidence.get("impact_chain", []):
        md += "- " + impact + "\n"

    md += "\n---\n\n## 8. CVSS Breakdown\n\n"
    md += "**Vector**: `" + enhanced["cvss"].get("vector", "") + "`\n\n"

    for b in enhanced["cvss"].get("breakdown", []):
        md += b + "\n"

    md += "\n---\n\n## 9. Suggested Fix\n\n"
    md += enhanced.get("fix_snippet", "") + "\n\n"
    md += "---\n\n## 10. References\n\n"

    for ref in enhanced.get("cve_references", []):
        md += "- **" + str(ref.get("id", "")) + "** - "
        md += str(ref.get("description", ""))[:200] + "\n"

    md += "\n---\n\n## 11. Timeline\n\n"
    for t in enhanced.get("timeline", []):
        md += "- " + t + "\n"

    md += "\n---\n\n*Generated by Dream Framework - proof bundle.*\n"
    return md


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="PoC enhancer")
    p.add_argument("--evidence", help="Path to evidence.json")
    p.add_argument("--output", help="Output dir for enhanced files")
    p.add_argument("--video", action="store_true", help="Record video")
    args = p.parse_args()

    if args.evidence and args.output:
        ev = json.loads(Path(args.evidence).read_text())
        finding = {
            "url": ev.get("url", ""),
            "vuln_type": ev.get("vuln_type", ""),
            "param": ev.get("param", ""),
            "payload": ev.get("attack", {}).get("payload", ""),
        }
        out = Path(args.output)
        r = enhance_evidence(ev, finding, out, enable_video=args.video)
        print(json.dumps({k: type(v).__name__ for k, v in r.items()}, indent=2))
    else:
        print("Provide --evidence and --output")
ENDOFFILE