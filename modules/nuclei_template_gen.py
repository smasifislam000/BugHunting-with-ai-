"""
modules/nuclei_template_gen.py
------------------------------
AI-assisted custom Nuclei template generator.

Given a target's tech stack or a specific bug class, ask AI to write
a YAML Nuclei template that can be used to scan similar targets.

Gracefully handles:
  - No AI key → uses built-in templates only
  - Invalid YAML → validate before saving
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from core.logger import get_logger, info, ok, warn, skip
from core.utils import write_lines, ensure_dir
from core.platform_detect import is_termux
from modules._common import module_dir, load_tech_stack, cli_main

log = get_logger("nuclei_template_gen")


# ─────────────────────────────────────────
# Built-in starter templates
# ─────────────────────────────────────────
BUILTIN_TEMPLATES = {
    "info_disclosure_header": """id: info-disclosure-custom

info:
  name: Information Disclosure - Custom Headers
  author: dream-framework
  severity: low
  description: Detects common information disclosure headers.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)X-Powered-By:.*"
          - "(?i)X-AspNet-Version:.*"
          - "(?i)X-Generator:.*"
""",

    "graphql_introspection": """id: graphql-introspection-custom

info:
  name: GraphQL Introspection Enabled
  author: dream-framework
  severity: medium
  description: Detects exposed GraphQL introspection.

requests:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
    headers:
      Content-Type: application/json
    body: '{"query":"{__schema{types{name}}}"}'
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "__schema"
      - type: status
        status:
          - 200
""",

    "actuator_exposed": """id: spring-actuator-custom

info:
  name: Spring Boot Actuator Exposed
  author: dream-framework
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/health"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - '"activeProfiles"'
          - '"propertySources"'
      - type: status
        status:
          - 200
""",
}


# ─────────────────────────────────────────
# YAML validation
# ─────────────────────────────────────────
def _is_valid_yaml(text: str) -> bool:
    try:
        import yaml
        yaml.safe_load(text)
        return True
    except Exception:
        return False


def _extract_yaml_from_ai_response(text: str) -> Optional[str]:
    """
    AI may return text with explanation; extract the YAML block.
    """
    if not text:
        return None
    # Try fenced code block
    m = re.search(r"```(?:yaml)?\s*(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Try to find 'id:' first line
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("id:"):
            start = i
            break
    if start is not None:
        return "\n".join(lines[start:]).strip()
    return None


# ─────────────────────────────────────────
# AI-driven template generation
# ─────────────────────────────────────────
def ai_generate_template(vuln_description: str,
                         tech_stack: Optional[List[str]] = None) -> Optional[str]:
    """
    Ask AI to write a Nuclei YAML template.
    """
    try:
        from core.auto_fallback import ai_ask
    except Exception:
        return None

    if is_termux():
        skip("Nuclei template gen skipped on Termux (needs AI)")
        return None

    system = (
        "You are an expert Nuclei template author. "
        "Respond ONLY with valid Nuclei YAML. No explanation."
    )
    prompt = f"""
Write a valid Nuclei v3 YAML template for the following vulnerability:

{vuln_description}

Target tech stack (if relevant): {', '.join(tech_stack or ['any'])}

Requirements:
  - Include 'id', 'info' (name, author, severity, description)
  - Include at least one 'requests' block
  - Use {{BaseURL}} as target placeholder
  - Include matchers (word/regex/status)
  - Output ONLY the YAML, no code fences.

Template:
"""
    result = ai_ask(prompt, system=system, json_mode=False)
    if not result:
        return None
    text = result.get("result", {}).get("text") or ""
    yaml_text = _extract_yaml_from_ai_response(text)
    if yaml_text and _is_valid_yaml(yaml_text):
        return yaml_text
    return None


# ─────────────────────────────────────────
# Save templates
# ─────────────────────────────────────────
def save_builtin_templates(output_dir: Path) -> List[str]:
    saved: List[str] = []
    for name, yaml in BUILTIN_TEMPLATES.items():
        path = output_dir / f"custom_{name}.yaml"
        try:
            path.write_text(yaml, encoding="utf-8")
            saved.append(str(path))
        except Exception as e:
            warn(f"could not save {name}: {e}")
    return saved


# ─────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────
def run(domain: str, output_root: str = "results",
        scan_id: Optional[int] = None,
        vuln_description: Optional[str] = None) -> Dict:
    mdir = module_dir(domain, "nuclei_template_gen", output_root)
    tpl_dir = mdir / "templates"
    ensure_dir(tpl_dir)

    # 1) Always save built-in templates
    builtin = save_builtin_templates(tpl_dir)
    ok(f"Built-in templates saved: {len(builtin)}")

    result: Dict = {
        "builtin_count": len(builtin),
        "ai_generated": [],
        "ai_count": 0,
        "output_dir": str(tpl_dir),
    }

    # 2) AI generation (optional)
    tech = load_tech_stack(domain, output_root).get("unique_tech", [])

    if vuln_description:
        desc = vuln_description
    elif tech:
        # Ask AI to generate a template based on tech stack
        desc = (
            f"Detect common misconfigurations and known CVEs for this tech stack: "
            f"{', '.join(tech[:10])}"
        )
    else:
        desc = None

    if desc:
        yaml = ai_generate_template(desc, tech)
        if yaml:
            name = re.sub(r"[^a-z0-9_-]", "_", desc.lower())[:60]
            path = tpl_dir / f"ai_{name}.yaml"
            try:
                path.write_text(yaml, encoding="utf-8")
                result["ai_generated"].append(str(path))
                result["ai_count"] = 1
                ok(f"AI template saved: {path}")
            except Exception as e:
                warn(f"Could not save AI template: {e}")
        else:
            info("AI template generation unavailable (no AI key or invalid response)")

    return {
        "count": result["builtin_count"] + result["ai_count"],
        "findings": [],
        **result,
    }


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Nuclei template generator")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="results")
    p.add_argument("--description", help="Custom vulnerability description")
    args = p.parse_args()

    cli_main(
        args.target, "nuclei_template_gen",
        lambda domain, output_root: run(domain, output_root,
                                        vuln_description=args.description),
        args.output
    )