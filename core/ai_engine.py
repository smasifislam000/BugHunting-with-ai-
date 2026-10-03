"""
core/ai_engine.py
-----------------
Optional internal AI engine.
This is ONLY used when the AI CLI (Claude Code / CommandCode) is NOT driving
the framework directly. If AI CLI is driving, it makes its own calls.

Auto-detects: CommandCode → DeepSeek → OpenAI → Anthropic → skip
If no key available: returns None (never crashes).
"""

import os
import json
import time
from typing import Dict, List, Optional, Any

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config
from core.utils import safe_request

log = get_logger("ai_engine")
cfg = get_config()


# ─────────────────────────────────────────
# Provider registry
# ─────────────────────────────────────────
PROVIDERS = {
    "commandcode": {
        "base_url": "https://api.commandcode.ai/provider/v1",
        "path": "/chat/completions",
        "default_model": "command-r-plus",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "path": "/chat/completions",
        "default_model": "deepseek-chat",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "path": "/chat/completions",
        "default_model": "gpt-4o-mini",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "path": "/messages",
        "default_model": "claude-3-5-sonnet-20241022",
        "auth_header": "x-api-key",
        "auth_prefix": "",
    },
}


# ─────────────────────────────────────────
# Provider discovery
# ─────────────────────────────────────────
def get_active_provider() -> Optional[Dict]:
    """
    Find first provider with a non-empty key.
    Returns dict with config, or None if no provider available.
    """
    internal = cfg.get("ai_driver.internal_ai_optional", {}) or {}
    if not internal.get("enabled", False):
        return None

    providers = internal.get("providers", {}) or {}
    for name in ["commandcode", "deepseek", "openai", "anthropic"]:
        pc = providers.get(name) or {}
        key = (pc.get("api_key") or "").strip()
        if not key:
            continue
        meta = PROVIDERS.get(name, {})
        return {
            "name": name,
            "api_key": key,
            "base_url": pc.get("base_url") or meta.get("base_url", ""),
            "path": meta.get("path", "/chat/completions"),
            "model": pc.get("model") or meta.get("default_model", ""),
            "auth_header": meta.get("auth_header", "Authorization"),
            "auth_prefix": meta.get("auth_prefix", "Bearer"),
        }
    return None


def is_ai_available() -> bool:
    return get_active_provider() is not None


# ─────────────────────────────────────────
# Main call
# ─────────────────────────────────────────
def ask_ai(prompt: str,
           system: str = "You are an expert bug bounty hunter. Respond with JSON only.",
           json_mode: bool = True,
           timeout: int = 60,
           max_retries: int = 2) -> Optional[Dict]:
    """
    Send a prompt to the active AI provider.
    Returns parsed dict (if json_mode) or {"text": "..."}.
    Returns None if no provider or on error.
    """
    provider = get_active_provider()
    if not provider:
        return None

    url = provider["base_url"].rstrip("/") + provider["path"]
    headers = {"Content-Type": "application/json"}
    key = provider["api_key"]
    if provider["auth_prefix"]:
        headers[provider["auth_header"]] = f"{provider['auth_prefix']} {key}"
    else:
        headers[provider["auth_header"]] = key

    # Anthropic different payload
    if provider["name"] == "anthropic":
        payload = {
            "model": provider["model"],
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
    else:
        payload = {
            "model": provider["model"],
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

    for attempt in range(max_retries + 1):
        r = safe_request(url, method="POST", headers=headers,
                         json=payload, timeout=timeout)
        if r is None:
            time.sleep(1 + attempt)
            continue
        if r.status_code != 200:
            log.debug(f"AI HTTP {r.status_code}: {r.text[:300]}")
            if r.status_code in (429, 500, 502, 503):
                time.sleep(2 + attempt * 2)
                continue
            return None

        try:
            data = r.json()
        except Exception:
            return None

        # Extract content
        text = ""
        if provider["name"] == "anthropic":
            content = data.get("content", [])
            if content and isinstance(content, list):
                text = content[0].get("text", "")
        else:
            choices = data.get("choices", [])
            if choices:
                text = choices[0].get("message", {}).get("content", "")

        if not text:
            return None

        if json_mode:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                # Best-effort extraction
                start = text.find("{")
                end = text.rfind("}")
                if start != -1 and end != -1:
                    try:
                        return json.loads(text[start:end + 1])
                    except Exception:
                        pass
                return {"text": text}
        return {"text": text}

    return None


# ─────────────────────────────────────────
# High-level helpers for framework
# ─────────────────────────────────────────
def triage_finding(finding: Dict) -> Optional[Dict]:
    """
    Ask AI to triage a single finding: true positive or false positive?
    """
    if not is_ai_available():
        return None
    prompt = f"""
You are a bug bounty triage assistant.

Finding:
{json.dumps(finding, indent=2)[:4000]}

Decide:
1. Is this a true positive or false positive?
2. What is the real severity (critical/high/medium/low/info)?
3. What is the exact next manual verification step?
4. What is the CVSS v3.1 vector?

Return JSON:
{{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "confidence": 0-100,
  "next_step": "...",
  "cvss_vector": "...",
  "reasoning": "..."
}}
"""
    return ask_ai(prompt)


def generate_payloads(vuln_type: str, tech_stack: str,
                      target_url: str, waf: str = "") -> Optional[Dict]:
    """
    Ask AI to generate custom payloads for a specific vuln type.
    """
    if not is_ai_available():
        return None
    prompt = f"""
You are an expert exploit developer.

Vulnerability: {vuln_type}
Target tech stack: {tech_stack}
WAF: {waf or "unknown"}
Target URL: {target_url}

Generate 5 context-aware payloads that bypass common WAFs.

Return JSON:
{{
  "payloads": [
    {{"payload": "...", "where": "param name", "note": "why this works"}}
  ]
}}
"""
    return ask_ai(prompt)


def generate_report(findings: List[Dict], domain: str) -> Optional[Dict]:
    """
    Ask AI to generate a HackerOne-format report.
    """
    if not is_ai_available():
        return None
    prompt = f"""
Write a complete HackerOne bug bounty report.

Target: {domain}
Finding data:
{json.dumps(findings, indent=2)[:6000]}

Return JSON:
{{
  "title": "...",
  "severity": "critical|high|medium|low",
  "cvss_score": 0.0,
  "cvss_vector": "...",
  "description": "...",
  "steps_to_reproduce": "1. ...\\n2. ...",
  "impact": "...",
  "remediation": "...",
  "poc_command": "curl ..."
}}
"""
    return ask_ai(prompt)


# ─────────────────────────────────────────
# CLI diagnostic
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Internal AI engine")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--prompt", help="Test prompt")
    args = parser.parse_args()

    if args.status:
        p = get_active_provider()
        if p:
            print(f"Active provider: {p['name']} | model: {p['model']}")
        else:
            print("No internal AI provider configured (this is OK — AI CLI drives it)")
    elif args.prompt:
        result = ask_ai(args.prompt, json_mode=False)
        print(json.dumps(result, indent=2) if result else "No response")
    else:
        parser.print_help()