"""
core/ai_function_calling.py
---------------------------
Native function-calling / tool-use for AI providers.

The AI can request tool executions like:
  - burp_scan_url
  - run_nuclei
  - fetch_url
  - search_cve
  - ask_more_context

The framework executes those tools and returns results.
"""

import json
from typing import Dict, List, Optional, Any, Callable

from core.logger import get_logger, info, ok, warn, skip

log = get_logger("ai_function_calling")


# ─────────────────────────────────────────
# Tool registry
# ─────────────────────────────────────────
TOOLS: Dict[str, Dict] = {}
_TOOL_IMPLS: Dict[str, Callable] = {}


def register_tool(name: str, description: str, parameters: Dict,
                  impl: Callable[[Dict], Any]) -> None:
    """
    Register a tool the AI can call.
    parameters should be JSON-schema style.
    """
    TOOLS[name] = {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters,
        },
    }
    _TOOL_IMPLS[name] = impl


def call_tool(name: str, arguments: Dict) -> Any:
    if name not in _TOOL_IMPLS:
        return {"error": f"Unknown tool: {name}"}
    try:
        return _TOOL_IMPLS[name](arguments)
    except Exception as e:
        log.debug(f"tool {name} failed: {e}")
        return {"error": str(e)}


# ─────────────────────────────────────────
# Built-in tool definitions (implementations are wired by user)
# ─────────────────────────────────────────
def _register_defaults() -> None:
    """Register framework default tools."""
    if "fetch_url" not in TOOLS:
        register_tool(
            name="fetch_url",
            description="Fetch a URL and return status, headers, body preview.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object"},
                    "body": {"type": "string"},
                },
                "required": ["url"],
            },
            impl=_impl_fetch_url,
        )

    if "run_nuclei" not in TOOLS:
        register_tool(
            name="run_nuclei",
            description="Run nuclei scanner on a target URL and return findings.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "severity": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "e.g. ['high','critical']",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["target"],
            },
            impl=_impl_run_nuclei,
        )

    if "burp_scan_url" not in TOOLS:
        register_tool(
            name="burp_scan_url",
            description="Send a URL to Burp Suite Pro for active scan.",
            parameters={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
            impl=_impl_burp_scan,
        )

    if "search_cve" not in TOOLS:
        register_tool(
            name="search_cve",
            description="Search NVD for CVEs matching a keyword (e.g., 'apache 2.4.49').",
            parameters={
                "type": "object",
                "properties": {"keyword": {"type": "string"}},
                "required": ["keyword"],
            },
            impl=_impl_search_cve,
        )

    if "check_tool" not in TOOLS:
        register_tool(
            name="check_tool",
            description="Check if a CLI tool is available on the system.",
            parameters={
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
            impl=_impl_check_tool,
        )


# ─────────────────────────────────────────
# Default implementations
# ─────────────────────────────────────────
def _impl_fetch_url(args: Dict) -> Dict:
    from core.utils import safe_request
    r = safe_request(
        args["url"],
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        data=args.get("body"),
        timeout=12,
    )
    if not r:
        return {"error": "request failed"}
    return {
        "status": r.status_code,
        "headers": dict(r.headers),
        "body_preview": (r.text or "")[:1500],
        "length": len(r.content),
    }


def _impl_run_nuclei(args: Dict) -> Dict:
    import tempfile
    from core.utils import run_command, has_tool
    if not has_tool("nuclei"):
        return {"error": "nuclei not installed"}

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(args["target"])
        target_file = f.name

    sev = ",".join(args.get("severity") or ["high", "critical"])
    tags = ",".join(args.get("tags") or [])
    cmd = f"nuclei -l {target_file} -severity {sev} -jsonl -silent"
    if tags:
        cmd += f" -tags {tags}"
    out = run_command(cmd, timeout=600)

    findings = []
    for line in out.splitlines():
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    return {"count": len(findings), "findings": findings[:20]}


def _impl_burp_scan(args: Dict) -> Dict:
    try:
        from core.auto_fallback import burp_scan
        return burp_scan(args["url"])
    except Exception as e:
        return {"error": str(e)}


def _impl_search_cve(args: Dict) -> Dict:
    try:
        from intel.nvd_api import search_cves
        cves = search_cves(args["keyword"], max_results=10)
        return {"count": len(cves), "cves": cves}
    except Exception as e:
        return {"error": str(e)}


def _impl_check_tool(args: Dict) -> Dict:
    try:
        from core.tool_checker import has_tool
        return {"name": args["name"], "available": has_tool(args["name"])}
    except Exception as e:
        return {"error": str(e)}


# Auto-register on import
_register_defaults()


# ─────────────────────────────────────────
# Function-calling API
# ─────────────────────────────────────────
def _supports_function_calling(provider_name: str) -> bool:
    """Which providers support OpenAI-style function calling?"""
    return provider_name in ("commandcode", "deepseek", "openai")


def ask_with_tools(prompt: str,
                   system: str = "You are an expert bug bounty hunter.",
                   tools: Optional[List[str]] = None,
                   max_iterations: int = 5,
                   timeout: int = 90) -> Optional[Dict]:
    """
    Ask the AI with tools enabled.
    Loop:
      1. Send prompt + tool definitions
      2. If AI requests tool call(s): execute them, feed results back
      3. Repeat until AI returns final answer or max_iterations reached
    """
    from core.utils import safe_request
    try:
        from core.ai_engine import get_active_provider
    except Exception:
        return None

    provider = get_active_provider()
    if not provider:
        return None
    if not _supports_function_calling(provider["name"]):
        skip(f"{provider['name']} does not support function calling")
        return None

    # Build tool list
    selected = tools or list(TOOLS.keys())
    tool_defs = [TOOLS[t] for t in selected if t in TOOLS]

    url = provider["base_url"].rstrip("/") + provider["path"]
    headers = {"Content-Type": "application/json"}
    key = provider["api_key"]
    if provider["auth_prefix"]:
        headers[provider["auth_header"]] = f"{provider['auth_prefix']} {key}"
    else:
        headers[provider["auth_header"]] = key

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]

    history: List[Dict] = []

    for iteration in range(max_iterations):
        payload = {
            "model": provider["model"],
            "messages": messages,
            "tools": tool_defs,
            "tool_choice": "auto",
            "temperature": 0.1,
        }
        r = safe_request(url, method="POST", headers=headers,
                         json=payload, timeout=timeout)
        if not r or r.status_code != 200:
            return {"error": f"HTTP {r.status_code if r else 'none'}"}

        try:
            data = r.json()
        except Exception:
            return {"error": "invalid json"}

        choices = data.get("choices") or []
        if not choices:
            return {"error": "no choices"}
        msg = choices[0].get("message") or {}

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            # Final answer
            return {
                "iterations": iteration + 1,
                "answer": msg.get("content", ""),
                "history": history,
            }

        # Append assistant message with tool_calls
        messages.append(msg)

        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except Exception:
                args = {}

            result = call_tool(name, args)
            history.append({"tool": name, "args": args, "result": result})

            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", ""),
                "content": json.dumps(result)[:4000],
            })

    return {
        "error": "max_iterations_reached",
        "history": history,
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI function calling")
    p.add_argument("--list-tools", action="store_true")
    p.add_argument("--test", help="Test prompt")
    args = p.parse_args()

    if args.list_tools:
        print(json.dumps(list(TOOLS.keys()), indent=2))
    elif args.test:
        r = ask_with_tools(args.test)
        print(json.dumps(r, indent=2, default=str))
    else:
        print(json.dumps(list(TOOLS.keys()), indent=2))