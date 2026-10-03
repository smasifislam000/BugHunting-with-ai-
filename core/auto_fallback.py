"""
core/auto_fallback.py
---------------------
Automatic fallback chain for external services:
  Burp MCP → Burp REST → Burp delegation (manual)
  AI primary → AI secondary → AI local → manual prompt
Never lets a single dependency stop the scan.
"""

import json
import time
from typing import Dict, Optional, Callable, Any, List

from core.logger import get_logger, info, warn, skip, ok
from core.config_loader import get_config
from core.platform_detect import is_termux

log = get_logger("auto_fallback")
cfg = get_config()


# ─────────────────────────────────────────
# Generic fallback executor
# ─────────────────────────────────────────
def try_chain(chain: List[Callable[[], Any]],
              labels: Optional[List[str]] = None,
              retry_delay: float = 0.5) -> Any:
    """
    Try each callable in order; return first non-None result.
    Logs which one succeeded.
    """
    labels = labels or [f"step_{i}" for i in range(len(chain))]
    for fn, label in zip(chain, labels):
        try:
            result = fn()
            if result is not None:
                log.debug(f"Fallback succeeded at: {label}")
                return result
        except Exception as e:
            log.debug(f"Fallback '{label}' failed: {e}")
            time.sleep(retry_delay)
    warn("All fallback steps failed")
    return None


# ─────────────────────────────────────────
# Burp fallback
# ─────────────────────────────────────────
def burp_scan(url: str, scan_config: Optional[str] = None) -> Dict:
    """
    Burp integration with 3-level fallback:
      1. MCP (preferred)
      2. REST API
      3. Delegation plan (returned to caller)
    """
    result = {
        "url": url,
        "mode": None,
        "success": False,
        "data": None,
        "delegation": None,
    }

    # Level 1: MCP
    try:
        from burp.burp_mcp_client import (
            check_burp_mcp_status, mcp_scan_url
        )
        status = check_burp_mcp_status()
        if status.get("reachable"):
            res = mcp_scan_url(url, scan_config=scan_config)
            if res.get("ok"):
                result.update({"mode": "mcp", "success": True, "data": res})
                return result
            else:
                warn(f"MCP rejected scan: {res.get('error', 'unknown')}")
    except Exception as e:
        log.debug(f"MCP path failed: {e}")

    # Level 2: REST API
    try:
        from burp.burp_mcp_client import _rest_scan_url
        if cfg.get("burp.rest_api.enabled", False):
            res = _rest_scan_url(url, scan_config, scope_only=True)
            if res.get("ok"):
                result.update({"mode": "rest", "success": True, "data": res})
                return result
    except Exception as e:
        log.debug(f"REST path failed: {e}")

    # Level 3: Delegation plan
    result.update({
        "mode": "delegation",
        "success": False,
        "delegation": {
            "instruction": (
                "AI agent should call 'burp_scan_url' MCP tool directly, "
                "or manually scan this URL in Burp Suite."
            ),
            "url": url,
            "scan_config": scan_config,
        },
    })
    info(f"Burp unavailable — delegation plan for: {url}")
    return result


def burp_available() -> Dict:
    """Return availability info for all Burp modes."""
    info_dict = {
        "mcp": False,
        "rest": False,
        "enabled": cfg.get("burp.enabled", True),
    }
    if not info_dict["enabled"]:
        return info_dict

    try:
        from burp.burp_mcp_client import check_burp_mcp_status
        status = check_burp_mcp_status()
        info_dict["mcp"] = bool(status.get("reachable"))
        info_dict["mcp_host"] = status.get("host")
        info_dict["mcp_port"] = status.get("port")
    except Exception:
        pass

    if cfg.get("burp.rest_api.enabled", False):
        key = cfg.get("burp.rest_api.api_key", "")
        info_dict["rest"] = bool(key)

    return info_dict


# ─────────────────────────────────────────
# AI fallback chain
# ─────────────────────────────────────────
def ai_ask(prompt: str, system: str = "You are a helpful assistant.",
           json_mode: bool = False) -> Optional[Dict]:
    """
    AI call with fallback:
      1. Primary provider (from config ai_driver.internal_ai_optional)
      2. Ollama local (if available)
      3. None (caller handles)
    """
    # Level 1: configured internal AI
    try:
        from core.ai_engine import (
            is_ai_available, ask_ai as _ask
        )
        if is_ai_available():
            res = _ask(prompt, system=system, json_mode=json_mode)
            if res:
                return {"mode": "primary", "result": res}
    except Exception as e:
        log.debug(f"Primary AI failed: {e}")

    # Level 2: Ollama local
    try:
        if not is_termux():
            from core.ai_router import ollama_ask
            res = ollama_ask(prompt)
            if res:
                return {"mode": "ollama", "result": res}
    except Exception as e:
        log.debug(f"Ollama fallback failed: {e}")

    # Level 3: none
    skip("No AI provider available")
    return None


# ─────────────────────────────────────────
# Generic external tool check
# ─────────────────────────────────────────
def tool_or_skip(tool_name: str, fallback_fn: Optional[Callable] = None) -> Any:
    """
    If tool exists → return tool marker.
    Else → run fallback_fn (if provided).
    """
    from core.tool_checker import has_tool
    if has_tool(tool_name):
        return {"available": True, "tool": tool_name}
    if fallback_fn:
        try:
            return {"available": False, "fallback": fallback_fn()}
        except Exception as e:
            log.debug(f"Fallback for {tool_name} failed: {e}")
    return {"available": False, "tool": tool_name}


# ─────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────
def diagnose() -> Dict:
    """Full dependency report."""
    burp = burp_available()
    ai_ok = False
    try:
        from core.ai_engine import is_ai_available
        ai_ok = is_ai_available()
    except Exception:
        pass

    ollama_ok = False
    if not is_termux():
        try:
            from core.ai_router import ollama_is_running
            ollama_ok = ollama_is_running()
        except Exception:
            pass

    return {
        "platform": "termux" if is_termux() else "desktop",
        "burp": burp,
        "ai_primary": ai_ok,
        "ai_ollama": ollama_ok,
        "notes": _notes(burp, ai_ok, ollama_ok),
    }


def _notes(burp, ai_ok, ollama_ok) -> List[str]:
    out = []
    if not burp["enabled"]:
        out.append("Burp disabled in config")
    elif not burp["mcp"]:
        out.append("Burp MCP not reachable — using REST/delegation")
    if not ai_ok:
        out.append("No internal AI key configured — external CLI drives")
    if not ollama_ok and not is_termux():
        out.append("Ollama not running (optional)")
    return out


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Auto fallback diagnostics")
    p.add_argument("--diagnose", action="store_true")
    p.add_argument("--burp-check", action="store_true")
    p.add_argument("--ai-test", help="Test AI prompt")
    args = p.parse_args()

    if args.diagnose:
        print(json.dumps(diagnose(), indent=2, default=str))
    elif args.burp_check:
        print(json.dumps(burp_available(), indent=2))
    elif args.ai_test:
        r = ai_ask(args.ai_test)
        print(json.dumps(r, indent=2, default=str) if r else "No AI result")
    else:
        print(json.dumps(diagnose(), indent=2, default=str))
