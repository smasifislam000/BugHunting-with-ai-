"""
core/ai_router.py
-----------------
Smart model routing based on task complexity.

Rules:
  - simple tasks (classification, yes/no, short extraction) → cheap/fast model
  - medium tasks (triage, summary) → balanced model
  - complex tasks (deep reasoning, chained exploit, business logic) → expensive model

Also provides local Ollama fallback when available.
"""

import json
import time
from typing import Dict, List, Optional, Any
from enum import Enum

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config
from core.platform_detect import is_termux

log = get_logger("ai_router")
cfg = get_config()


# ─────────────────────────────────────────
# Task complexity
# ─────────────────────────────────────────
class Complexity(str, Enum):
    SIMPLE = "simple"
    MEDIUM = "medium"
    COMPLEX = "complex"


# ─────────────────────────────────────────
# Model tiers per provider
# ─────────────────────────────────────────
MODEL_TIERS = {
    "commandcode": {
        Complexity.SIMPLE:  "command-r",
        Complexity.MEDIUM:  "command-r-plus",
        Complexity.COMPLEX: "command-r-plus",
    },
    "deepseek": {
        Complexity.SIMPLE:  "deepseek-chat",
        Complexity.MEDIUM:  "deepseek-chat",
        Complexity.COMPLEX: "deepseek-reasoner",
    },
    "openai": {
        Complexity.SIMPLE:  "gpt-4o-mini",
        Complexity.MEDIUM:  "gpt-4o-mini",
        Complexity.COMPLEX: "gpt-4o",
    },
    "anthropic": {
        Complexity.SIMPLE:  "claude-3-5-haiku-20241022",
        Complexity.MEDIUM:  "claude-3-5-sonnet-20241022",
        Complexity.COMPLEX: "claude-3-5-sonnet-20241022",
    },
}


# Relative costs (arbitrary units, higher = more expensive)
MODEL_COST = {
    "command-r":              1,
    "command-r-plus":         3,
    "deepseek-chat":          1,
    "deepseek-reasoner":      2,
    "gpt-4o-mini":            2,
    "gpt-4o":                 10,
    "claude-3-5-haiku-20241022":   1,
    "claude-3-5-sonnet-20241022":  5,
    "llama3.1:8b":            0.1,  # ollama local
    "qwen2.5:7b":             0.1,  # ollama local
    "mistral:7b":             0.1,  # ollama local
}


# ─────────────────────────────────────────
# Complexity heuristics
# ─────────────────────────────────────────
COMPLEX_KEYWORDS = [
    "chain", "exploit", "business logic", "race condition",
    "multi-step", "combine", "bypass", "reasoning", "why",
    "analyze deeply", "correlate", "prioritize by impact",
    "auth bypass", "privilege escalation", "csrf chain",
]

SIMPLE_KEYWORDS = [
    "is this", "yes or no", "classify", "label",
    "true or false", "which one", "yes/no",
    "is the following", "does this contain",
]


def classify_complexity(prompt: str, task_hint: Optional[str] = None) -> Complexity:
    """
    Heuristic classifier for prompt complexity.
    """
    p = (prompt or "").lower()

    if task_hint:
        hint = task_hint.lower()
        if hint in ("classify", "boolean", "yes_no", "label"):
            return Complexity.SIMPLE
        if hint in ("triage", "summary", "extract", "next_step"):
            return Complexity.MEDIUM
        if hint in ("chain", "deep_analysis", "exploit", "business_logic"):
            return Complexity.COMPLEX

    # Keyword matching
    for kw in COMPLEX_KEYWORDS:
        if kw in p:
            return Complexity.COMPLEX
    for kw in SIMPLE_KEYWORDS:
        if kw in p:
            return Complexity.SIMPLE

    # Length heuristic
    if len(p) < 300:
        return Complexity.SIMPLE
    if len(p) < 1500:
        return Complexity.MEDIUM
    return Complexity.COMPLEX


# ─────────────────────────────────────────
# Provider access
# ─────────────────────────────────────────
def _all_providers() -> List[Dict]:
    try:
        from core.ai_engine import PROVIDERS, get_active_provider
    except Exception:
        return []

    internal = cfg.get("ai_driver.internal_ai_optional", {}) or {}
    providers_cfg = internal.get("providers", {}) or {}

    active = []
    for name, meta in PROVIDERS.items():
        pc = providers_cfg.get(name) or {}
        key = (pc.get("api_key") or "").strip()
        if not key:
            continue
        active.append({
            "name": name,
            "api_key": key,
            "base_url": pc.get("base_url") or meta["base_url"],
            "path": meta["path"],
            "auth_header": meta["auth_header"],
            "auth_prefix": meta["auth_prefix"],
        })
    return active


def _pick_model(provider_name: str, complexity: Complexity) -> str:
    tier = MODEL_TIERS.get(provider_name, {})
    return tier.get(complexity) or "default"


# ─────────────────────────────────────────
# Ollama local support
# ─────────────────────────────────────────
def ollama_is_running(host: str = "127.0.0.1", port: int = 11434) -> bool:
    if is_termux():
        return False
    try:
        import socket
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except Exception:
        return False


def ollama_list_models(host: str = "127.0.0.1", port: int = 11434) -> List[str]:
    try:
        from core.utils import safe_request
        r = safe_request(f"http://{host}:{port}/api/tags", timeout=4)
        if r and r.status_code == 200:
            data = r.json()
            return [m.get("name", "") for m in data.get("models", [])]
    except Exception:
        pass
    return []


def ollama_ask(prompt: str,
               model: str = "llama3.1:8b",
               system: str = "You are a helpful assistant.",
               host: str = "127.0.0.1",
               port: int = 11434,
               timeout: int = 60) -> Optional[Dict]:
    """
    Call local Ollama. Only works if Ollama is running.
    """
    if is_termux():
        return None
    try:
        from core.utils import safe_request
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
        }
        r = safe_request(f"http://{host}:{port}/api/generate",
                         method="POST", json=payload, timeout=timeout)
        if not r or r.status_code != 200:
            return None
        data = r.json()
        text = data.get("response", "")
        return {"text": text} if text else None
    except Exception as e:
        log.debug(f"ollama failed: {e}")
        return None


# ─────────────────────────────────────────
# Main router
# ─────────────────────────────────────────
def route_and_call(prompt: str,
                   system: str = "You are an expert bug bounty hunter. Respond with JSON only.",
                   task_hint: Optional[str] = None,
                   json_mode: bool = True,
                   timeout: int = 60,
                   prefer_cheap: bool = False,
                   allow_local: bool = True) -> Optional[Dict]:
    """
    Route prompt to the best provider/model based on complexity.
    """
    complexity = classify_complexity(prompt, task_hint)

    # 1) Local Ollama for SIMPLE tasks (free)
    if allow_local and complexity == Complexity.SIMPLE and not is_termux():
        if ollama_is_running():
            models = ollama_list_models()
            if models:
                model = models[0]
                local = ollama_ask(prompt, model=model, system=system)
                if local:
                    log.debug(f"routed to local Ollama ({model})")
                    return {
                        "mode": "local",
                        "provider": "ollama",
                        "model": model,
                        "complexity": complexity.value,
                        "answer": local,
                    }

    # 2) Remote providers
    providers = _all_providers()
    if not providers:
        return None

    if prefer_cheap:
        # Sort providers by their tier's cost
        def _cost(p):
            model = _pick_model(p["name"], complexity)
            return MODEL_COST.get(model, 99)
        providers.sort(key=_cost)

    # Try each provider in order
    for p in providers:
        model = _pick_model(p["name"], complexity)
        result = _call_provider_model(p, model, prompt, system, json_mode, timeout)
        if result:
            log.debug(f"routed to {p['name']} / {model} ({complexity.value})")
            return {
                "mode": "remote",
                "provider": p["name"],
                "model": model,
                "complexity": complexity.value,
                "answer": result,
            }

    return None


def _call_provider_model(provider: Dict, model: str, prompt: str,
                         system: str, json_mode: bool, timeout: int
                         ) -> Optional[Any]:
    """Call a specific provider/model combination."""
    from core.utils import safe_request

    url = provider["base_url"].rstrip("/") + provider["path"]
    headers = {"Content-Type": "application/json"}
    if provider["auth_prefix"]:
        headers[provider["auth_header"]] = f"{provider['auth_prefix']} {provider['api_key']}"
    else:
        headers[provider["auth_header"]] = provider["api_key"]

    if provider["name"] == "anthropic":
        payload = {
            "model": model,
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
    else:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

    try:
        r = safe_request(url, method="POST", headers=headers,
                         json=payload, timeout=timeout)
        if not r or r.status_code != 200:
            return None
        data = r.json()
    except Exception as e:
        log.debug(f"call failed: {e}")
        return None

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
        except Exception:
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end != -1:
                try:
                    return json.loads(text[start:end + 1])
                except Exception:
                    pass
            return {"text": text}
    return {"text": text}


# ─────────────────────────────────────────
# Cost reporting
# ─────────────────────────────────────────
def estimate_routing(prompt: str, task_hint: Optional[str] = None) -> Dict:
    """
    Preview which provider/model will be used and cost weight.
    """
    complexity = classify_complexity(prompt, task_hint)
    providers = _all_providers()
    result = {
        "complexity": complexity.value,
        "candidates": [],
    }
    for p in providers:
        model = _pick_model(p["name"], complexity)
        result["candidates"].append({
            "provider": p["name"],
            "model": model,
            "cost_weight": MODEL_COST.get(model, 99),
        })
    result["candidates"].sort(key=lambda x: x["cost_weight"])
    return result


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI router")
    p.add_argument("--classify", help="Test complexity classification")
    p.add_argument("--preview", help="Preview routing for a prompt")
    p.add_argument("--ollama-status", action="store_true")
    p.add_argument("--models", action="store_true", help="List Ollama models")
    args = p.parse_args()

    if args.classify:
        print(classify_complexity(args.classify))
    elif args.preview:
        print(json.dumps(estimate_routing(args.preview), indent=2))
    elif args.ollama_status:
        print("Ollama running:", ollama_is_running())
    elif args.models:
        print(json.dumps(ollama_list_models(), indent=2))
    else:
        print(json.dumps(estimate_routing("classify this finding"), indent=2))