"""
core/ai_multi.py
----------------
Multi-model orchestration for AI calls.

Sends the same prompt to N providers in parallel, compares answers,
returns the highest-confidence result (or consensus).

Used when accuracy matters more than cost.
"""

import json
import time
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Callable

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config

log = get_logger("ai_multi")
cfg = get_config()


# ─────────────────────────────────────────
# Provider registry (mirrors ai_engine)
# ─────────────────────────────────────────
PROVIDER_META = {
    "commandcode": {
        "base_url": "https://api.commandcode.ai/provider/v1",
        "path": "/chat/completions",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "path": "/chat/completions",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "path": "/chat/completions",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "path": "/messages",
        "auth_header": "x-api-key",
        "auth_prefix": "",
    },
}


# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
def _active_providers() -> List[Dict]:
    """
    Return list of providers with non-empty API keys.
    """
    providers_cfg = (
        cfg.get("ai_driver.internal_ai_optional.providers", {}) or {}
    )
    active = []
    for name, meta in PROVIDER_META.items():
        pc = providers_cfg.get(name) or {}
        key = (pc.get("api_key") or "").strip()
        if not key:
            continue
        active.append({
            "name": name,
            "api_key": key,
            "base_url": pc.get("base_url") or meta["base_url"],
            "path": meta["path"],
            "model": pc.get("model") or _default_model(name),
            "auth_header": meta["auth_header"],
            "auth_prefix": meta["auth_prefix"],
        })
    return active


def _default_model(name: str) -> str:
    return {
        "commandcode": "command-r-plus",
        "deepseek": "deepseek-chat",
        "openai": "gpt-4o-mini",
        "anthropic": "claude-3-5-sonnet-20241022",
    }.get(name, "")


def multi_available() -> bool:
    return len(_active_providers()) >= 1


def multi_count() -> int:
    return len(_active_providers())


# ─────────────────────────────────────────
# Single provider call
# ─────────────────────────────────────────
def _call_provider(provider: Dict, prompt: str, system: str,
                   json_mode: bool, timeout: int) -> Optional[Dict]:
    """
    Call a single provider. Returns parsed result or None.
    """
    from core.utils import safe_request

    url = provider["base_url"].rstrip("/") + provider["path"]
    headers = {"Content-Type": "application/json"}
    if provider["auth_prefix"]:
        headers[provider["auth_header"]] = f"{provider['auth_prefix']} {provider['api_key']}"
    else:
        headers[provider["auth_header"]] = provider["api_key"]

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

    try:
        r = safe_request(url, method="POST", headers=headers,
                         json=payload, timeout=timeout)
        if not r or r.status_code != 200:
            return None
        data = r.json()
    except Exception as e:
        log.debug(f"provider {provider['name']} failed: {e}")
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

    parsed: Any
    if json_mode:
        try:
            parsed = json.loads(text)
        except Exception:
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end != -1:
                try:
                    parsed = json.loads(text[start:end + 1])
                except Exception:
                    parsed = {"text": text}
            else:
                parsed = {"text": text}
    else:
        parsed = {"text": text}

    return {
        "provider": provider["name"],
        "model": provider["model"],
        "result": parsed,
        "raw_text": text,
    }


# ─────────────────────────────────────────
# Multi-call
# ─────────────────────────────────────────
def ask_multi(prompt: str,
              system: str = "You are an expert bug bounty hunter. Respond with JSON only.",
              json_mode: bool = True,
              timeout: int = 60,
              max_providers: int = 3) -> Optional[Dict]:
    """
    Send prompt to multiple providers in parallel.
    Returns the result with highest consensus.
    """
    providers = _active_providers()[:max_providers]
    if not providers:
        return None

    if len(providers) == 1:
        # Single provider — just call it
        single = _call_provider(providers[0], prompt, system, json_mode, timeout)
        if single:
            return {
                "mode": "single",
                "consensus": False,
                "providers_used": [single["provider"]],
                "answer": single["result"],
                "raw": single["raw_text"],
                "all": [single],
            }
        return None

    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=len(providers)) as ex:
        futures = {
            ex.submit(_call_provider, p, prompt, system, json_mode, timeout): p["name"]
            for p in providers
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                res = fut.result(timeout=timeout + 10)
                if res:
                    results.append(res)
            except Exception as e:
                log.debug(f"provider {name} failed: {e}")

    if not results:
        return None

    # Find consensus by comparing JSON hashes
    hashes: Dict[str, List[Dict]] = {}
    for r in results:
        h = _result_hash(r["result"])
        hashes.setdefault(h, []).append(r)

    # Most common answer
    best_hash = max(hashes.keys(), key=lambda k: len(hashes[k]))
    best_group = hashes[best_hash]

    winner = best_group[0]
    consensus = len(best_group) > len(results) / 2

    return {
        "mode": "multi",
        "consensus": consensus,
        "providers_used": [r["provider"] for r in results],
        "agreeing_providers": [r["provider"] for r in best_group],
        "answer": winner["result"],
        "raw": winner["raw_text"],
        "all": results,
        "agreement_ratio": len(best_group) / len(results),
    }


def _result_hash(result: Any) -> str:
    try:
        canonical = json.dumps(result, sort_keys=True, ensure_ascii=False)
    except Exception:
        canonical = str(result)
    return hashlib.md5(canonical.encode("utf-8", errors="ignore")).hexdigest()


# ─────────────────────────────────────────
# Chain delegation (fallback across providers)
# ─────────────────────────────────────────
def ask_chain(prompt: str,
              system: str = "You are an expert bug bounty hunter. Respond with JSON only.",
              json_mode: bool = True,
              timeout: int = 60) -> Optional[Dict]:
    """
    Try providers in order; return first successful.
    Faster than multi but no consensus.
    """
    for p in _active_providers():
        res = _call_provider(p, prompt, system, json_mode, timeout)
        if res:
            return {
                "mode": "chain",
                "provider": res["provider"],
                "answer": res["result"],
                "raw": res["raw_text"],
            }
    return None


# ─────────────────────────────────────────
# Stats
# ─────────────────────────────────────────
def provider_stats() -> Dict:
    providers = _active_providers()
    return {
        "available": len(providers) > 0,
        "count": len(providers),
        "providers": [p["name"] for p in providers],
    }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Multi-model AI orchestrator")
    p.add_argument("--status", action="store_true")
    p.add_argument("--prompt", help="Test prompt")
    p.add_argument("--chain", action="store_true", help="Use chain instead of multi")
    args = p.parse_args()

    if args.status:
        print(json.dumps(provider_stats(), indent=2))
    elif args.prompt:
        fn = ask_chain if args.chain else ask_multi
        r = fn(args.prompt, json_mode=False)
        print(json.dumps(r, indent=2, default=str) if r else "No result")
    else:
        print(json.dumps(provider_stats(), indent=2))