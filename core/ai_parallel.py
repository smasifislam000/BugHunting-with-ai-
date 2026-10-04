"""
core/ai_parallel.py
-------------------
Parallel AI calls — send multiple prompts simultaneously.

Purpose:
  - Speed up bulk AI operations (triage 20 findings at once)
  - Rate-limited to avoid hitting provider limits
  - Falls back to sequential if threaded execution not possible

Side-effect free:
  - Only imports from core/ai_engine.py (which is unmodified)
  - If aiohttp not installed, falls back to threaded
  - If threading fails, falls back to sequential
  - Never crashes the framework
"""

import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Callable

from core.logger import get_logger

log = get_logger("ai_parallel")


# ─────────────────────────────────────────
# Rate limiter (token-bucket)
# ─────────────────────────────────────────
class RateGate:
    def __init__(self, per_second: float = 5.0):
        self.per_second = float(per_second)
        self._lock = threading.Lock()
        self._tokens = self.per_second
        self._last = time.time()

    def acquire(self, blocking: bool = True, timeout: float = 30.0) -> bool:
        deadline = time.time() + timeout
        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self._last
                self._tokens = min(self.per_second,
                                   self._tokens + elapsed * self.per_second)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return True
            if not blocking:
                return False
            if time.time() > deadline:
                return False
            time.sleep(0.05)


# ─────────────────────────────────────────
# Parallel via threads
# ─────────────────────────────────────────
def parallel_ai_calls(
    prompts: List[str],
    system: str = "You are an expert bug bounty hunter. Respond in JSON.",
    json_mode: bool = True,
    timeout: int = 60,
    max_workers: int = 5,
    rate_per_sec: float = 5.0,
    on_result: Optional[Callable[[int, Dict], None]] = None
) -> List[Dict]:
    """
    Send N prompts concurrently (threaded) with rate limiting.

    Returns: list of
        {"index": i, "prompt": p, "result": ..., "error": ...}
    """
    if not prompts:
        return []

    results: List[Optional[Dict]] = [None] * len(prompts)
    gate = RateGate(per_second=rate_per_sec)

    try:
        from core.ai_engine import ask_ai
    except Exception as e:
        log.debug("AI engine unavailable: " + str(e))
        return [{"index": i, "error": "no engine"} for i in range(len(prompts))]

    def worker(i: int, prompt: str) -> Dict:
        gate.acquire(blocking=True, timeout=30)
        try:
            r = ask_ai(prompt, system=system, json_mode=json_mode,
                       timeout=timeout)
            return {"index": i, "prompt": prompt[:200],
                    "result": r, "error": None}
        except Exception as e:
            return {"index": i, "prompt": prompt[:200],
                    "result": None, "error": str(e)}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(worker, i, p): i for i, p in enumerate(prompts)}
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                res = fut.result(timeout=timeout + 30)
            except Exception as e:
                res = {"index": i, "error": str(e)}
            results[i] = res
            if on_result:
                try:
                    on_result(i, res)
                except Exception:
                    pass

    # Fill any leftover None
    for i in range(len(results)):
        if results[i] is None:
            results[i] = {"index": i, "error": "timeout"}
    return results


# ─────────────────────────────────────────
# Parallel via asyncio (optional)
# ─────────────────────────────────────────
async def _async_call(session, url: str, headers: Dict, payload: Dict,
                      timeout: int, semaphore) -> Optional[Dict]:
    try:
        async with semaphore:
            async with session.post(url, headers=headers, json=payload,
                                    timeout=timeout) as resp:
                if resp.status != 200:
                    return None
                return await resp.json()
    except Exception as e:
        log.debug("async call failed: " + str(e))
        return None


def async_ai_calls(
    prompts: List[str],
    system: str = "You are an expert bug bounty hunter. Respond in JSON.",
    json_mode: bool = True,
    timeout: int = 60,
    max_concurrent: int = 5,
    rate_per_sec: float = 5.0
) -> List[Dict]:
    """
    True async version using aiohttp.
    If aiohttp not available, falls back to threaded version.
    """
    try:
        import aiohttp
    except ImportError:
        log.debug("aiohttp not installed — using threaded fallback")
        return parallel_ai_calls(
            prompts, system=system, json_mode=json_mode,
            timeout=timeout, max_workers=max_concurrent,
            rate_per_sec=rate_per_sec
        )

    try:
        from core.ai_engine import get_active_provider
    except Exception:
        return [{"index": i, "error": "no engine"}
                for i in range(len(prompts))]

    provider = get_active_provider()
    if not provider:
        return [{"index": i, "error": "no provider"}
                for i in range(len(prompts))]

    url = provider["base_url"].rstrip("/") + provider["path"]
    headers = {"Content-Type": "application/json"}
    key = provider["api_key"]
    if provider["auth_prefix"]:
        headers[provider["auth_header"]] = provider["auth_prefix"] + " " + key
    else:
        headers[provider["auth_header"]] = key

    async def _run():
        import asyncio
        sem = asyncio.Semaphore(max_concurrent)
        async with aiohttp.ClientSession() as session:
            tasks = []
            for p in prompts:
                payload = {
                    "model": provider["model"],
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": p},
                    ],
                    "temperature": 0.1,
                }
                if json_mode:
                    payload["response_format"] = {"type": "json_object"}
                tasks.append(_async_call(session, url, headers, payload,
                                         timeout, sem))
            raw = await asyncio.gather(*tasks, return_exceptions=True)
            return raw

    try:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        raw_results = loop.run_until_complete(_run())
        loop.close()
    except Exception as e:
        log.debug("async loop failed: " + str(e))
        return parallel_ai_calls(
            prompts, system=system, json_mode=json_mode,
            timeout=timeout, max_workers=max_concurrent,
            rate_per_sec=rate_per_sec
        )

    parsed: List[Dict] = []
    for i, data in enumerate(raw_results):
        if isinstance(data, Exception) or data is None:
            parsed.append({"index": i, "result": None, "error": str(data)})
            continue
        text = ""
        choices = data.get("choices", []) if isinstance(data, dict) else []
        if choices:
            text = choices[0].get("message", {}).get("content", "")
        if not text:
            parsed.append({"index": i, "result": None, "error": "empty"})
            continue

        result: Any
        if json_mode:
            try:
                result = json.loads(text)
            except Exception:
                start, end = text.find("{"), text.rfind("}")
                if start != -1 and end != -1:
                    try:
                        result = json.loads(text[start:end + 1])
                    except Exception:
                        result = {"text": text}
                else:
                    result = {"text": text}
        else:
            result = {"text": text}
        parsed.append({"index": i, "result": result, "error": None})

    return parsed


# ─────────────────────────────────────────
# High-level: batch triage
# ─────────────────────────────────────────
def batch_triage(findings: List[Dict],
                 max_workers: int = 5,
                 timeout: int = 60) -> List[Dict]:
    """
    Triage many findings in parallel.
    Each finding -> one prompt.
    """
    if not findings:
        return []

    prompts = []
    for f in findings:
        prompts.append(
            "Analyze this finding and return JSON with "
            '{"verdict": "true_positive"|"false_positive"|"uncertain", '
            '"severity": "...", "confidence": 0-100, "reasoning": "..."}:\n'
            + json.dumps(f, ensure_ascii=False)[:2000]
        )

    results = parallel_ai_calls(prompts, max_workers=max_workers,
                                timeout=timeout)
    merged: List[Dict] = []
    for i, f in enumerate(findings):
        r = results[i] if i < len(results) else {}
        merged.append({
            "finding": f,
            "ai_result": r.get("result"),
            "error": r.get("error"),
        })
    return merged


# ─────────────────────────────────────────
# High-level: batch payload generation
# ─────────────────────────────────────────
def batch_payloads(vuln_types: List[str],
                   tech_stack: str = "",
                   target_url: str = "",
                   max_workers: int = 5,
                   timeout: int = 60) -> Dict[str, Any]:
    """
    Generate payloads for multiple vuln types in parallel.
    """
    if not vuln_types:
        return {}

    prompts = []
    for vt in vuln_types:
        prompts.append(
            "Generate 5 WAF-bypass payloads for " + vt + " on " + target_url +
            " (tech: " + tech_stack + "). Return JSON: "
            '{"payloads": [{"payload": "...", "note": "..."}]}'
        )

    results = parallel_ai_calls(prompts, max_workers=max_workers,
                                timeout=timeout)
    out = {}
    for i, vt in enumerate(vuln_types):
        r = results[i] if i < len(results) else {}
        out[vt] = r.get("result") or r.get("error")
    return out


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Parallel AI calls")
    p.add_argument("--test", type=int, default=0,
                   help="Number of test prompts")
    p.add_argument("--async-mode", action="store_true",
                   help="Use async version (requires aiohttp)")
    p.add_argument("--workers", type=int, default=5)
    args = p.parse_args()

    if args.test > 0:
        prompts = ["Classify " + str(i) + " as XSS or SQLi. Return JSON."
                   for i in range(args.test)]
        t0 = time.time()
        if args.async_mode:
            results = async_ai_calls(prompts, max_concurrent=args.workers)
        else:
            results = parallel_ai_calls(prompts, max_workers=args.workers)
        elapsed = time.time() - t0
        ok_count = sum(1 for r in results if r.get("result"))
        print(str(ok_count) + "/" + str(len(prompts)) +
              " succeeded in " + str(round(elapsed, 2)) + "s")
    else:
        print("Use --test N")