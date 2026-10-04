"""
core/ai_async.py
----------------
Asynchronous parallel AI calls.

Send many prompts concurrently (rate-limited) and collect results.
Used in triage/report phases when there are many findings.
"""

import json
import time
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Callable, Iterable

from core.logger import get_logger, info, ok, warn

log = get_logger("ai_async")


# ─────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────
class RateGate:
    """
    Simple token-bucket gate for AI calls per second.
    """
    def __init__(self, per_second: float = 5.0):
        self.per_second = per_second
        self._lock = threading.Lock()
        self._tokens = per_second
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
# Threaded parallel caller
# ─────────────────────────────────────────
def parallel_ai_calls(prompts: List[str],
                      system: str = "You are an expert bug bounty hunter. Respond in JSON.",
                      json_mode: bool = True,
                      timeout: int = 60,
                      max_workers: int = 5,
                      rate_per_sec: float = 5.0,
                      on_result: Optional[Callable[[int, Any], None]] = None
                      ) -> List[Dict]:
    """
    Send N prompts concurrently (threaded) with rate limiting.

    Returns: list of {"index": i, "prompt": p, "result": ..., "error": ...}
    """
    results: List[Optional[Dict]] = [None] * len(prompts)
    gate = RateGate(per_second=rate_per_sec)

    try:
        from core.ai_engine import ask_ai
    except Exception as e:
        warn(f"AI engine unavailable: {e}")
        return [{"index": i, "error": "no engine"} for i in range(len(prompts))]

    def worker(i: int, prompt: str) -> Dict:
        gate.acquire(blocking=True, timeout=30)
        try:
            r = ask_ai(prompt, system=system, json_mode=json_mode, timeout=timeout)
            return {"index": i, "prompt": prompt[:200], "result": r, "error": None}
        except Exception as e:
            return {"index": i, "prompt": prompt[:200], "error": str(e)}

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

    return [r or {"index": i, "error": "timeout"} for i, r in enumerate(results)]


# ─────────────────────────────────────────
# Async version (true asyncio)
# ─────────────────────────────────────────
async def _async_call(session, url: str, headers: Dict, payload: Dict,
                      timeout: int, semaphore: asyncio.Semaphore) -> Optional[Dict]:
    """
    Async HTTP call using aiohttp (if installed).
    """
    try:
        async with semaphore:
            async with session.post(url, headers=headers, json=payload,
                                    timeout=timeout) as resp:
                if resp.status != 200:
                    return None
                return await resp.json()
    except Exception as e:
        log.debug(f"async call failed: {e}")
        return None


def async_ai_calls(prompts: List[str],
                   system: str = "You are an expert bug bounty hunter. Respond in JSON.",
                   json_mode: bool = True,
                   timeout: int = 60,
                   max_concurrent: int = 5,
                   rate_per_sec: float = 5.0) -> List[Dict]:
    """
    True async version using aiohttp. Requires: pip install aiohttp
    """
    try:
        import aiohttp
    except ImportError:
        warn("aiohttp not installed — falling back to threaded parallel_ai_calls")
        return parallel_ai_calls(prompts, system=system, json_mode=json_mode,
                                 timeout=timeout, max_workers=max_concurrent,
                                 rate_per_sec=rate_per_sec)

    try:
        from core.ai_engine import get_active_provider
    except Exception:
        return [{"index": i, "error": "no engine"} for i in range(len(prompts))]

    provider = get_active_provider()
    if not provider:
        return [{"index": i, "error": "no provider"} for i in range(len(prompts))]

    url = provider["base_url"].rstrip("/") + provider["path"]
    headers = {"Content-Type": "application/json"}
    key = provider["api_key"]
    if provider["auth_prefix"]:
        headers[provider["auth_header"]] = f"{provider['auth_prefix']} {key}"
    else:
        headers[provider["auth_header"]] = key

    async def _run():
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
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        raw_results = loop.run_until_complete(_run())
        loop.close()
    except Exception as e:
        warn(f"async loop failed: {e}")
        return [{"index": i, "error": str(e)} for i in range(len(prompts))]

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
# Batch triage helper
# ─────────────────────────────────────────
def batch_triage(findings: List[Dict],
                 max_workers: int = 5,
                 timeout: int = 60) -> List[Dict]:
    """
    Triage many findings in parallel.
    Each finding → one prompt.
    """
    prompts = []
    for f in findings:
        prompts.append(
            "Analyze this finding and return JSON with "
            '{"verdict": "true_positive"|"false_positive"|"uncertain", '
            '"severity": "...", "confidence": 0-100, "reasoning": "..."}:\n'
            + json.dumps(f, ensure_ascii=False)[:2000]
        )

    results = parallel_ai_calls(prompts, max_workers=max_workers, timeout=timeout)
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
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Async AI calls")
    p.add_argument("--test", type=int, default=0,
                   help="Number of test prompts")
    p.add_argument("--async-mode", action="store_true",
                   help="Use async version (requires aiohttp)")
    p.add_argument("--workers", type=int, default=5)
    args = p.parse_args()

    if args.test > 0:
        prompts = [f"Classify: is {i} vulnerable? Return JSON." for i in range(args.test)]
        t0 = time.time()
        if args.async_mode:
            results = async_ai_calls(prompts, max_concurrent=args.workers)
        else:
            results = parallel_ai_calls(prompts, max_workers=args.workers)
        elapsed = time.time() - t0
        ok_c = sum(1 for r in results if r.get("result"))
        print(f"\n{ok_c}/{len(prompts)} succeeded in {elapsed:.2f}s")
    else:
        print("Use --test N")