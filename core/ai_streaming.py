"""
core/ai_streaming.py
--------------------
Streaming AI responses (SSE).

Displays tokens as they arrive, so long responses don't time out
and users see progress in real-time.
"""

import json
import time
import threading
from typing import Dict, Optional, Generator, Callable

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config

log = get_logger("ai_streaming")
cfg = get_config()


# ─────────────────────────────────────────
# Provider selection
# ─────────────────────────────────────────
def _get_active_provider() -> Optional[Dict]:
    try:
        from core.ai_engine import get_active_provider
        return get_active_provider()
    except Exception:
        return None


def streaming_available() -> bool:
    p = _get_active_provider()
    if not p:
        return False
    # Anthropic uses SSE too but different format; only OpenAI-style for now
    return p["name"] in ("commandcode", "deepseek", "openai")


# ─────────────────────────────────────────
# Stream call (raw)
# ─────────────────────────────────────────
def stream_ai(prompt: str,
              system: str = "You are an expert bug bounty hunter.",
              json_mode: bool = False,
              timeout: int = 120,
              on_chunk: Optional[Callable[[str], None]] = None
              ) -> Generator[str, None, None]:
    """
    Generator yielding text chunks from the AI.
    If on_chunk is provided, it's also called for each chunk.
    """
    import requests

    provider = _get_active_provider()
    if not provider:
        skip("No AI provider available for streaming")
        return

    url = provider["base_url"].rstrip("/") + provider["path"]
    headers = {"Content-Type": "application/json"}
    key = provider["api_key"]
    if provider["auth_prefix"]:
        headers[provider["auth_header"]] = f"{provider['auth_prefix']} {key}"
    else:
        headers[provider["auth_header"]] = key

    payload = {
        "model": provider["model"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "stream": True,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    try:
        with requests.post(url, headers=headers, json=payload,
                           stream=True, timeout=timeout, verify=False) as r:
            if r.status_code != 200:
                warn(f"Stream HTTP {r.status_code}")
                return
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                if line.startswith("data: "):
                    data = line[6:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        obj = json.loads(data)
                    except Exception:
                        continue
                    choices = obj.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        if on_chunk:
                            try:
                                on_chunk(content)
                            except Exception:
                                pass
                        yield content
    except Exception as e:
        log.debug(f"stream error: {e}")


def stream_to_string(prompt: str,
                     system: str = "You are an expert bug bounty hunter.",
                     json_mode: bool = False,
                     timeout: int = 120,
                     print_live: bool = False) -> Optional[str]:
    """
    Collect the entire streamed response as a single string.
    If print_live=True, prints to stdout live.
    """
    chunks = []
    for chunk in stream_ai(prompt, system=system,
                           json_mode=json_mode, timeout=timeout):
        chunks.append(chunk)
        if print_live:
            print(chunk, end="", flush=True)
    if print_live:
        print()
    text = "".join(chunks)
    return text or None


# ─────────────────────────────────────────
# Progress-aware stream with callback
# ─────────────────────────────────────────
class StreamPrinter:
    """
    Thread-safe printer that shows live progress.
    """

    def __init__(self, prefix: str = "AI: ", newline_at_end: bool = True):
        self.prefix = prefix
        self.newline_at_end = newline_at_end
        self._printed_prefix = False
        self._lock = threading.Lock()
        self.bytes_written = 0
        self.start_time = time.time()

    def on_chunk(self, chunk: str) -> None:
        with self._lock:
            if not self._printed_prefix:
                print(self.prefix, end="", flush=True)
                self._printed_prefix = True
            print(chunk, end="", flush=True)
            self.bytes_written += len(chunk)

    def finish(self) -> None:
        with self._lock:
            if self._printed_prefix and self.newline_at_end:
                elapsed = time.time() - self.start_time
                print(f"\n[{self.bytes_written} chars in {elapsed:.1f}s]")


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI streaming")
    p.add_argument("--status", action="store_true")
    p.add_argument("--prompt", help="Prompt to stream")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    if args.status:
        print("Streaming available:", streaming_available())
        prov = _get_active_provider()
        print("Active provider:", prov["name"] if prov else "none")
    elif args.prompt:
        printer = StreamPrinter("AI: ")
        chunks = []
        for chunk in stream_ai(args.prompt, on_chunk=printer.on_chunk):
            chunks.append(chunk)
        printer.finish()
        if args.quiet:
            print("Total:", len("".join(chunks)), "chars")
    else:
        print("Streaming available:", streaming_available())