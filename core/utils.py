"""
core/utils.py
-------------
Common helpers used across the framework.
All functions fail gracefully — no unhandled exceptions.
"""

import os
import re
import json
import time
import random
import hashlib
import subprocess
import shutil
from pathlib import Path
from typing import List, Iterable, Optional, Any
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import requests
import urllib3

from core.logger import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = get_logger("utils")


# ─────────────────────────────────────────
# Filesystem Helpers
# ─────────────────────────────────────────
def ensure_dir(path: str | Path) -> Path:
    """Create directory if missing. Returns Path."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_lines(path: str | Path) -> List[str]:
    """Read file lines, strip, drop empties. Empty list if missing."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip()]
    except Exception as e:
        log.debug(f"read_lines failed for {path}: {e}")
        return []


def write_lines(path: str | Path, lines: Iterable[str]) -> int:
    """Write unique lines to file. Returns count written."""
    p = Path(path)
    ensure_dir(p.parent)
    uniq = dedupe(lines)
    try:
        with open(p, "w", encoding="utf-8") as f:
            for ln in uniq:
                f.write(f"{ln}\n")
        return len(uniq)
    except Exception as e:
        log.warning(f"write_lines failed for {path}: {e}")
        return 0


def append_lines(path: str | Path, lines: Iterable[str]) -> int:
    """Append unique NEW lines only. Returns count added."""
    p = Path(path)
    ensure_dir(p.parent)
    existing = set(read_lines(p))
    added = 0
    try:
        with open(p, "a", encoding="utf-8") as f:
            for ln in lines:
                ln = ln.strip()
                if ln and ln not in existing:
                    f.write(f"{ln}\n")
                    existing.add(ln)
                    added += 1
        return added
    except Exception as e:
        log.warning(f"append_lines failed for {path}: {e}")
        return 0


def dedupe(items: Iterable[str]) -> List[str]:
    """Preserve-order unique list."""
    seen = set()
    out = []
    for it in items:
        it = (it or "").strip()
        if it and it not in seen:
            seen.add(it)
            out.append(it)
    return out


def load_json(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default if default is not None else {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def save_json(path: str | Path, data: Any) -> bool:
    p = Path(path)
    ensure_dir(p.parent)
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        log.warning(f"save_json failed for {path}: {e}")
        return False


# ─────────────────────────────────────────
# Command Runner
# ─────────────────────────────────────────
def which(cmd: str) -> Optional[str]:
    """Check if command exists. Returns path or None."""
    return shutil.which(cmd)


def has_tool(cmd: str) -> bool:
    return which(cmd) is not None


def run_command(cmd, timeout: int = 300, shell: bool = True,
                capture: bool = True) -> str:
    """
    Run shell command. Returns stdout (str). Never raises.
    Logs warning on failure or missing tool.
    """
    if isinstance(cmd, str) and shell:
        first = cmd.strip().split()[0] if cmd.strip() else ""
        if first and not has_tool(first):
            log.debug(f"tool missing: {first}")
            return ""

    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=capture,
            text=True, timeout=timeout
        )
        return result.stdout or ""
    except subprocess.TimeoutExpired:
        log.debug(f"timeout: {cmd}")
        return ""
    except FileNotFoundError:
        log.debug(f"not found: {cmd}")
        return ""
    except Exception as e:
        log.debug(f"run_command error: {e}")
        return ""


def run_command_stream(cmd, timeout: int = 600):
    """
    Generator yielding stdout lines in real-time.
    Useful for long-running tools (nuclei, httpx).
    """
    if isinstance(cmd, str):
        first = cmd.strip().split()[0] if cmd.strip() else ""
        if first and not has_tool(first):
            log.debug(f"tool missing: {first}")
            return
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1
        )
        start = time.time()
        for line in proc.stdout:
            if time.time() - start > timeout:
                proc.kill()
                break
            yield line.rstrip("\n")
        proc.wait(timeout=10)
    except Exception as e:
        log.debug(f"stream error: {e}")


# ─────────────────────────────────────────
# HTTP Helper
# ─────────────────────────────────────────
DEFAULT_UA = "Mozilla/5.0 (compatible; DreamFramework/1.0; +https://example.com)"

def safe_request(url: str, method: str = "GET",
                 timeout: int = 10,
                 headers: Optional[dict] = None,
                 allow_redirects: bool = False,
                 verify: bool = False,
                 retries: int = 2,
                 **kwargs) -> Optional[requests.Response]:
    """Wrapper around requests that never raises."""
    h = {"User-Agent": DEFAULT_UA}
    if headers:
        h.update(headers)
    for attempt in range(retries + 1):
        try:
            return requests.request(
                method, url, timeout=timeout, headers=h,
                allow_redirects=allow_redirects, verify=verify, **kwargs
            )
        except requests.exceptions.RequestException:
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None
        except Exception:
            return None
    return None


# ─────────────────────────────────────────
# URL Helpers
# ─────────────────────────────────────────
def normalize_url(url: str) -> str:
    """Strip fragment, keep query, ensure scheme."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path or "/",
                           p.params, p.query, ""))
    except Exception:
        return url


def extract_domain(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else "https://" + url)
        return p.netloc.split(":")[0]
    except Exception:
        return ""


def url_has_params(url: str) -> bool:
    try:
        return bool(urlparse(url).query)
    except Exception:
        return False


def get_params(url: str) -> List[str]:
    """Return param names from URL query."""
    try:
        return [k for k, _ in parse_qsl(urlparse(url).query)]
    except Exception:
        return []


def inject_param(url: str, param: str, payload: str) -> str:
    """Replace param value in URL with payload."""
    try:
        p = urlparse(url)
        qs = dict(parse_qsl(p.query))
        qs[param] = payload
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs), ""))
    except Exception:
        return url


def url_hash(url: str) -> str:
    return hashlib.md5(url.encode("utf-8", errors="ignore")).hexdigest()[:12]


# ─────────────────────────────────────────
# Regex Extractors
# ─────────────────────────────────────────
URL_RE  = re.compile(r'https?://[^\s"\'<>()\[\]]+')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IP_RE    = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')


def extract_urls(text: str) -> List[str]:
    return dedupe(URL_RE.findall(text or ""))


def extract_emails(text: str) -> List[str]:
    return dedupe(EMAIL_RE.findall(text or ""))


def extract_domains(text: str) -> List[str]:
    return dedupe(m.lower() for m in DOMAIN_RE.findall(text or ""))


# ─────────────────────────────────────────
# Misc
# ─────────────────────────────────────────
def rand_ua() -> str:
    """Random User-Agent (basic rotation)."""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    return random.choice(agents)


def human_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def safe_filename(s: str) -> str:
    """Make a string safe for filenames."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', s)[:120]