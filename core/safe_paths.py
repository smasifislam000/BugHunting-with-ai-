"""
core/safe_paths.py
------------------
Safe path utilities for writing results, logs, reports.
Prevents directory traversal and OS-specific filename issues.
"""

import os
import re
import platform
from pathlib import Path
from typing import Union, Optional
from urllib.parse import urlparse

from core.logger import get_logger

log = get_logger("safe_paths")


# ─────────────────────────────────────────
# Constants
# ─────────────────────────────────────────
INVALID_CHARS = {
    "windows": r'<>:"/\|?*',
    "unix": "/",
    "macos": "/:",
}


def sanitize_filename(name: str, max_len: int = 200) -> str:
    """
    Convert arbitrary string to a safe filename for the current OS.
    """
    if not name:
        return "unnamed"

    sys = platform.system().lower()
    invalid = INVALID_CHARS.get(sys, "/")

    safe = name
    for ch in invalid:
        safe = safe.replace(ch, "_")

    # Remove control chars
    safe = re.sub(r"[\x00-\x1f]", "_", safe)

    # Avoid reserved names on Windows
    if sys == "windows":
        reserved = {"CON", "PRN", "AUX", "NUL",
                    "COM1", "COM2", "COM3", "COM4",
                    "LPT1", "LPT2", "LPT3"}
        stem = safe.split(".")[0].upper()
        if stem in reserved:
            safe = "_" + safe

    # Collapse whitespace
    safe = re.sub(r"\s+", "_", safe)

    # Trim length
    if len(safe) > max_len:
        stem, ext = os.path.splitext(safe)
        keep = max_len - len(ext)
        safe = stem[:keep] + ext

    return safe or "unnamed"


def sanitize_domain(domain: str) -> str:
    """Domain → safe folder name."""
    if not domain:
        return "unknown"
    d = domain.lower().strip()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = d.split(":")[0]
    d = re.sub(r"[^a-z0-9.\-_]", "_", d)
    return d[:150] or "unknown"


def ensure_within(base: Union[str, Path], target: Union[str, Path]) -> Path:
    """
    Ensure target is inside base.
    Raises ValueError if traversal detected.
    """
    base_p = Path(base).resolve()
    target_p = Path(target).resolve()
    try:
        target_p.relative_to(base_p)
    except ValueError:
        raise ValueError(f"Path traversal detected: {target_p} not in {base_p}")
    return target_p


def safe_join(base: Union[str, Path], *parts: str) -> Path:
    """
    Join base with parts, sanitizing each part.
    Ensures result stays under base.
    """
    base_p = Path(base).resolve()
    sanitized = [sanitize_filename(p) for p in parts if p]
    target = base_p.joinpath(*sanitized)
    return ensure_within(base_p, target)


def safe_results_dir(domain: str, base: str = "results",
                     module: Optional[str] = None) -> Path:
    """
    results/<domain>/[modules/<module>]/
    """
    d = sanitize_domain(domain)
    if module:
        m = sanitize_filename(module)
        return Path(base) / d / "modules" / m
    return Path(base) / d


def ensure_dir(path: Union[str, Path]) -> Path:
    """Create directory if not exists. Returns Path."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def safe_write(path: Union[str, Path], content: str,
               encoding: str = "utf-8") -> bool:
    """Write file safely. Never raises."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding=encoding, errors="ignore") as f:
            f.write(content)
        return True
    except Exception as e:
        log.debug(f"safe_write failed for {path}: {e}")
        return False


def safe_append(path: Union[str, Path], content: str,
                encoding: str = "utf-8") -> bool:
    """Append to file safely. Never raises."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding=encoding, errors="ignore") as f:
            f.write(content)
        return True
    except Exception as e:
        log.debug(f"safe_append failed for {path}: {e}")
        return False


def safe_read(path: Union[str, Path],
              encoding: str = "utf-8") -> Optional[str]:
    """Read file safely. Returns None on failure."""
    try:
        p = Path(path)
        if not p.exists():
            return None
        with open(p, "r", encoding=encoding, errors="ignore") as f:
            return f.read()
    except Exception as e:
        log.debug(f"safe_read failed for {path}: {e}")
        return None


def filename_from_url(url: str, suffix: str = "") -> str:
    """
    Create a safe filename from a URL.
    """
    try:
        p = urlparse(url)
        host = sanitize_filename(p.netloc or "host")
        path = (p.path or "/").strip("/").replace("/", "_")
        if not path:
            path = "root"
        name = f"{host}_{path}"
        if p.query:
            name += "_" + sanitize_filename(p.query[:50])
        if suffix:
            name += suffix
        return sanitize_filename(name, max_len=180)
    except Exception:
        return sanitize_filename(str(url)[:100])


def cleanup_empty_dirs(root: Union[str, Path]) -> int:
    """Remove empty directories under root (bottom-up)."""
    count = 0
    root_p = Path(root)
    if not root_p.exists():
        return 0
    for dirpath, dirnames, filenames in os.walk(str(root_p), topdown=False):
        try:
            if not os.listdir(dirpath):
                os.rmdir(dirpath)
                count += 1
        except Exception:
            pass
    return count


def free_space_gb(path: Union[str, Path] = ".") -> float:
    """Return free space in GB."""
    try:
        import shutil
        total, used, free = shutil.disk_usage(str(path))
        return free / (1024 ** 3)
    except Exception:
        return 0.0


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Safe paths")
    p.add_argument("--test")
    p.add_argument("--space", default=".")
    args = p.parse_args()

    if args.test:
        print("Input:  ", args.test)
        print("Safe:   ", sanitize_filename(args.test))
    else:
        print(f"Free space: {free_space_gb(args.space):.2f} GB")