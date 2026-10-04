"""
core/platform_detect.py
-----------------------
Detects the running environment: Termux, Kali, Ubuntu, macOS, Windows, Docker.
Modules can behave differently per platform (e.g., skip Playwright on Termux).
"""

import os
import sys
import platform
import shutil
from pathlib import Path
from typing import Dict, Optional

from core.logger import get_logger

log = get_logger("platform_detect")


# ─────────────────────────────────────────
# Cached detection
# ─────────────────────────────────────────
_INFO: Optional[Dict] = None


def _detect() -> Dict:
    global _INFO
    if _INFO is not None:
        return _INFO

    sys_platform = sys.platform.lower()
    machine = platform.machine().lower()
    is_termux = (
        "com.termux" in os.environ.get("PREFIX", "")
        or Path("/data/data/com.termux").exists()
        or "ANDROID_ROOT" in os.environ
    )
    is_wsl = "microsoft" in platform.release().lower() or "WSL" in platform.release()

    distro = ""
    distro_id = ""
    try:
        if Path("/etc/os-release").exists():
            data = {}
            for line in Path("/etc/os-release").read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"')
            distro = data.get("PRETTY_NAME", "")
            distro_id = data.get("ID", "").lower()
    except Exception:
        pass

    is_kali = "kali" in distro_id or "kali" in distro.lower()
    is_ubuntu = "ubuntu" in distro_id or "ubuntu" in distro.lower()
    is_debian = "debian" in distro_id
    is_arch = "arch" in distro_id
    is_fedora = "fedora" in distro_id

    is_macos = sys_platform == "darwin"
    is_windows = sys_platform.startswith("win")
    is_linux = sys_platform.startswith("linux")

    is_docker = Path("/.dockerenv").exists() or "docker" in platform.release().lower()
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    _INFO = {
        "system": "termux" if is_termux else
                  "windows" if is_windows else
                  "macos" if is_macos else
                  "wsl" if is_wsl else
                  "linux",
        "distro": distro,
        "distro_id": distro_id,
        "is_termux": is_termux,
        "is_wsl": is_wsl,
        "is_kali": is_kali,
        "is_ubuntu": is_ubuntu,
        "is_debian": is_debian,
        "is_arch": is_arch,
        "is_fedora": is_fedora,
        "is_macos": is_macos,
        "is_windows": is_windows,
        "is_linux": is_linux,
        "is_docker": is_docker,
        "is_root": is_root,
        "machine": machine,
        "python": platform.python_version(),
        "arch": platform.machine(),
    }
    return _INFO


# ─────────────────────────────────────────
# Convenience accessors
# ─────────────────────────────────────────
def info() -> Dict:
    return dict(_detect())


def system() -> str:
    return _detect()["system"]


def is_termux() -> bool:
    return _detect()["is_termux"]


def is_kali() -> bool:
    return _detect()["is_kali"]


def is_ubuntu() -> bool:
    return _detect()["is_ubuntu"]


def is_macos() -> bool:
    return _detect()["is_macos"]


def is_windows() -> bool:
    return _detect()["is_windows"]


def is_linux() -> bool:
    return _detect()["is_linux"]


def is_docker() -> bool:
    return _detect()["is_docker"]


def is_root() -> bool:
    return _detect()["is_root"]


def is_mobile() -> bool:
    """Termux or any Android-like environment."""
    return is_termux()


def is_low_resource() -> bool:
    """
    Envs where heavy tools (Playwright, big scans) should be skipped.
    """
    return is_termux() or is_docker()


# ─────────────────────────────────────────
# Resource recommendations
# ─────────────────────────────────────────
def recommended_limits() -> Dict:
    """
    Return recommended concurrency/timeout values based on platform.
    """
    if is_termux():
        return {
            "max_concurrent": 5,
            "nuclei_rate_limit": 30,
            "httpx_threads": 20,
            "playwright_enabled": False,
            "browser_max_urls": 0,
            "sqlmap_threads": 2,
        }
    if is_docker():
        return {
            "max_concurrent": 10,
            "nuclei_rate_limit": 50,
            "httpx_threads": 30,
            "playwright_enabled": True,
            "browser_max_urls": 5,
            "sqlmap_threads": 3,
        }
    # Native Linux / macOS / Windows
    return {
        "max_concurrent": 20,
        "nuclei_rate_limit": 70,
        "httpx_threads": 50,
        "playwright_enabled": True,
        "browser_max_urls": 20,
        "sqlmap_threads": 5,
    }


def tool_skip_list() -> list:
    """
    Tools that should be skipped on this platform.
    """
    skip = []
    if is_termux():
        skip.extend([
            "playwright",       # heavy chromium
            "sqlmap",           # slow on mobile
            "amass",            # very heavy
        ])
    return skip


def which(package: str) -> Optional[str]:
    """shutil.which wrapper; returns path or None."""
    return shutil.which(package)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import json
    info = _detect()
    print(json.dumps(info, indent=2))
    print()
    print("Recommended limits:")
    print(json.dumps(recommended_limits(), indent=2))
    print()
    print("Skip list:", tool_skip_list())