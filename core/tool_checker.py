"""
core/tool_checker.py
--------------------
Detects which external tools are available on the system.
Caches results for fast lookups.
Never crashes — missing tools return False.
"""

import shutil
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from core.logger import get_logger, info, warn, skip, ok

log = get_logger("tool_checker")


# ─────────────────────────────────────────
# Tool Registry (all tools this framework uses)
# ─────────────────────────────────────────
REQUIRED_TOOLS = {
    # Recon
    "subfinder":    "Subdomain enumeration",
    "httpx":        "HTTP probing",
    "dnsx":         "DNS resolution",
    "naabu":        "Port scanning",
    "katana":       "Web crawling",
    "gau":          "URL discovery",
    "waybackurls":  "Wayback URL discovery",

    # Vulnerability scanning
    "nuclei":       "Vulnerability scanner",
    "dalfox":       "XSS scanner",
    "ffuf":         "Fuzzer",
    "sqlmap":       "SQLi scanner",
    "arjun":        "Parameter discovery",
    "kxss":         "XSS reflection check",

    # Utilities
    "gf":           "Grep patterns",
    "anew":         "Append unique",
    "qsreplace":    "Query string replace",
    "uro":          "URL dedupe",

    # Optional advanced
    "amass":        "Deep subdomain enum",
    "assetfinder":  "Subdomain enum",
    "findomain":    "Subdomain enum",
    "chaos":        "Chaos dataset",
    "subzy":        "Subdomain takeover",
    "puredns":      "DNS resolver",
    "dnsgen":       "DNS permutation",
    "interactsh-client": "OOB detection",
    "kxss":         "XSS reflection",
    "waymore":      "Wayback extended",
    "dirsearch":    "Directory brute force",
    "searchsploit": "ExploitDB local",
}


# ─────────────────────────────────────────
# Cache
# ─────────────────────────────────────────
_CACHE: Optional[Dict[str, bool]] = None
_CACHE_FILE = Path(".cache/tool_status.json")


def _load_cache() -> Dict[str, bool]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if _CACHE_FILE.exists():
        try:
            with open(_CACHE_FILE, "r") as f:
                _CACHE = json.load(f)
                return _CACHE
        except Exception:
            pass
    _CACHE = {}
    return _CACHE


def _save_cache(cache: Dict[str, bool]) -> None:
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        log.debug(f"cache save failed: {e}")


# ─────────────────────────────────────────
# Core API
# ─────────────────────────────────────────
def has_tool(name: str) -> bool:
    """Check if a single tool exists."""
    cache = _load_cache()
    if name in cache:
        return cache[name]
    found = shutil.which(name) is not None
    cache[name] = found
    _save_cache(cache)
    return found


def get_tool_path(name: str) -> Optional[str]:
    """Return absolute path to a tool, or None."""
    return shutil.which(name)


def check_all() -> Dict[str, bool]:
    """Check every registered tool. Returns dict of name → present."""
    result = {}
    for tool in REQUIRED_TOOLS:
        result[tool] = has_tool(tool)
    return result


def missing_tools() -> List[str]:
    """List of tools that are NOT installed."""
    all_tools = check_all()
    return [t for t, present in all_tools.items() if not present]


def present_tools() -> List[str]:
    """List of tools that ARE installed."""
    all_tools = check_all()
    return [t for t, present in all_tools.items() if present]


def report() -> Dict:
    """Full diagnostic report of tools."""
    all_status = check_all()
    missing = [t for t, v in all_status.items() if not v]
    present = [t for t, v in all_status.items() if v]
    return {
        "total": len(all_status),
        "present": len(present),
        "missing": len(missing),
        "present_list": present,
        "missing_list": missing,
        "details": all_status,
    }


def print_report() -> None:
    """Pretty-print tool status."""
    r = report()
    ok(f"Tools present: {r['present']}/{r['total']}")
    if r["missing_list"]:
        warn(f"Missing tools ({len(r['missing_list'])}):")
        for t in r["missing_list"]:
            skip(f"  • {t} ({REQUIRED_TOOLS.get(t, 'unknown')})")


def get_version(tool: str, timeout: int = 3) -> Optional[str]:
    """Try to get tool version."""
    if not has_tool(tool):
        return None
    for flag in ("--version", "-version", "-V", "version"):
        try:
            r = subprocess.run(
                [tool, flag], capture_output=True, text=True, timeout=timeout
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().split("\n")[0][:120]
        except Exception:
            continue
    return None


def require(*tools: str) -> bool:
    """
    Check if ALL named tools are available.
    Useful for modules: if not require("nuclei", "httpx"): return
    """
    return all(has_tool(t) for t in tools)


def require_any(*tools: str) -> bool:
    """Check if ANY of the named tools are available."""
    return any(has_tool(t) for t in tools)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import sys
    p = argparse.ArgumentParser(description="Tool checker")
    p.add_argument("--check", help="Check single tool")
    p.add_argument("--list", action="store_true", help="List all tools")
    p.add_argument("--missing", action="store_true", help="Only missing")
    p.add_argument("--version", help="Get tool version")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--clear-cache", action="store_true")
    args = p.parse_args()

    if args.clear_cache:
        _CACHE_FILE.unlink(missing_ok=True)
        ok("Cache cleared")
        sys.exit(0)

    if args.check:
        present = has_tool(args.check)
        print(f"{args.check}: {'YES' if present else 'NO'}")
    elif args.version:
        v = get_version(args.version)
        print(v or f"{args.version} not found")
    elif args.list:
        r = report()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print_report()
    elif args.missing:
        for t in missing_tools():
            print(t)
    else:
        print_report()