"""
burp/burp_scan_helper.py
------------------------
High-level helpers for triggering Burp scans via MCP or REST fallback.
Bridges between the framework's core.py and Burp Suite Pro.
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.logger import get_logger, info, ok, warn, skip
from core.config_loader import get_config

log = get_logger("burp_helper")
cfg = get_config()


def is_burp_enabled() -> bool:
    return bool(cfg.get("burp.enabled", True))


def burp_status() -> Dict:
    try:
        from burp.burp_mcp_client import check_burp_mcp_status
        return check_burp_mcp_status()
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def scan_url(url: str,
             scan_config: Optional[str] = None,
             use_mcp: bool = True) -> Dict:
    """
    Trigger a Burp scan via MCP (preferred) or REST fallback.
    Returns:
      {
        "ok": bool,
        "mode": "mcp" | "rest" | "delegation" | "none",
        "scan_id": str,
        "url": str,
        "error": str,
      }
    """
    if not is_burp_enabled():
        return {"ok": False, "mode": "none", "url": url,
                "error": "Burp disabled in config"}

    # Try MCP first
    if use_mcp:
        try:
            from burp.burp_mcp_client import mcp_scan_url
            res = mcp_scan_url(url, scan_config=scan_config, scope_only=True)
            if res and res.get("ok"):
                return {"ok": True, "mode": "mcp", "url": url,
                        "scan_id": res.get("scan_id", ""),
                        "error": ""}
        except Exception as e:
            log.debug(f"MCP scan failed: {e}")

    # REST fallback
    try:
        from burp.burp_mcp_client import _rest_scan_url
        if cfg.get("burp.rest_api.enabled", False):
            res = _rest_scan_url(url, scan_config, scope_only=True)
            if res and res.get("ok"):
                return {"ok": True, "mode": "rest", "url": url,
                        "scan_id": res.get("scan_id", ""),
                        "error": ""}
    except Exception as e:
        log.debug(f"REST scan failed: {e}")

    # Delegation plan
    return {
        "ok": False,
        "mode": "delegation",
        "url": url,
        "error": "",
        "delegation": (
            "Burp not reachable. Manually scan this URL in Burp Suite Pro, "
            "or ensure the MCP server is running."
        ),
    }


def bulk_scan(urls: List[str],
              output_dir: Optional[str] = None,
              scan_config: Optional[str] = None,
              max_urls: int = 20) -> Dict:
    """
    Trigger Burp scans for a list of URLs.
    """
    results = {
        "total": min(len(urls), max_urls),
        "ok": 0,
        "delegated": 0,
        "failed": 0,
        "details": [],
    }

    for url in urls[:max_urls]:
        r = scan_url(url, scan_config=scan_config)
        results["details"].append(r)
        if r.get("ok"):
            results["ok"] += 1
        elif r.get("mode") == "delegation":
            results["delegated"] += 1
        else:
            results["failed"] += 1

    ok(f"Burp: {results['ok']} scanned, {results['delegated']} delegated, "
       f"{results['failed']} failed")

    if output_dir:
        from core.utils import save_json, ensure_dir
        from pathlib import Path
        ensure_dir(output_dir)
        save_json(Path(output_dir) / "burp_scan_results.json", results)

    return results


def collaborator_payload() -> Optional[str]:
    """
    Get an OOB payload from Burp Collaborator or Interactsh.
    """
    try:
        from burp.collaborator import get_oob_payload
        res = get_oob_payload()
        if res.get("ok"):
            return res.get("payload") or res.get("data", {}).get("payload")
    except Exception as e:
        log.debug(f"OOB payload failed: {e}")
    return None


def is_in_scope(url: str, scope_domains: Optional[List[str]] = None) -> bool:
    """
    Simple scope check: URL host must match one of scope_domains.
    """
    if not scope_domains:
        return True
    try:
        host = urlparse(url).netloc.split(":")[0]
        for d in scope_domains:
            if host == d or host.endswith("." + d):
                return True
    except Exception:
        return False
    return False


if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser(description="Burp scan helper")
    p.add_argument("--status", action="store_true")
    p.add_argument("--scan", help="URL to scan")
    p.add_argument("--payload", action="store_true",
                   help="Get collaborator payload")
    args = p.parse_args()

    if args.status:
        print(json.dumps(burp_status(), indent=2))
    elif args.scan:
        print(json.dumps(scan_url(args.scan), indent=2))
    elif args.payload:
        print(collaborator_payload() or "No payload available")
    else:
        print(json.dumps(burp_status(), indent=2))