"""
intel/chaos_api.py
------------------
Chaos dataset (ProjectDiscovery) for subdomain enumeration.
Requires: api_keys.chaos in config.json.
"""

from typing import List, Dict, Optional

from core.logger import get_logger, info, ok, skip, warn
from core.config_loader import get_config
from core.utils import safe_request, has_tool, run_command

log = get_logger("chaos")
cfg = get_config()


def fetch_subdomains(domain: str, timeout: int = 30) -> List[str]:
    """
    Fetch subdomains from Chaos dataset via API.
    Returns list of subdomains.
    """
    key = cfg.get("api_keys.chaos", "")
    if not key:
        skip("Chaos API key missing")
        return []

    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    headers = {"Authorization": key}
    try:
        info(f"Chaos: fetching subdomains for {domain}")
        r = safe_request(url, headers=headers, timeout=timeout)
        if not r or r.status_code != 200:
            warn(f"Chaos API returned {r.status_code if r else 'no response'}")
            return []
        data = r.json()
        subs = data.get("subdomains", [])
        full = [f"{s}.{domain}" for s in subs]
        ok(f"Chaos: {len(full)} subdomains")
        return full
    except Exception as e:
        log.debug(f"Chaos fetch failed: {e}")
        return []


def fetch_via_cli(domain: str, timeout: int = 60) -> List[str]:
    """
    Fetch subdomains via chaos-client CLI if installed.
    """
    if not has_tool("chaos"):
        return []

    key = cfg.get("api_keys.chaos", "")
    if not key:
        return []

    cmd = f"chaos -d {domain} -key {key} -silent"
    out = run_command(cmd, timeout=timeout)
    if not out:
        return []
    subs = [ln.strip() for ln in out.splitlines() if ln.strip()]
    ok(f"Chaos CLI: {len(subs)} subdomains")
    return subs


def get_subdomains(domain: str) -> List[str]:
    """
    Try CLI first, then API fallback.
    """
    subs = fetch_via_cli(domain)
    if not subs:
        subs = fetch_subdomains(domain)
    return sorted(set(subs))


def info_summary() -> Dict:
    """
    Return availability info for Chaos.
    """
    return {
        "api_key_present": bool(cfg.get("api_keys.chaos", "")),
        "cli_installed": has_tool("chaos"),
        "notes": "Both API key and CLI are optional",
    }


if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser()
    p.add_argument("-d", "--domain")
    p.add_argument("--status", action="store_true")
    args = p.parse_args()

    if args.status:
        print(json.dumps(info_summary(), indent=2))
    elif args.domain:
        subs = get_subdomains(args.domain)
        print(json.dumps(subs, indent=2))
    else:
        print("Use -d <domain> or --status")