"""
intel/shodan_api.py
-------------------
Shodan lookups for a hostname/IP.
Requires: shodan API key in config.json (api_keys.shodan)
Skips silently if key missing or library not installed.
"""

from typing import Dict, List, Optional

from core.logger import get_logger, info, ok, skip, warn
from core.config_loader import get_config

log = get_logger("shodan")
cfg = get_config()


def _get_client():
    key = cfg.get("api_keys.shodan", "")
    if not key:
        skip("Shodan API key missing")
        return None
    try:
        import shodan  # type: ignore
    except ImportError:
        skip("shodan Python library not installed")
        return None
    try:
        return shodan.Shodan(key)
    except Exception as e:
        warn(f"Shodan client init failed: {e}")
        return None


def lookup_host(ip: str) -> Optional[Dict]:
    """Look up a single IP on Shodan."""
    api = _get_client()
    if not api:
        return None
    try:
        info(f"Shodan lookup: {ip}")
        data = api.host(ip)
        return {
            "ip": data.get("ip_str"),
            "org": data.get("org"),
            "os": data.get("os"),
            "country": data.get("country_name"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "vulns": list((data.get("vulns") or {}).keys()),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
        }
    except Exception as e:
        log.debug(f"Shodan lookup failed for {ip}: {e}")
        return None


def search(query: str, limit: int = 20) -> List[Dict]:
    """
    Free-form Shodan search (uses credits).
    """
    api = _get_client()
    if not api:
        return []
    try:
        results = api.search(query, limit=limit)
        return [
            {
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "hostnames": m.get("hostnames", []),
                "org": m.get("org"),
                "product": m.get("product"),
                "version": m.get("version"),
            }
            for m in results.get("matches", [])
        ]
    except Exception as e:
        log.debug(f"Shodan search failed: {e}")
        return []


def domain_info(domain: str) -> Optional[Dict]:
    """Get subdomains + DNS records for a domain from Shodan."""
    api = _get_client()
    if not api:
        return None
    try:
        info(f"Shodan domain info: {domain}")
        data = api.dns.domain_info(domain)
        return {
            "domain": domain,
            "subdomains": data.get("subdomains", []),
            "records": data.get("data", []),
        }
    except Exception as e:
        log.debug(f"Shodan domain_info failed: {e}")
        return None


if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip")
    parser.add_argument("--domain")
    parser.add_argument("--search")
    args = parser.parse_args()

    if args.ip:
        print(json.dumps(lookup_host(args.ip), indent=2, default=str))
    elif args.domain:
        print(json.dumps(domain_info(args.domain), indent=2, default=str))
    elif args.search:
        print(json.dumps(search(args.search), indent=2, default=str))