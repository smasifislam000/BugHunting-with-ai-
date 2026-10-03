"""
intel/securitytrails_api.py
---------------------------
SecurityTrails DNS history + subdomains.
Requires: api_keys.securitytrails in config.json.
"""

from typing import Dict, List, Optional

from core.logger import get_logger, info, skip, warn
from core.config_loader import get_config
from core.utils import safe_request

log = get_logger("securitytrails")
cfg = get_config()

BASE = "https://api.securitytrails.com/v1"


def _headers() -> Dict:
    key = cfg.get("api_keys.securitytrails", "")
    if not key:
        return {}
    return {"APIKEY": key, "Accept": "application/json"}


def get_subdomains(domain: str) -> List[str]:
    """All subdomains via SecurityTrails."""
    headers = _headers()
    if not headers:
        skip("SecurityTrails API key missing")
        return []
    try:
        info(f"SecurityTrails subdomains: {domain}")
        url = f"{BASE}/domain/{domain}/subdomains?children_only=false"
        r = safe_request(url, headers=headers, timeout=20)
        if not r or r.status_code != 200:
            return []
        data = r.json()
        subs = data.get("subdomains", [])
        return [f"{s}.{domain}" for s in subs]
    except Exception as e:
        log.debug(f"ST subdomains failed: {e}")
        return []


def get_dns_history(domain: str, record_type: str = "a") -> List[Dict]:
    """DNS history for a domain."""
    headers = _headers()
    if not headers:
        return []
    try:
        info(f"SecurityTrails DNS history: {domain} ({record_type})")
        url = f"{BASE}/history/{domain}/dns/{record_type}"
        r = safe_request(url, headers=headers, timeout=20)
        if not r or r.status_code != 200:
            return []
        data = r.json()
        return data.get("records", [])
    except Exception as e:
        log.debug(f"ST DNS history failed: {e}")
        return []


def get_whois(domain: str) -> Optional[Dict]:
    headers = _headers()
    if not headers:
        return None
    try:
        url = f"{BASE}/domain/{domain}/whois"
        r = safe_request(url, headers=headers, timeout=20)
        if not r or r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dns-history", action="store_true")
    args = parser.parse_args()
    if args.dns_history:
        print(json.dumps(get_dns_history(args.domain), indent=2, default=str))
    else:
        print(json.dumps(get_subdomains(args.domain), indent=2))