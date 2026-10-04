"""
intel/censys_api.py
-------------------
Censys lookups.
Requires: censys_id + censys_secret in config.json.
"""

from typing import Dict, List, Optional

from core.logger import get_logger, info, skip, warn
from core.config_loader import get_config

log = get_logger("censys")
cfg = get_config()


def _get_client():
    cid = cfg.get("api_keys.censys_id", "")
    secret = cfg.get("api_keys.censys_secret", "")
    if not cid or not secret:
        skip("Censys credentials missing")
        return None
    try:
        from censys.search import CensysHosts
        CensysHosts.default_auth = (cid, secret)
        return CensysHosts()
    except Exception as e:
        warn(f"Censys init failed: {e}")
        return None


def lookup_host(ip: str) -> Optional[Dict]:
    api = _get_client()
    if not api:
        return None
    try:
        info(f"Censys lookup: {ip}")
        data = api.view(ip)
        services = []
        for svc in data.get("services", []):
            services.append({
                "port": svc.get("port"),
                "service_name": svc.get("service_name"),
                "transport": svc.get("transport_protocol"),
                "banner": (svc.get("banner") or "")[:300],
            })
        return {
            "ip": ip,
            "asn": (data.get("autonomous_system") or {}).get("asn"),
            "as_name": (data.get("autonomous_system") or {}).get("name"),
            "country": data.get("location", {}).get("country"),
            "services": services,
            "names": data.get("names", []),
        }
    except Exception as e:
        log.debug(f"Censys lookup failed: {e}")
        return None


def search(query: str, limit: int = 20) -> List[Dict]:
    api = _get_client()
    if not api:
        return []
    try:
        results = []
        for host in api.search(query, per_page=min(limit, 100)):
            results.append({
                "ip": host.get("ip"),
                "services": [s.get("service_name") for s in host.get("services", [])],
                "location": host.get("location", {}),
            })
        return results
    except Exception as e:
        log.debug(f"Censys search failed: {e}")
        return []


if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser()
    p.add_argument("--ip")
    p.add_argument("--search")
    args = p.parse_args()
    if args.ip:
        print(json.dumps(lookup_host(args.ip), indent=2, default=str))
    elif args.search:
        print(json.dumps(search(args.search), indent=2, default=str))