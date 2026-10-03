"""
intel/virustotal_api.py
-----------------------
VirusTotal lookups: subdomains, URLs, IP reports.
Requires: api_keys.virustotal in config.json.
"""

import time
from typing import Dict, List, Optional

from core.logger import get_logger, info, skip, warn
from core.config_loader import get_config

log = get_logger("virustotal")
cfg = get_config()


def _get_client():
    key = cfg.get("api_keys.virustotal", "")
    if not key:
        skip("VirusTotal API key missing")
        return None
    try:
        import vt  # type: ignore
        return vt.Client(key)
    except Exception as e:
        warn(f"VirusTotal init failed: {e}")
        return None


def get_subdomains(domain: str, limit: int = 100) -> List[str]:
    """Fetch subdomains from VirusTotal."""
    client = _get_client()
    if not client:
        return []
    try:
        info(f"VirusTotal subdomains: {domain}")
        subs = []
        url = f"/domains/{domain}/subdomains?limit={min(limit, 40)}"
        while url and len(subs) < limit:
            resp = client.get_object(url)
            for item in resp.data:
                if isinstance(item, dict):
                    subs.append(item.get("id", ""))
            url = resp.links.get("next") if hasattr(resp, "links") else None
            time.sleep(0.3)
        ok(f"VirusTotal: {len(subs)} subdomains")
        return [s for s in subs if s]
    except Exception as e:
        log.debug(f"VT subdomains failed: {e}")
        return []
    finally:
        try:
            client.close()
        except Exception:
            pass


def get_url_report(url: str) -> Optional[Dict]:
    """URL report (base64 URL id)."""
    import base64
    client = _get_client()
    if not client:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report = client.get_object(f"/urls/{url_id}")
        stats = report.last_analysis_stats or {}
        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": getattr(report, "reputation", 0),
        }
    except Exception as e:
        log.debug(f"VT url report failed: {e}")
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


def get_ip_report(ip: str) -> Optional[Dict]:
    client = _get_client()
    if not client:
        return None
    try:
        report = client.get_object(f"/ip_addresses/{ip}")
        stats = report.last_analysis_stats or {}
        return {
            "ip": ip,
            "asn": getattr(report, "asn", None),
            "as_owner": getattr(report, "as_owner", None),
            "country": getattr(report, "country", None),
            "reputation": getattr(report, "reputation", 0),
            "malicious": stats.get("malicious", 0),
        }
    except Exception as e:
        log.debug(f"VT ip report failed: {e}")
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain")
    parser.add_argument("--url")
    parser.add_argument("--ip")
    args = parser.parse_args()
    if args.domain:
        print(json.dumps(get_subdomains(args.domain), indent=2))
    elif args.url:
        print(json.dumps(get_url_report(args.url), indent=2, default=str))
    elif args.ip:
        print(json.dumps(get_ip_report(args.ip), indent=2, default=str))