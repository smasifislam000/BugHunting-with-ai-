"""
monitoring/ct_monitor.py
------------------------
Certificate Transparency log monitoring.
Checks crt.sh periodically for new certificates.
Alerts on new domains.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Optional

from core.logger import get_logger, info, ok, warn, skip
from core.utils import safe_request, save_json, load_json, ensure_dir
from monitoring.alerts import alert_new_subdomains

log = get_logger("ct_monitor")


# ─────────────────────────────────────────
# Storage
# ─────────────────────────────────────────
def _state_file(domain: str) -> Path:
    return Path("results") / domain / "monitoring" / "ct_state.json"


def _load_state(domain: str) -> Dict:
    return load_json(_state_file(domain), {"known": [], "last_check": ""})


def _save_state(domain: str, state: Dict) -> None:
    p = _state_file(domain)
    ensure_dir(p.parent)
    save_json(p, state)


# ─────────────────────────────────────────
# Fetch from crt.sh
# ─────────────────────────────────────────
def fetch_crt_sh(domain: str, timeout: int = 30) -> List[Dict]:
    """
    Query crt.sh for all certificates for a domain.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = safe_request(url, timeout=timeout)
    if not r or r.status_code != 200:
        warn(f"crt.sh fetch failed: {r.status_code if r else 'no response'}")
        return []
    try:
        data = r.json()
    except Exception:
        return []
    return data if isinstance(data, list) else []


def extract_domains(crt_entries: List[Dict]) -> Set[str]:
    """
    Extract unique domains from crt.sh entries.
    """
    domains: Set[str] = set()
    for entry in crt_entries:
        name_val = entry.get("name_value", "")
        common = entry.get("common_name", "")
        for raw in (name_val, common):
            for line in (raw or "").split("\n"):
                d = line.strip().lower()
                if d and "*" not in d:
                    domains.add(d)
    return domains


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def check(domain: str) -> Dict:
    """
    One CT log check. Returns newly-discovered domains.
    """
    info(f"CT check for {domain}")
    entries = fetch_crt_sh(domain)
    if not entries:
        return {"new": [], "total_known": 0}

    current = extract_domains(entries)

    state = _load_state(domain)
    known: Set[str] = set(state.get("known", []))
    new_domains = sorted(current - known)

    # Update state
    state["known"] = sorted(known | current)
    state["last_check"] = datetime.utcnow().isoformat()
    _save_state(domain, state)

    if new_domains:
        ok(f"CT: {len(new_domains)} new domain(s)")
        try:
            alert_new_subdomains(domain, new_domains)
        except Exception as e:
            log.debug(f"alert failed: {e}")
    else:
        info(f"CT: no new domains ({len(current)} total)")

    return {
        "new": new_domains,
        "total_known": len(current),
        "total_certs": len(entries),
    }


def run_forever(domain: str, interval_minutes: int = 60) -> None:
    """
    Continuous monitoring loop.
    """
    info(f"CT monitor started: every {interval_minutes} min")
    while True:
        try:
            check(domain)
        except KeyboardInterrupt:
            break
        except Exception as e:
            warn(f"CT monitor failed: {e}")
        try:
            time.sleep(interval_minutes * 60)
        except KeyboardInterrupt:
            break
    info("CT monitor stopped")


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="CT log monitor")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-i", "--interval", type=int, default=60,
                   help="minutes between checks (0 = once)")
    p.add_argument("--once", action="store_true")
    args = p.parse_args()

    if args.once or args.interval == 0:
        result = check(args.target)
        print(json.dumps(result, indent=2))
    else:
        run_forever(args.target, args.interval)